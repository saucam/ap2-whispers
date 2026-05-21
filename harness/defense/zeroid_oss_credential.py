"""REAL standalone OSS-ZeroID scoped-credential enforcement for the AP2 v1
credentials provider (Phase 3b-oss).

This is the PUBLIC-REPO twin of `zeroid_credential.py`. The Phase 3b authn-
flavour wrapper talks to the PRIVATE `highflame-ai/highflame-authn` service
(`:8051/v1/auth/...`); this wrapper talks to the PUBLIC, standalone, runnable
`highflame-ai/zeroid` service brought up via its own docker-compose
(`:8899`). Same enforcement contract, same out-of-band session principal,
same defense-aware scorer -- only the mint/introspect endpoints and the
token-issuance grant differ. A reader cloning only public sources can
reproduce the Vault-defended result against this wrapper.

Why client_credentials, not token-exchange? Standalone ZeroID's
client_credentials grant is the cleanest way to carry an out-of-band session
principal as a bound subject: each AP2 session maps deterministically to one
ZeroID identity (`external_id = ap2-session-<local-part>`), one OAuth2 client
is registered against that identity (`client_id == external_id`), and a
client_credentials mint produces an ES256-signed JWT whose `sub` is the
SPIFFE URI of that identity and whose `external_id` claim returns that same
id from introspection. RFC 8693 token-exchange requires an incoming
"subject_token" we'd have to mint first (a hen-and-egg: we'd still need a
prior credential carrying the session principal). client_credentials carries
the bound principal in one round trip and exercises ZeroID's
identity-binding + signed-token + introspection path end-to-end, which is
the only path our enforcement-point check needs.

Pre-bootstrap: a one-shot `zeroid_oss_bootstrap.py` (run once by a reader
following NOTES_ZEROID_OSS.md) registers the identity + OAuth client and
writes the resulting `client_id`/`client_secret` to a local env file the
harness sources. No secret is hardcoded in this file or in source control.

Mint:    POST /oauth2/token  (grant_type=client_credentials,
                              client_id, client_secret, scope=account:read,
                              account_id, project_id)
Verify:  POST /oauth2/token/introspect  (token=<the minted JWT>)
Reject:  principal_id(requested user_email) != introspect.external_id
         -> deny BEFORE _account_db / account_manager is consulted.

The principal mapping (email -> SPIFFE-safe external_id) is unchanged:
`bugsbunny@gmail.com` -> `ap2-session-bugsbunny`. Pure bijection on the
demo's fixed email set -- a token minted for one principal NEVER introspects
to a different external_id, so a Vault Whisper email swap is rejected.

Toggle: active only when `AP2_ZEROID_OSS_ENFORCE=1`. Unset => transparent
pass-through (byte-identical to the unmodified AP2 reference handler path).
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import DataPart, Part, Task

from common import message_utils


_LOG = logging.getLogger("ap2.zeroid_oss_credential")

# Running standalone ZeroID service on the box (public docker-compose, :8899).
ZEROID_BASE = os.environ.get("AP2_ZEROID_OSS_BASE", "http://localhost:8899")
# Out-of-band authorized session principal (the AP2 demo's named login;
# stubbed identity redirect, public-derivable from AP2's demo prose).
AUTHORIZED_PRINCIPAL = os.environ.get(
    "AP2_ZEROID_OSS_PRINCIPAL", "bugsbunny@gmail.com"
)
# Tenant headers for ZeroID admin routes (NOT used on /oauth2/token; included
# in the request body for client_credentials, which is what ZeroID requires).
ZEROID_ACCOUNT = os.environ.get("AP2_ZEROID_OSS_ACCOUNT", "ap2demo")
ZEROID_PROJECT = os.environ.get("AP2_ZEROID_OSS_PROJECT", "ap2")
# client_id and client_secret are bootstrapped once via zeroid_oss_bootstrap.py
# and supplied here via env (sourced from the file the bootstrap writes).
ZEROID_CLIENT_ID = os.environ.get(
    "AP2_ZEROID_OSS_CLIENT_ID", "ap2-session-bugsbunny"
)
ZEROID_CLIENT_SECRET = os.environ.get("AP2_ZEROID_OSS_CLIENT_SECRET", "")
ZEROID_SCOPE = os.environ.get(
    "AP2_ZEROID_OSS_SCOPE", "account:read"
)
# Refresh window: re-mint when within 30s of expiry; introspection
# (which the resource server enforces) is the authoritative validity check.
CREDENTIAL_REMINT_BEFORE_S = 30


def _enforce_enabled() -> bool:
  return os.environ.get("AP2_ZEROID_OSS_ENFORCE", "") == "1"


def principal_id(email: str) -> str:
  """Map an AP2 email to a stable SPIFFE-safe ZeroID external_id.

  Pure deterministic bijection on the demo's fixed email set. A different
  email maps to a different id, so a token minted for one principal never
  verifies a request for another.
  """
  local = (email or "").split("@", 1)[0]
  local = re.sub(r"[^a-zA-Z0-9.\-_]", "_", local)
  return f"ap2-session-{local}"


def _http_form(url: str, form: dict[str, str]) -> tuple[int, Any]:
  data = urllib.parse.urlencode(form).encode()
  req = urllib.request.Request(url, data=data, method="POST")
  req.add_header("Content-Type", "application/x-www-form-urlencoded")
  return _do(req)


def _http_json(method: str, url: str, body: dict | None) -> tuple[int, Any]:
  data = json.dumps(body).encode() if body is not None else None
  req = urllib.request.Request(url, data=data, method=method)
  req.add_header("Content-Type", "application/json")
  return _do(req)


def _do(req: urllib.request.Request) -> tuple[int, Any]:
  try:
    with urllib.request.urlopen(req, timeout=15) as r:
      raw = r.read().decode()
      return r.status, (json.loads(raw) if raw else {})
  except urllib.error.HTTPError as e:
    raw = e.read().decode()
    try:
      return e.code, json.loads(raw)
    except Exception:  # noqa: BLE001
      return e.code, {"raw": raw}
  except Exception as e:  # noqa: BLE001
    return -1, {"error": f"{type(e).__name__}: {e}"}


class ZeroIDOSSError(Exception):
  pass


def _mint_token() -> tuple[str, int]:
  """Real OSS-ZeroID client_credentials mint -> (signed JWT, expires_in)."""
  if not ZEROID_CLIENT_SECRET:
    raise ZeroIDOSSError(
        "AP2_ZEROID_OSS_CLIENT_SECRET unset; run zeroid_oss_bootstrap.py first"
    )
  form = {
      "grant_type": "client_credentials",
      "client_id": ZEROID_CLIENT_ID,
      "client_secret": ZEROID_CLIENT_SECRET,
      "scope": ZEROID_SCOPE,
      "account_id": ZEROID_ACCOUNT,
      "project_id": ZEROID_PROJECT,
  }
  st, resp = _http_form(f"{ZEROID_BASE}/oauth2/token", form)
  if st not in (200, 201) or not isinstance(resp, dict):
    raise ZeroIDOSSError(f"mint failed: {st}/{resp}")
  tok = resp.get("access_token")
  if not tok:
    raise ZeroIDOSSError(f"mint returned no access_token: {resp}")
  return tok, int(resp.get("expires_in", 0))


def _introspect(token: str) -> dict:
  """Real OSS-ZeroID verify (RFC 7662)."""
  st, resp = _http_json(
      "POST", f"{ZEROID_BASE}/oauth2/token/introspect", {"token": token}
  )
  if st not in (200, 201) or not isinstance(resp, dict):
    return {"active": False, "_introspect_http": st, "_raw": resp}
  return resp


class _SessionCred:
  """One real OSS-ZeroID-minted credential per AP2 shopping session."""

  __slots__ = ("context_id", "principal_email", "principal_ext_id",
               "token", "minted_at", "expires_in")

  def __init__(self, context_id: str):
    self.context_id = context_id
    self.principal_email = AUTHORIZED_PRINCIPAL
    self.principal_ext_id = principal_id(AUTHORIZED_PRINCIPAL)
    self.token, self.expires_in = _mint_token()
    self.minted_at = time.time()
    _LOG.info(
        "zeroid_oss MINT context_id=%s principal=%s ext_id=%s "
        "expires_in=%ss endpoint=%s",
        context_id, self.principal_email, self.principal_ext_id,
        self.expires_in, ZEROID_BASE,
    )

  def stale(self) -> bool:
    return (time.time() - self.minted_at) > max(
        0, self.expires_in - CREDENTIAL_REMINT_BEFORE_S
    )


class _Store:
  def __init__(self):
    self._by_ctx: dict[str, _SessionCred] = {}

  def cred_for(self, context_id: str) -> _SessionCred:
    c = self._by_ctx.get(context_id)
    if c is None or c.stale():
      c = _SessionCred(context_id)
      self._by_ctx[context_id] = c
    return c


_STORE = _Store()


async def _emit_denial(updater: TaskUpdater, reason: str,
                       introspect: dict) -> None:
  await updater.add_artifact(
      [
          Part(
              root=DataPart(
                  data={
                      "scoped_credential_denied": True,
                      "enforcement": "real-zeroid-oss",
                      "zeroid_introspect_active": introspect.get("active"),
                      "zeroid_bound_sub": introspect.get("sub"),
                      "zeroid_bound_external_id": introspect.get(
                          "external_id"
                      ),
                      "reason": reason,
                  }
              )
          )
      ]
  )
  await updater.failed()


def guard_zeroid_oss_tool(handler):
  """Decorator: enforce a REAL standalone-OSS ZeroID verify before a
  creds-provider tool.

  Mint-once per session (real client_credentials call to public ZeroID),
  then on every account-scoped tool call: introspect the minted token
  against the same running ZeroID, and require
      principal_id(requested user_email) == bound principal in the
      VERIFIED ZeroID token (external_id from /oauth2/token/introspect)
  A mismatch (the Vault Whisper email swap) is rejected at the capability
  layer BEFORE `account_manager` / `_account_db` is touched.
  """

  async def wrapped(
      data_parts: list[dict[str, Any]],
      updater: TaskUpdater,
      current_task: Task | None,
  ) -> None:
    if not _enforce_enabled():
      return await handler(data_parts, updater, current_task)

    requested_email = message_utils.find_data_part("user_email", data_parts)
    context_id = getattr(updater, "context_id", None) or "no-context"

    if not requested_email:
      # Not an account-scoped read; reference handler decides.
      return await handler(data_parts, updater, current_task)

    try:
      cred = _STORE.cred_for(context_id)
    except ZeroIDOSSError as e:
      _LOG.error("zeroid_oss MINT error context_id=%s: %s", context_id, e)
      await _emit_denial(
          updater, f"OSS-ZeroID mint unavailable: {e}", {"active": None}
      )
      return

    intro = _introspect(cred.token)
    bound = intro.get("external_id") or ""
    if not intro.get("active") or not bound:
      _LOG.warning(
          "zeroid_oss VERIFY-FAIL context_id=%s active=%s sub=%s",
          context_id, intro.get("active"), intro.get("sub"),
      )
      await _emit_denial(
          updater,
          "minted OSS-ZeroID token did not verify (active=%s)"
          % intro.get("active"),
          intro,
      )
      return

    requested_ext = principal_id(requested_email)
    if requested_ext != bound:
      reason = (
          f"requested user_email={requested_email!r} maps to principal "
          f"{requested_ext!r}, but the OSS-ZeroID-verified session "
          f"credential is bound to {bound!r} "
          f"(sub={intro.get('sub')!r}, context_id={context_id!r}). "
          f"Cross-account read rejected at the capability layer; "
          f"account store NOT consulted."
      )
      _LOG.warning("zeroid_oss DENY %s", reason)
      await _emit_denial(updater, reason, intro)
      return

    _LOG.info(
        "zeroid_oss ALLOW context_id=%s principal=%s bound=%s tool=%s "
        "(verified by real OSS-ZeroID introspect, jti=%s)",
        context_id, requested_email, bound,
        getattr(handler, "__name__", "?"), intro.get("jti"),
    )
    return await handler(data_parts, updater, current_task)

  wrapped.__name__ = getattr(handler, "__name__", "wrapped")
  wrapped.__doc__ = getattr(handler, "__doc__", None)
  return wrapped
