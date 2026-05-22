"""Phase 3c: REAL standalone OSS-ZeroID as a *production-shaped* OAuth2
resource-server middleware for the AP2 v1 credentials provider.

This file is the architectural refactor of `zeroid_oss_credential.py`. The
Phase 3b-oss wrapper was a per-tool-call decorator that ran one introspect
HTTP round trip per tool invocation, then string-compared the agent-supplied
`user_email` against the bound `external_id`. The user (correctly) flagged
that shape as a retrofit. Phase 3c rebuilds it as a proper OAuth2
resource-server middleware:

  1. **Validate ONCE at request entry**, not per tool. Local JWT verification
     against the issuer's JWKS (`/.well-known/jwks.json`, cached after the
     first fetch -- no per-request network for the signature check). Standard
     resource-server checks: signature, `iss`, `aud`, `exp`, `nbf`, `scope`.
     This is the OAuth2 RS pattern -- no per-call introspect.

  2. **Stash the verified principal + scope claims into a per-request
     context** (`context_id` = the A2A session id, used as the resource-
     server request key). Subsequent tool calls within the same session
     read from that verified context.

  3. **Tools substitute the bound principal for the agent-supplied
     `user_email`**. The agent CANNOT pick whose account is read; the
     credential's `sub`/`external_id` IS the answer. The attacker-
     influenceable `user_email` data part is logged and dropped. This is
     the cleaner capability model the per-call string compare was an
     awkward retrofit toward.

  4. **Scope confinement on write/issue tools**. The credential carries a
     `scope` claim (`account:read`, optionally `payment:issue`). The
     credentials-provider's `handle_create_payment_credential_token`
     (which actually issues a payment credential token / DPAN artifact) is
     gated on `payment:issue`. The Phase 3c session is minted with
     `account:read` only, so a scope-breach payload -- one that convinces
     the agent to invoke the write tool from a read-only session -- is
     rejected at the capability layer BEFORE the token is issued. This is
     ZeroID's actual distinguishing property over the naive
     substitute-then-trust shape: the credential's authorization envelope
     is honored, not just its identity.

  5. Optional short-TTL introspect cache for revocation visibility,
     OFF by default (set `AP2_ZEROID_3C_INTROSPECT_REVOCATION=1` to enable).
     Production RS deployments combine local JWKS validation with periodic
     introspection on a configurable interval; we expose the toggle for
     completeness but disable it for the Phase 3c measurement to keep the
     "validate-at-entry, no per-call network" property clean.

The wrapper is installed by `agent_executor.py.phase3c`: it overrides
`CredentialsProviderExecutor.execute()` to run the resource-server check
at request entry (once), then forwards to the parent. The tool functions
themselves are wrapped to read the verified principal from the request
context (and to enforce scope on write tools).

Toggle: active only when `AP2_ZEROID_3C_ENFORCE=1`. Unset => transparent
pass-through, byte-equivalent to the unmodified reference handler path.

Honesty caveat (carried from Phase 3a/3b/3b-oss): the AP2 reference stubs
its identity redirect (it never authenticates the user; its own demo prose
hardcodes `bugsbunny@gmail.com`). The middleware therefore mints the
session-bound credential out-of-band on first hit (one real `POST
/oauth2/token` against the running standalone OSS ZeroID) and treats that
as the resource-server's incoming bearer. Everything downstream of that --
the JWKS-grounded local verify, the aud/exp/scope checks, the principal
binding, the scope confinement on writes -- is real production-shaped
resource-server behavior.
"""

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


_LOG = logging.getLogger("ap2.zeroid_middleware_oss")


# ---------- configuration (env-driven) -----------------------------------

ZEROID_BASE = os.environ.get("AP2_ZEROID_OSS_BASE", "http://localhost:8899")

# The AP2 demo's named authenticated login (stubbed identity redirect).
AUTHORIZED_PRINCIPAL = os.environ.get(
    "AP2_ZEROID_OSS_PRINCIPAL", "bugsbunny@gmail.com"
)
# OAuth client (one client per AP2 session principal). Phase 3b-oss bootstrap
# script (`zeroid_oss_bootstrap.py`) wrote these to `zeroid_oss_client.env`.
ZEROID_CLIENT_ID = os.environ.get(
    "AP2_ZEROID_OSS_CLIENT_ID", "ap2-session-bugsbunny"
)
ZEROID_CLIENT_SECRET = os.environ.get("AP2_ZEROID_OSS_CLIENT_SECRET", "")
ZEROID_ACCOUNT = os.environ.get("AP2_ZEROID_OSS_ACCOUNT", "ap2demo")
ZEROID_PROJECT = os.environ.get("AP2_ZEROID_OSS_PROJECT", "ap2")

# Resource-server audience this middleware expects. Standalone ZeroID's
# client_credentials JWTs carry `aud=["https://highflame.ai"]` (the issuer
# URL) by default; the resource server validates against that.
ZEROID_EXPECTED_AUD = os.environ.get(
    "AP2_ZEROID_3C_EXPECTED_AUD", "https://highflame.ai"
)
ZEROID_EXPECTED_ISS = os.environ.get(
    "AP2_ZEROID_3C_EXPECTED_ISS", "https://highflame.ai"
)
# Allowed clock skew between issuer and resource server, seconds.
ALLOWED_CLOCK_SKEW_S = int(os.environ.get("AP2_ZEROID_3C_SKEW_S", "30"))
# Re-mint when within this many seconds of expiry.
REMINT_BEFORE_S = int(os.environ.get("AP2_ZEROID_3C_REMINT_BEFORE_S", "30"))
# Session-credential scope. Phase 3c sanity / Vault: account:read.
# Scope-breach payload mints with account:read AND attacks the write tool.
ZEROID_SCOPE = os.environ.get("AP2_ZEROID_3C_SCOPE", "account:read")

# Per-tool scope requirement (the resource server's capability map).
# Keep narrow + explicit. Documented in NOTES_ZEROID_OSS_3C.md.
TOOL_REQUIRED_SCOPE: dict[str, str] = {
    "handle_get_shipping_address": "account:read",
    "handle_search_payment_methods": "account:read",
    # Tokenization / payment-credential-token issuance is a WRITE/ISSUE
    # capability: it mints a payment artifact (DPAN proxy) bound to a
    # payment alias for an account. A read-only session must not be
    # able to invoke it.
    "handle_create_payment_credential_token": "payment:issue",
}

INTROSPECT_FOR_REVOCATION = (
    os.environ.get("AP2_ZEROID_3C_INTROSPECT_REVOCATION", "") == "1"
)
INTROSPECT_CACHE_TTL_S = int(
    os.environ.get("AP2_ZEROID_3C_INTROSPECT_CACHE_TTL_S", "30")
)


def _enforce_enabled() -> bool:
  return os.environ.get("AP2_ZEROID_3C_ENFORCE", "") == "1"


# ---------- principal mapping (unchanged from Phase 3b-oss) --------------

def principal_id(email: str) -> str:
  local = (email or "").split("@", 1)[0]
  local = re.sub(r"[^a-zA-Z0-9.\-_]", "_", local)
  return f"ap2-session-{local}"


# ---------- HTTP helpers --------------------------------------------------

def _http_form(url: str, form: dict[str, str], timeout: float = 15.0):
  data = urllib.parse.urlencode(form).encode()
  req = urllib.request.Request(url, data=data, method="POST")
  req.add_header("Content-Type", "application/x-www-form-urlencoded")
  return _do(req, timeout)


def _http_json(method: str, url: str, body: dict | None, timeout: float = 15.0):
  data = json.dumps(body).encode() if body is not None else None
  req = urllib.request.Request(url, data=data, method=method)
  req.add_header("Content-Type", "application/json")
  return _do(req, timeout)


def _http_get_json(url: str, timeout: float = 15.0):
  req = urllib.request.Request(url, method="GET")
  return _do(req, timeout)


def _do(req: urllib.request.Request, timeout: float):
  try:
    with urllib.request.urlopen(req, timeout=timeout) as r:
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


# ---------- JWKS cache + local JWT verification --------------------------

_JWKS_LOCK = threading.Lock()
_JWKS: dict[str, dict] = {}  # kid -> JWK
_JWKS_FETCHED_AT = 0.0
_JWKS_TTL_S = 600.0


def _b64url_decode(s: str) -> bytes:
  s += "=" * ((4 - len(s) % 4) % 4)
  return base64.urlsafe_b64decode(s)


def _refresh_jwks() -> dict[str, dict]:
  st, resp = _http_get_json(f"{ZEROID_BASE}/.well-known/jwks.json")
  if st != 200 or not isinstance(resp, dict):
    raise ZeroIDMiddlewareError(f"JWKS fetch failed: {st}/{resp}")
  keys = resp.get("keys") or []
  return {k["kid"]: k for k in keys if isinstance(k, dict) and k.get("kid")}


def _get_jwk(kid: str) -> dict:
  global _JWKS_FETCHED_AT
  with _JWKS_LOCK:
    if (
        not _JWKS
        or (time.time() - _JWKS_FETCHED_AT) > _JWKS_TTL_S
        or kid not in _JWKS
    ):
      try:
        new = _refresh_jwks()
      except ZeroIDMiddlewareError:
        if not _JWKS:
          raise
        new = _JWKS  # serve stale on transient failure
      _JWKS.clear()
      _JWKS.update(new)
      _JWKS_FETCHED_AT = time.time()
    if kid not in _JWKS:
      raise ZeroIDMiddlewareError(f"JWKS missing kid={kid!r}")
    return _JWKS[kid]


def _load_es256_pub(jwk: dict) -> ec.EllipticCurvePublicKey:
  x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
  y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
  return ec.EllipticCurvePublicKey.from_encoded_point(
      ec.SECP256R1(), b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
  )


class ZeroIDMiddlewareError(Exception):
  pass


def _verify_jwt_local(token: str, now: float | None = None) -> dict:
  """Local JWKS-grounded JWT verification. Production resource-server path.

  Validates: signature (ES256), `iss`, `aud`, `exp`, `nbf`, structure.
  Returns the decoded claims dict on success; raises on failure. Does NOT
  hit the network (after JWKS is cached).
  """
  if not token or token.count(".") != 2:
    raise ZeroIDMiddlewareError("malformed JWT (segments)")
  hdr_b64, body_b64, sig_b64 = token.split(".")
  try:
    hdr = json.loads(_b64url_decode(hdr_b64).decode())
    body = json.loads(_b64url_decode(body_b64).decode())
  except Exception as e:  # noqa: BLE001
    raise ZeroIDMiddlewareError(f"malformed JWT (b64/json): {e}") from e

  alg = hdr.get("alg")
  kid = hdr.get("kid")
  if alg != "ES256":
    raise ZeroIDMiddlewareError(f"unsupported alg={alg!r} (expected ES256)")
  if not kid:
    raise ZeroIDMiddlewareError("JWT missing kid")
  jwk = _get_jwk(kid)
  if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
    raise ZeroIDMiddlewareError(f"unsupported JWK kty/crv for kid={kid!r}")

  pub = _load_es256_pub(jwk)
  sig_raw = _b64url_decode(sig_b64)
  if len(sig_raw) != 64:
    raise ZeroIDMiddlewareError(f"bad ES256 signature length={len(sig_raw)}")
  r = int.from_bytes(sig_raw[:32], "big")
  s = int.from_bytes(sig_raw[32:], "big")
  der_sig = encode_dss_signature(r, s)
  signing_input = f"{hdr_b64}.{body_b64}".encode()
  try:
    pub.verify(der_sig, signing_input, ec.ECDSA(hashes_sha256()))
  except InvalidSignature as e:
    raise ZeroIDMiddlewareError("JWT signature verification failed") from e

  t = now or time.time()
  exp = body.get("exp")
  if exp is None:
    raise ZeroIDMiddlewareError("JWT missing exp")
  if t > exp + ALLOWED_CLOCK_SKEW_S:
    raise ZeroIDMiddlewareError(
        f"JWT expired (exp={exp}, now={int(t)}, skew_allowed_s={ALLOWED_CLOCK_SKEW_S})"
    )
  nbf = body.get("nbf")
  if nbf is not None and t + ALLOWED_CLOCK_SKEW_S < nbf:
    raise ZeroIDMiddlewareError(
        f"JWT not yet valid (nbf={nbf}, now={int(t)})"
    )
  iss = body.get("iss")
  if iss != ZEROID_EXPECTED_ISS:
    raise ZeroIDMiddlewareError(
        f"JWT iss mismatch: got {iss!r}, expected {ZEROID_EXPECTED_ISS!r}"
    )
  aud = body.get("aud")
  if isinstance(aud, str):
    aud_list = [aud]
  elif isinstance(aud, list):
    aud_list = aud
  else:
    aud_list = []
  if ZEROID_EXPECTED_AUD not in aud_list:
    raise ZeroIDMiddlewareError(
        f"JWT aud mismatch: got {aud_list!r}, expected to contain "
        f"{ZEROID_EXPECTED_AUD!r}"
    )
  return body


def hashes_sha256():
  # Import lazily to avoid an import cycle if cryptography is half-loaded.
  from cryptography.hazmat.primitives import hashes
  return hashes.SHA256()


# ---------- token mint (real OSS-ZeroID round trip, ONCE per session) ----

def mint_session_token(scope: str | None = None) -> tuple[str, int]:
  """Real OSS-ZeroID client_credentials mint -> (signed JWT, expires_in)."""
  if not ZEROID_CLIENT_SECRET:
    raise ZeroIDMiddlewareError(
        "AP2_ZEROID_OSS_CLIENT_SECRET unset; run zeroid_oss_bootstrap.py first"
    )
  form = {
      "grant_type": "client_credentials",
      "client_id": ZEROID_CLIENT_ID,
      "client_secret": ZEROID_CLIENT_SECRET,
      "scope": scope or ZEROID_SCOPE,
      "account_id": ZEROID_ACCOUNT,
      "project_id": ZEROID_PROJECT,
  }
  st, resp = _http_form(f"{ZEROID_BASE}/oauth2/token", form)
  if st not in (200, 201) or not isinstance(resp, dict):
    raise ZeroIDMiddlewareError(f"mint failed: {st}/{resp}")
  tok = resp.get("access_token")
  if not tok:
    raise ZeroIDMiddlewareError(f"mint returned no access_token: {resp}")
  return tok, int(resp.get("expires_in", 0))


# ---------- introspect (optional, for revocation) ------------------------

_INTROSPECT_CACHE: dict[str, tuple[float, dict]] = {}


def introspect_token(token: str) -> dict:
  now = time.time()
  jti_key = hashlib.sha256(token.encode()).hexdigest()[:32]
  cached = _INTROSPECT_CACHE.get(jti_key)
  if cached and (now - cached[0]) < INTROSPECT_CACHE_TTL_S:
    return cached[1]
  st, resp = _http_json(
      "POST", f"{ZEROID_BASE}/oauth2/token/introspect", {"token": token}
  )
  if st not in (200, 201) or not isinstance(resp, dict):
    out = {"active": False, "_introspect_http": st}
  else:
    out = resp
  _INTROSPECT_CACHE[jti_key] = (now, out)
  return out


# ---------- per-request validated context --------------------------------

class ValidatedContext:
  __slots__ = (
      "context_id", "principal_email", "principal_ext_id", "token",
      "claims", "scopes", "minted_at", "expires_at",
  )

  def __init__(
      self,
      context_id: str,
      principal_email: str,
      principal_ext_id: str,
      token: str,
      claims: dict,
  ):
    self.context_id = context_id
    self.principal_email = principal_email
    self.principal_ext_id = principal_ext_id
    self.token = token
    self.claims = claims
    self.minted_at = time.time()
    self.expires_at = float(claims.get("exp", self.minted_at + 3600))
    # Standalone ZeroID emits `scopes: ["account:read", ...]` in the JWT
    # body AND mirrors a `scope` string on the /oauth2/token response. The
    # token's authoritative claim is `scopes` (list). Fall back to a space-
    # delimited `scope` string for OAuth2-form compatibility.
    raw_scopes = claims.get("scopes")
    if isinstance(raw_scopes, list):
      self.scopes = [str(s) for s in raw_scopes]
    elif isinstance(claims.get("scope"), str):
      self.scopes = claims["scope"].split()
    else:
      self.scopes = []

  def stale(self) -> bool:
    return time.time() > (self.expires_at - REMINT_BEFORE_S)

  def has_scope(self, required: str) -> bool:
    return required in self.scopes

  def to_log(self) -> dict:
    return {
        "principal_email": self.principal_email,
        "principal_ext_id": self.principal_ext_id,
        "sub": self.claims.get("sub"),
        "jti": self.claims.get("jti"),
        "scopes": self.scopes,
        "aud": self.claims.get("aud"),
        "iss": self.claims.get("iss"),
        "exp": self.claims.get("exp"),
        "context_id": self.context_id,
        "enforcement": "real-zeroid-oss-middleware-3c",
    }


_CTX_LOCK = threading.Lock()
_CTX_BY_ID: dict[str, ValidatedContext] = {}


def validated_context_for(context_id: str) -> ValidatedContext:
  """Validate-at-entry: mint+verify ONCE per A2A session, then cache.

  Subsequent tool calls within the same context_id reuse the cached,
  verified context. NO per-call network for the signature check.
  """
  with _CTX_LOCK:
    cur = _CTX_BY_ID.get(context_id)
    if cur and not cur.stale():
      return cur
    token, _expires_in = mint_session_token()
    claims = _verify_jwt_local(token)
    if INTROSPECT_FOR_REVOCATION:
      intro = introspect_token(token)
      if not intro.get("active"):
        raise ZeroIDMiddlewareError(
            f"introspect says token inactive at mint: {intro}"
        )
    ctx = ValidatedContext(
        context_id=context_id,
        principal_email=AUTHORIZED_PRINCIPAL,
        principal_ext_id=principal_id(AUTHORIZED_PRINCIPAL),
        token=token,
        claims=claims,
    )
    _CTX_BY_ID[context_id] = ctx
    _LOG.info(
        "zeroid_middleware MINT+VERIFY (entry) context_id=%s principal=%s "
        "ext_id=%s scopes=%s aud=%s exp=%s jti=%s endpoint=%s",
        context_id, ctx.principal_email, ctx.principal_ext_id,
        ctx.scopes, ctx.claims.get("aud"), ctx.claims.get("exp"),
        ctx.claims.get("jti"), ZEROID_BASE,
    )
    return ctx
