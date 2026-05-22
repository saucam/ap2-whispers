"""Phase 3c: production-shaped *comparison baseline* middleware -- the
naive equivalent of a typical session-cookie auth pattern.

Same architectural shape as `zeroid_middleware_oss.py` (validate at request
entry, stash verified principal into a per-request context, tools read from
that context and DROP the attacker-supplied `user_email`), but with NO
OAuth2 properties:

  * No bearer token / no JWT.
  * No signature check.
  * No `aud` check (no audience concept).
  * No `exp` check (no expiry concept beyond the session lifetime).
  * No `scope` check / no capability mapping.
  * No introspection / no revocation channel.

It is the simplest middleware a developer could write that still does the
capability-substitution part correctly: "is there a session credential
attached to this request? extract the bound subject; tools use the bound
subject, not the agent-supplied email." Functionally equivalent to a
backend that decodes a server-issued session cookie and trusts whatever
it finds inside without OAuth2 plumbing.

The point of comparison: Phase 3c measures
  (a) the Vault Whisper sanity result on this AP2 substrate -- expected:
      BOTH middlewares close it structurally because substitution + a
      bound subject is sufficient. The introspect / signature / aud / exp
      machinery is not exercised by the Vault attack family.
  (b) a scope-confinement attack ("Payment Token Whisper" / scope_breach)
      that actively probes the write/issue authority -- expected: the
      ZeroID middleware rejects at the capability layer because the
      session's `scope` claim is read-only, the naive middleware lets
      the call through and a payment credential token is issued.

That is the architectural finding the user pushed for: substitution closes
Vault structurally regardless of token plumbing; scope-confinement is
where the OAuth2 machinery actually pays.

Toggle: active only when `AP2_NAIVE_3C_ENFORCE=1`. Unset => transparent
pass-through (byte-equivalent to the unmodified reference handler path).
"""

import logging
import os
import threading
import time
from typing import Any


_LOG = logging.getLogger("ap2.naive_middleware")


SESSION_SUBJECT = os.environ.get(
    "AP2_NAIVE_3C_SUBJECT", "bugsbunny@gmail.com"
)


def _enforce_enabled() -> bool:
  return os.environ.get("AP2_NAIVE_3C_ENFORCE", "") == "1"


class NaiveValidatedContext:
  """Same shape as `ValidatedContext` minus the OAuth2 fields."""

  __slots__ = (
      "context_id", "principal_email", "scopes", "minted_at",
  )

  def __init__(self, context_id: str, principal_email: str):
    self.context_id = context_id
    self.principal_email = principal_email
    # Naive middleware has no concept of scope / capability bounds.
    # Anything the user is logged in for is allowed -- equivalent to a
    # typical session-cookie pattern that says "the user is logged in,
    # let them do anything they could do logged in."
    self.scopes: list[str] = []
    self.minted_at = time.time()

  def stale(self) -> bool:
    return False  # naive: no expiry concept.

  def has_scope(self, required: str) -> bool:
    # No capability model. The naive middleware grants whatever the
    # logged-in user could do -- so any tool the agent picks goes through.
    # Returning True is the load-bearing comparison point: this is what
    # the naive shape buys you, capability-wise, vs the OAuth2 shape.
    return True

  def to_log(self) -> dict:
    return {
        "principal_email": self.principal_email,
        "context_id": self.context_id,
        "enforcement": "naive-session-cookie-shape-3c",
        "note": (
            "no token, no signature, no aud, no exp, no scope, no "
            "revocation -- substitution-only middleware"
        ),
    }


_CTX_LOCK = threading.Lock()
_CTX_BY_ID: dict[str, NaiveValidatedContext] = {}


def validated_context_for(context_id: str) -> NaiveValidatedContext:
  """Validate-at-entry analog: bind the session subject ONCE per session.

  No mint, no verify, no network. Equivalent to a session-cookie decode
  that just returns whatever subject the server stamped at login.
  """
  with _CTX_LOCK:
    cur = _CTX_BY_ID.get(context_id)
    if cur is not None:
      return cur
    ctx = NaiveValidatedContext(
        context_id=context_id, principal_email=SESSION_SUBJECT
    )
    _CTX_BY_ID[context_id] = ctx
    _LOG.info(
        "naive_middleware BIND (entry) context_id=%s subject=%s "
        "(no token, no aud, no exp, no scope)",
        context_id, ctx.principal_email,
    )
    return ctx
