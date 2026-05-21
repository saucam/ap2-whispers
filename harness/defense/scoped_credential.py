"""ZeroID-style scoped-credential enforcement for the AP2 v1 credentials
provider.

This is a faithful capability-layer enforcement point, not a string filter.
It models the PUBLIC / DOCUMENTED scoped-credential contract (the same family
as OAuth2 Token Exchange RFC 8693 and SPIFFE workload scoping): at session /
intent establishment a short-lived credential is *minted* bound to a
principal + audience + scope, and the resource server (here: the credentials
provider) answers ONLY for the bound principal. A request for any other
principal is *unrepresentable* -- there is no code path that returns another
account's data, because the capability the caller holds is scoped to exactly
one `authorized_user_email`. Deny-by-capability, not deny-by-pattern.

Mechanism (faithful to the AP2 v1 reference's real surface):

  * The AP2 v1 stack propagates a stable A2A `context_id` for the whole
    purchase session: `subagents/shopper/tools.py` sets
    `tool_context.state["shopping_context_id"] = task.context_id` once, and
    every subsequent credentials-provider call rides that same context_id via
    `A2aMessageBuilder().set_context_id(...)`. The credentials provider sees
    it as `updater.context_id`. That is the session identifier the scoped
    credential is bound to -- a real protocol fact, not something invented.

  * The authorized principal is the identity the session authenticated as.
    The AP2 demo explicitly stubs the real identity step ("you might have to
    go through a redirect to prove your identity ... but this is a demo, so I
    will assume you have granted me access to your account, with the login of
    bugsbunny@gmail.com"). In a real ZeroID / OAuth2-token-exchange
    deployment that redirect yields the authenticated subject and the
    credential is minted bound to it. We model exactly that: the authorized
    principal is `AP2_SCOPED_CRED_PRINCIPAL` (default `bugsbunny@gmail.com`,
    the AP2 demo session login), captured out-of-band at session
    establishment -- NOT read from the attacker-influenceable request body.

  * On every credential operation (`get_shipping_address`,
    `search_payment_methods`, `create_payment_credential_token`) the wrapper
    looks up / mints the scoped credential for this `context_id`, then
    enforces: requested `user_email` MUST equal the bound
    `authorized_user_email`. If it does not, the request is rejected at the
    capability layer and `account_manager` / `_account_db` is NEVER touched.

Toggle: enforcement is active only when `AP2_SCOPED_CRED_ENFORCE=1`. With it
unset the credentials provider behaves exactly as the unmodified reference,
so the SAME harness measures both the undefended (Phase 1) and defended
(Phase 3) paths with zero other changes.
"""

import logging
import os
import time
from typing import Any

from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import DataPart, Part, Task

from common import message_utils


_LOG = logging.getLogger("ap2.scoped_credential")

# Out-of-band authorized principal for the demo session. In production this is
# the subject from the OAuth2 / ZeroID identity redirect; the AP2 demo stubs
# that redirect and assumes the login `bugsbunny@gmail.com`.
AUTHORIZED_PRINCIPAL = os.environ.get(
    "AP2_SCOPED_CRED_PRINCIPAL", "bugsbunny@gmail.com"
)

# Short credential lifetime, like an OAuth2 token-exchange access token.
CREDENTIAL_TTL_S = float(os.environ.get("AP2_SCOPED_CRED_TTL_S", "900"))


def _enforce_enabled() -> bool:
  return os.environ.get("AP2_SCOPED_CRED_ENFORCE", "") == "1"


class ScopedCredential:
  """A capability bound to (session, principal), minted at session start."""

  __slots__ = ("context_id", "authorized_user_email", "minted_at", "audience")

  def __init__(self, context_id: str, authorized_user_email: str):
    self.context_id = context_id
    self.authorized_user_email = authorized_user_email
    self.minted_at = time.time()
    self.audience = "credentials-provider"

  def expired(self) -> bool:
    return (time.time() - self.minted_at) > CREDENTIAL_TTL_S

  def permits(self, requested_user_email: str) -> bool:
    """The credential answers ONLY for the bound principal."""
    return (
        not self.expired()
        and requested_user_email == self.authorized_user_email
    )


class _CredentialStore:
  """Mints/holds one scoped credential per shopping session (context_id).

  Mint-once: the authorized principal is frozen at first contact for a
  session and is sourced out-of-band (the authenticated session subject),
  never from the request DataPart. The attacker controls the request body,
  not the session's authenticated identity, so it cannot influence the bind.
  """

  def __init__(self):
    self._by_context: dict[str, ScopedCredential] = {}

  def credential_for(self, context_id: str) -> ScopedCredential:
    cred = self._by_context.get(context_id)
    if cred is None or cred.expired():
      cred = ScopedCredential(context_id, AUTHORIZED_PRINCIPAL)
      self._by_context[context_id] = cred
      _LOG.info(
          "scoped-credential MINT context_id=%s principal=%s aud=%s ttl=%ss",
          context_id,
          cred.authorized_user_email,
          cred.audience,
          int(CREDENTIAL_TTL_S),
      )
    return cred


_STORE = _CredentialStore()


class ScopedCredentialDenied(Exception):
  """Raised when a credential request falls outside the minted scope.

  This fires BEFORE account_manager / _account_db is touched: the
  cross-account read is unrepresentable at the capability layer.
  """


async def _emit_denial(updater: TaskUpdater, reason: str) -> None:
  """Surface the capability denial as a structured task artifact + fail."""
  await updater.add_artifact(
      [
          Part(
              root=DataPart(
                  data={
                      "scoped_credential_denied": True,
                      "reason": reason,
                      "enforcement": "zeroid-style-scoped-credential",
                  }
              )
          )
      ]
  )
  # Terminal failure: no account data is ever produced for this request.
  await updater.failed()


def guard_credentialed_tool(handler):
  """Decorator: enforce the scoped credential before a creds-provider tool.

  Applies only to tools that resolve account data from a request-supplied
  `user_email` (the Vault Whisper surface). Mandate-chain tools that do not
  take a `user_email` are passed straight through.
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

    # No user_email in this request -> not an account-scoped read; the
    # reference handler will raise its own ValueError if it needs one.
    if not requested_email:
      return await handler(data_parts, updater, current_task)

    cred = _STORE.credential_for(context_id)
    if not cred.permits(requested_email):
      reason = (
          f"requested user_email={requested_email!r} is outside the scope of "
          f"the credential minted for this session "
          f"(authorized principal={cred.authorized_user_email!r}, "
          f"context_id={context_id!r}, audience={cred.audience!r}). "
          f"Cross-account read rejected at the capability layer; "
          f"account store NOT consulted."
      )
      _LOG.warning("scoped-credential DENY %s", reason)
      await _emit_denial(updater, reason)
      return

    _LOG.info(
        "scoped-credential ALLOW context_id=%s principal=%s tool=%s",
        context_id,
        requested_email,
        getattr(handler, "__name__", "?"),
    )
    return await handler(data_parts, updater, current_task)

  wrapped.__name__ = getattr(handler, "__name__", "wrapped")
  wrapped.__doc__ = getattr(handler, "__doc__", None)
  return wrapped
