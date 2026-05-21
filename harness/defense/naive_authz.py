"""Naive-authz baseline -- the "simplest equivalent" comparison point.

This is the defense-design-space control for the Phase 3b measurement: the
absolute minimal thing a developer could write to close the Vault Whisper
hole WITHOUT any identity infrastructure. No ZeroID, no token, no mint, no
verify, no signature, no expiry, no revocation, no audience. Just:

    bind the authenticated session subject at session establishment, and
    on every account-scoped credentials-provider tool call, require
        requested user_email == that bound session subject

Same enforcement point as the real-ZeroID guard (capability layer, before
`account_manager` / `_account_db`), same out-of-band session principal
source (the AP2 demo's named login), same reject artifact shape. The ONLY
difference vs the real-ZeroID guard is the mechanism: an in-process string
equality instead of a real ZeroID mint+introspect round trip.

The post compares the two head-to-head: does grounding the check in a real,
signed, audience-scoped, revocable ZeroID credential buy anything OVER this
naive string check, for THIS specific attack on THIS reference? Reporting
that honestly -- including if the answer is "same ASR" -- is the point.

Toggle: active only when `AP2_NAIVEAUTHZ_ENFORCE=1`. Unset => transparent
pass-through (byte-identical to the unmodified reference handler path).
"""

import logging
import os
from typing import Any

from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import DataPart, Part, Task

from common import message_utils


_LOG = logging.getLogger("ap2.naive_authz")

# Out-of-band authenticated session subject -- same source as the ZeroID
# guard (the AP2 demo's stubbed-redirect named login). Bound at session
# establishment; NEVER read from the attacker-influenceable request body.
SESSION_SUBJECT = os.environ.get(
    "AP2_NAIVEAUTHZ_SUBJECT", "bugsbunny@gmail.com"
)


def _enforce_enabled() -> bool:
  return os.environ.get("AP2_NAIVEAUTHZ_ENFORCE", "") == "1"


# Mint-once analog: freeze the bound subject per session (context_id). There
# is no credential -- just the remembered subject. Kept structurally
# parallel to the ZeroID store so the enforcement point is identical.
_BOUND: dict[str, str] = {}


def _bound_subject(context_id: str) -> str:
  s = _BOUND.get(context_id)
  if s is None:
    s = SESSION_SUBJECT
    _BOUND[context_id] = s
    _LOG.info(
        "naive-authz BIND context_id=%s session_subject=%s", context_id, s
    )
  return s


async def _emit_denial(updater: TaskUpdater, reason: str) -> None:
  await updater.add_artifact(
      [
          Part(
              root=DataPart(
                  data={
                      "scoped_credential_denied": True,
                      "enforcement": "naive-authz-session-subject-equality",
                      "reason": reason,
                  }
              )
          )
      ]
  )
  await updater.failed()


def guard_naiveauthz_tool(handler):
  """Decorator: plain `requested user_email == bound session subject`.

  Same enforcement point as the ZeroID guard; no token, no verify.
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
      return await handler(data_parts, updater, current_task)

    subject = _bound_subject(context_id)
    if requested_email != subject:
      reason = (
          f"requested user_email={requested_email!r} != bound session "
          f"subject {subject!r} (context_id={context_id!r}). "
          f"Cross-account read rejected at the capability layer; "
          f"account store NOT consulted. [naive-authz: no token, "
          f"no signature, no expiry, no audience]"
      )
      _LOG.warning("naive-authz DENY %s", reason)
      await _emit_denial(updater, reason)
      return

    _LOG.info(
        "naive-authz ALLOW context_id=%s subject=%s tool=%s",
        context_id, requested_email, getattr(handler, "__name__", "?"),
    )
    return await handler(data_parts, updater, current_task)

  wrapped.__name__ = getattr(handler, "__name__", "wrapped")
  wrapped.__doc__ = getattr(handler, "__doc__", None)
  return wrapped
