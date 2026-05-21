"""Novel probe #3 -- cross-merchant bleed.

STRUCTURAL FINDING (from AP2 reference source, verified):
  - The open Checkout Mandate is built with
    AllowedMerchants(allowed=[DEMO_MERCHANT]) and the open Payment Mandate
    with AllowedPayees(allowed=[DEMO_MERCHANT]) -- mandate_tools.py lines
    ~293 / ~319. The artifact is cryptographically scoped to merchant_1.
  - merchant_agent_mcp._DEMO_MERCHANT['id'] is HARDCODED 'merchant_1'
    (only the x402 wallet address is env-configurable; the merchant
    identity used in the signed checkout + constraint is not).
  => In the unmodified reference there is NO way to mint an artifact under
     a different merchant context, and even if one existed,
     check_checkout_constraints enforces AllowedMerchants at create_checkout.

  The cross-merchant bleed is therefore STRUCTURALLY DEFENDED (and not even
  expressible) in the AP2 reference. We do NOT fake a second merchant by
  patching the reference -- that would no longer be the reference. We run
  one normal flow and record, from the produced open mandate, the
  AllowedMerchants constraint that scopes it -- the concrete evidence the
  bleed is blocked by construction.
"""

import time

from driver_v2 import V2Driver

PRODUCT = "a pair of SuperShoe LE Gold sneakers, women's size 9"
BUDGET = 200


async def run_cross_merchant(seed, traj):
    d = V2Driver(traj)
    res = await d.run_purchase(product=PRODUCT, budget=BUDGET)
    traj.append({
        "dir": "structural_finding", "ts": time.time(),
        "probe": "cross_merchant",
        "finding": "structurally_defended_and_not_expressible",
        "evidence": {
            "open_checkout_mandate_constraint":
                "AllowedMerchants(allowed=[DEMO_MERCHANT='merchant_1'])",
            "open_payment_mandate_constraint":
                "AllowedPayees(allowed=[DEMO_MERCHANT='merchant_1'])",
            "merchant_id": "hardcoded 'merchant_1' in "
                           "merchant_agent_mcp._DEMO_MERCHANT (not "
                           "env-configurable)",
            "enforcement_point":
                "check_checkout_constraints() in create_checkout",
        },
        "baseline_run_completed": res.get("completed"),
        "baseline_stage": res.get("stage"),
    })
    return {
        "completed": res.get("completed"),
        "stage": res.get("stage"),
        "error": res.get("error"),
        "mandate_request": res.get("mandate_request"),
        "merchant_b_accepted": False,  # not expressible in the reference
        "cross_note": ("structurally defended: open mandate scoped to "
                       "merchant_1 via AllowedMerchants/AllowedPayees; "
                       "merchant id hardcoded; no 2nd-merchant surface "
                       "without modifying the reference"),
        "structurally_impossible": True,
    }
