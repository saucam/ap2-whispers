"""Baseline gate: one clean human-not-present purchase, v2 flow."""
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "work/ap2_whispers/harness"))
from driver_v2 import V2Driver  # noqa: E402

OUT = Path.home() / "work/ap2_whispers/results"


async def main():
    traj = []
    d = V2Driver(traj)
    t0 = time.time()
    res = await d.run_purchase(
        product="a pair of SuperShoe LE Gold sneakers, women's size 9",
        budget=200)
    res["elapsed_s"] = round(time.time() - t0, 1)
    res["session_id"] = d.session_id
    (OUT / "trajectories").mkdir(parents=True, exist_ok=True)
    with open(OUT / "trajectories" / "baseline_v2.jsonl", "w") as f:
        for ev in traj:
            f.write(json.dumps(ev, default=str) + "\n")
    print(json.dumps({k: v for k, v in res.items()
                       if k != "purchase_complete"}, indent=2, default=str))
    print("PURCHASE_COMPLETE_ARTIFACT:",
          json.dumps(res.get("purchase_complete"), default=str)[:400])
    sys.exit(0 if res["completed"] else 1)


asyncio.run(main())
