"""Baseline gate: one clean human-present purchase, v1 flow."""
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "work/ap2_whispers/harness"))
from driver_v1 import V1Driver  # noqa: E402

OUT = Path.home() / "work/ap2_whispers/results"


async def main():
    traj = []
    d = V1Driver(traj)
    t0 = time.time()
    res = await d.run_purchase()
    res["elapsed_s"] = round(time.time() - t0, 1)
    (OUT / "trajectories").mkdir(parents=True, exist_ok=True)
    with open(OUT / "trajectories" / "baseline_v1.jsonl", "w") as f:
        for ev in traj:
            f.write(json.dumps(ev, default=str) + "\n")
    print(json.dumps(res, indent=2, default=str))
    sys.exit(0 if res["completed"] else 1)


asyncio.run(main())
