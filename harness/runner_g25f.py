"""Gap A apples-to-apples rerun on the paper's model (gemini-2.5-flash).

Wraps harness/runner.run_one WITHOUT modifying the shared runner. All
outputs are written to NEW *_g25f paths so the flash-lite Phase 1
artifacts (RIG.md guardrail) are never touched:

  results/trajectories/<attack>_g25f_seed<seed>.jsonl
  results/<attack>_g25f_runs.jsonl
  results/<attack>_g25f_summary.json

Usage (from AP2/code/samples/python):
  uv run --no-sync python harness/runner_g25f.py <attack> <n> [start_seed] [append]
"""

import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

H = Path.home() / "work/ap2_whispers/harness"
sys.path.insert(0, str(H))

import runner  # noqa: E402  the shared, unmodified runner

OUT = Path.home() / "work/ap2_whispers/results"
TRAJ = OUT / "trajectories"
TRAJ.mkdir(parents=True, exist_ok=True)


def _save_traj_g25f(attack, seed, traj):
    """Override: suffix _g25f so flash-lite trajectories stay byte-exact."""
    path = TRAJ / f"{attack}_g25f_seed{seed}.jsonl"
    with open(path, "w") as f:
        for ev in traj:
            f.write(json.dumps(ev, default=str) + "\n")
    return path


# monkeypatch the trajectory writer used inside runner.run_one
runner._save_traj = _save_traj_g25f


async def main():
    attack = sys.argv[1]
    n = int(sys.argv[2])
    start = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    mode = sys.argv[4] if len(sys.argv) > 4 else "fresh"
    per_run_timeout = 240.0
    runs_path = OUT / f"{attack}_g25f_runs.jsonl"
    runs = []
    if mode == "append" and runs_path.exists():
        with open(runs_path) as f:
            runs = [json.loads(x) for x in f if x.strip()]
    rf = open(runs_path, "a" if mode == "append" else "w")
    try:
        for seed in range(start, start + n):
            t0 = time.time()
            try:
                sc = await asyncio.wait_for(runner.run_one(attack, seed),
                                            timeout=per_run_timeout)
            except asyncio.TimeoutError:
                sc = {"attack": attack, "seed": seed, "success": False,
                      "error": f"hard_timeout_{int(per_run_timeout)}s",
                      "reached_decision_point": False}
            except Exception as e:  # noqa: BLE001
                sc = {"attack": attack, "seed": seed, "success": False,
                      "error": f"runner_exception: {type(e).__name__}: {e}",
                      "reached_decision_point": False}
            sc["elapsed_s"] = round(time.time() - t0, 1)
            sc["model"] = "gemini-2.5-flash"
            runs.append(sc)
            rf.write(json.dumps(sc, default=str) + "\n")
            rf.flush()
            print(f"[{attack}|g25f seed={seed}] success={sc.get('success')} "
                  f"stage={sc.get('stage')} err={sc.get('error')} "
                  f"{sc['elapsed_s']}s", flush=True)
    finally:
        rf.close()

    succ = [1 if r.get("success") else 0 for r in runs]
    asr = sum(succ) / len(succ) if succ else 0.0
    reached = [r for r in runs if r.get("reached_decision_point")]
    rsucc = sum(1 for r in reached if r.get("success"))
    casr = (rsucc / len(reached)) if reached else 0.0
    summary = {
        "attack": attack, "model": "gemini-2.5-flash", "n": len(runs),
        "successes": sum(succ),
        "raw_asr": round(asr, 4), "raw_asr_pct": round(asr * 100, 1),
        "reached_decision_point": len(reached),
        "conditional_asr": round(casr, 4),
        "conditional_asr_pct": round(casr * 100, 1),
        "variance": round(statistics.pvariance(succ), 4) if succ else 0.0,
        "stdev": round(statistics.pstdev(succ), 4) if succ else 0.0,
        "completed_runs": sum(1 for r in runs if r.get("completed")),
        "errors_sample": [r.get("error") for r in runs
                          if r.get("error")][:8],
        "mean_elapsed_s": round(
            statistics.mean([r["elapsed_s"] for r in runs]), 1)
        if runs else 0,
    }
    with open(OUT / f"{attack}_g25f_summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print("SUMMARY_G25F:", json.dumps(summary, default=str))


if __name__ == "__main__":
    asyncio.run(main())
