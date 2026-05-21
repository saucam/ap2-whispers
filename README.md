# ap2-whispers

Headless attack rig + measurement results + a reproducible scoped-credential defense for the two attacks described in *"Whispers of Wealth: Red-Teaming Google's Agent Payments Protocol via Prompt Injection"* ([arXiv:2601.22569](https://arxiv.org/abs/2601.22569)), against the open-source AP2 ([Agent Payments Protocol](https://github.com/google-agentic-commerce/AP2)) Python reference. Companion code + trajectories for the long-form write-up.

## What this is

A measurement-piece companion repo. The paper presents two attacks (*Vault Whisper* and *Branded Whisper*) qualitatively, one screenshot each, on Gemini-2.5-Flash. This repo quantifies them:

- **20 seeds per attack**, raw and conditional ASR, variance, and a separate **clean no-attack baseline** as a reference-stability control.
- **Two flow harnesses** (AP2 v1 / human-present, AP2 v2 / human-not-present), each hitting its real surface. v1 is `shopping_agent` plus the A2A `credentials_provider_agent` (Vault surface); v2 is `shopping_agent_v2` plus MCP stdio role servers (Branded surface).
- **Four escalation probes** (refund-leg whisper, cart-mandate TOCTOU, cross-merchant bleed, payment-mandate scope inflation) measured against the unmodified reference.
- **Two defense variants** of the same enforcement point — principal-binding at the credentials provider — measured side-by-side: a *real* scoped-credential capability via the public [`highflame-ai/zeroid`](https://github.com/highflame-ai/zeroid) service, and a 3-line `requested == bound-subject` baseline. Both fully reproducible from public sources.

Trajectories, per-seed scored runs, and aggregated tables are in `results/`.

## Headline numbers (gemini-2.5-flash, paper's model)

| | N | Raw ASR | Conditional ASR | Clean baseline completion (no attack) |
|---|---|---|---|---|
| Vault Whisper (undefended) | 20 | **90.0%** (18/20) | 90.0% (18/20 reached) | v1: 10/10 (100%) |
| Branded Whisper (undefended) | 20 | 0.0% | 0.0% (0/19 reached) | v2: **0/10** (autonomous flow doesn't complete on paper's model) |
| Refund-leg whisper | 20 | 0.0% | n/a — no refund tool in AP2 reference (structural) |
| Cart-mandate TOCTOU | 20 | 0.0% | flow doesn't reach signing window |
| Cross-merchant bleed | 5 | 0.0% | n/a — mandates cryptographically scoped to one merchant (structural) |
| Payment-mandate scope inflation | 20 | 0.0% | defended 20/20 by AP2's own `AmountRange` constraint |
| **Vault Whisper, defended by standalone zeroid** | 20 | **0.0%** (0/20 breaches) | 0.0% | 0/12 false-deny on clean baseline |
| **Vault Whisper, defended by naive `email == bound-subject` check** | 20 | **0.0%** (0/20 breaches) | 0.0% | 0/12 false-deny on clean baseline |

Full tables: [`results/ASR_TABLE.md`](results/ASR_TABLE.md), [`results/ASR_TABLE_g25f.md`](results/ASR_TABLE_g25f.md), [`results/DEFENSE_TABLE.md`](results/DEFENSE_TABLE.md), [`results/DEFENSE_ZEROID_OSS_TABLE.md`](results/DEFENSE_ZEROID_OSS_TABLE.md). Methodology + caveats: [`results/RESULTS.md`](results/RESULTS.md), [`results/NOTES_DEFENSE.md`](results/NOTES_DEFENSE.md), [`results/NOTES_ZEROID_OSS.md`](results/NOTES_ZEROID_OSS.md).

## Honest caveats (read before citing)

- **Branded Whisper's clean non-repro control is `flash-lite`, not the paper's `2.5-flash`.** On the paper's own model the v2 baseline completes 0/10 (broken substrate). The honest claim is "Branded Whisper is unsubstantiated by any reproducible run" — both the paper's qualitative one and this measurement's. Don't read 0/20 on 2.5-Flash as a clean refutation; the cleaner control is the flash-lite run (0/18 conditional on a ~60%-stable baseline).
- **Cart-Mandate TOCTOU did not reproduce.** Two runs flagged by the post-hoc scorer had no signed-total-mismatch evidence in the trajectory; we do not claim TOCTOU.
- **The one modeled element in the defense is the source of the authorized session principal.** The AP2 reference stubs its identity redirect; we supply `bugsbunny@gmail.com` out-of-band from AP2's own demo prose. Everything downstream (mint, signature, introspection, reject) is a real OSS-zeroid HTTP round trip.
- **The threat models a real scoped-credential service closes that the 3-line check does not are not measured here.** The repo asserts them in `NOTES_ZEROID_OSS.md`; it does not claim numeric evidence for them.
- **Harness covers cards/v1/v2.** The `x402` (crypto) payment flow, the human-present interactive consent flow with browser UI, multi-merchant deployments, and Vertex AI–served Gemini are out of scope.

## Layout

```
harness/
  driver_v1.py, driver_v2.py     # headless A2A clients (no browser/Node)
  payloads.py                    # injection library
  adversary.py                   # adversarial-merchant cart-data variant
  runner.py, runner_g25f.py      # N-seed loop + trajectory capture
  scorer.py                      # success criteria per attack
  launch_v1.sh, launch_v2.sh     # bring up the AP2 role servers headless
  baseline_v1.py, baseline_v2.py, baseline_n.py, baseline_g25f.py
  cross_merchant.py              # escalation probe (structural)
  defense/
    scoped_credential.py         # Phase 3a — modeled (in-process) scoped-credential capability layer
    defense_scorer.py            # defense-aware scorer (breach = data RETURNED, not arg attempted)
    defense_runner.py            # Phase 3a runner
    apply_defense.sh / revert_defense.sh
    agent_executor.py.orig / .patched   # Phase 3a AP2 creds-provider patch
    naive_authz.py               # 3-line `email == bound-subject` baseline
    zeroid_oss_credential.py     # Phase 3b-oss — real OSS-zeroid (https://github.com/highflame-ai/zeroid) HTTP integration
    zeroid_oss_bootstrap.py      # one-shot: register identity + OAuth client against standalone zeroid
    agent_executor.py.phase3b_oss
    apply_defense_oss.sh         # idempotent, reversible
    defense_runner_oss.py        # Phase 3b-oss runner
results/
  ASR_TABLE.md, ASR_TABLE_g25f.md, DEFENSE_TABLE.md, DEFENSE_ZEROID_OSS_TABLE.md
  RESULTS.md, RESULTS_g25f.md, NOTES_DEFENSE.md, NOTES_ZEROID_OSS.md
  *_summary.json, *_runs.jsonl       # per-attack aggregates + per-seed
  trajectories/*.jsonl                # raw A2A trajectories (~230 files)
```

## Quick-start (full repro of the defense leg)

Tested on Ubuntu 24.04, Python 3.11, [`uv`](https://docs.astral.sh/uv/), Docker.

```bash
# 0. Get a personal Google AI Studio Gemini key.
#    https://aistudio.google.com/apikey

# 1. Clone this repo (the attack rig + harness) AND the AP2 reference.
git clone https://github.com/saucam/ap2-whispers.git
git clone https://github.com/google-agentic-commerce/AP2.git
cd ap2-whispers
# place the harness/ + harness/defense/ next to AP2/code/samples/python (or set AP2_ROOT)
echo "GOOGLE_API_KEY=<your_key>"          >  AP2/.env
echo "AGENT_MODEL=gemini-2.5-flash"       >> AP2/.env

# 2. Reproduce the undefended Vault Whisper (paper's deterministic data breach).
bash harness/launch_v1.sh
(cd AP2/code/samples/python && uv run python harness/runner.py vault_whisper 20 1)
# -> results/vault_whisper_g25f_runs.jsonl + summary

# 3. Bring up the public standalone ZeroID service (separate clone).
git clone https://github.com/highflame-ai/zeroid.git ~/work/zeroid
cd ~/work/zeroid
make setup-keys
sed -i 's/"5432:5432"/"5435:5432"/' docker-compose.yml   # if 5432 is already used on your host
docker compose up -d --build
curl http://localhost:8899/health   # {"status":"healthy","service":"zeroid",...}

# 4. Bootstrap the ZeroID identity + OAuth client for the AP2 demo session subject.
python3 ap2-whispers/harness/defense/zeroid_oss_bootstrap.py
# writes ./zeroid_oss_client.env (or set AP2_ZEROID_OSS_CLIENT_ENV)

# 5. Apply the defense to the v1 creds-provider, run defended Vault N=20 + clean baseline.
bash ap2-whispers/harness/defense/apply_defense_oss.sh
(cd AP2/code/samples/python && uv run python harness/defense/defense_runner_oss.py vault 20 1)
(cd AP2/code/samples/python && uv run python harness/defense/defense_runner_oss.py baseline 12 1)
# -> results/defense_zeroid_oss_vault_runs.jsonl + defense_zeroid_oss_baseline_runs.jsonl
```

Detailed reader notes: [`results/NOTES_ZEROID_OSS.md`](results/NOTES_ZEROID_OSS.md). The `naive-authz` variant follows the same pattern with `harness/defense/naive_authz.py`.

## Companion write-up

The long-form discussion of these numbers, the methodology, what they mean for AP2's threat model, and where productized scoped credentials matter beyond what this measurement shows lives in the published write-up (link to be added on publication). For the headline read of the results, the four tables under `results/` are self-contained.

## Cost

The Vault + Branded + escalations + defense + baseline runs cost on the order of a few hundred K Gemini tokens total (negligible $ on a personal Google AI Studio key). CPU box, no GPU needed.

## Acknowledgments

- The AP2 reference and its demo data ([Apache-2.0](https://github.com/google-agentic-commerce/AP2/blob/main/LICENSE)) are the substrate this work measures against.
- The *Whispers of Wealth* paper authors ([arXiv:2601.22569](https://arxiv.org/abs/2601.22569)) for the original attack design.
- The [`highflame-ai/zeroid`](https://github.com/highflame-ai/zeroid) ZeroID project for an open-source scoped-credential service that the defense leg uses verbatim.

## License

[Apache-2.0](LICENSE). Files in `harness/defense/agent_executor.py.{orig,patched,phase3b_oss}` are derivatives of AP2's own Apache-2.0 source and preserve the original headers.

## Disclosure

`Vault Whisper` is a quantification of a previously published attack against a public OSS reference; the underlying root cause (zero session↔account binding on the credentials provider) is openly visible in the reference's own source. A courtesy heads-up was sent to Google via `g.co/vulnz` before publication (the path AP2's `SECURITY.md` documents). The AP2 reference is explicitly a demo; this repo is not an exploit kit for a deployed payments system.
