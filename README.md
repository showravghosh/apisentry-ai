# APISentry

This repository accompanies the manuscript "APISentry: A Real-Time Hybrid Machine Learning Gateway for Detecting Behavioural and Payload-Based API Attacks". It contains the labelled dataset, the test API and traffic generator, the gateway in its frozen configuration, the signature-blocking baseline APISentry-SIG, the rate-limiting baseline, every evaluation script with its seeds, and the raw result files behind every table and figure.

## 1. Contents

| Folder | What it contains |
|---|---|
| `data/` | `apishield_dataset_v1.csv`: 11,415 labelled requests in 1,741 sessions (8 classes); `external/README.md` explains how to obtain the two public benchmarks |
| `test-api/` | The REST API used as the protected backend (FastAPI) |
| `traffic-generator/` | Scripts that generated the dataset (normal traffic and seven attack types) |
| `gateway/` | APISentry in its frozen configuration: `gateway.py` and `artifacts/` (CatBoost model, scaler, encoders, feature list, policies, API profile for VAmPI). Run with `APISENTRY_POLICY=v9` |
| `original_with_reset_hook/` | APISentry-SIG: the signature-blocking gateway (behavioural guard and fixed rate and token signatures) with a test reset endpoint |
| `previous_v8/`, `previous_v7/` | Earlier configurations from the development phase. `previous_v8/` is started by the live run script; its results are not reported in the paper |
| `baseline/` | Token-bucket rate limiter baseline (`ratelimit_proxy.py`) |
| `ml-pipeline/` | Feature construction (`features.py`), model definition (`common.py`), statistics (`stats.py`) and `build_gateway_model.py` |
| `offline/` | Offline experiments, one script per experiment (Section 4) |
| `analysis/` | `event_level.py`: live event-level summary from a decision log |
| `experiments/live/` | Live coverage, network-regime, evasion and load-test scripts, the stub backend and the frozen configuration record `FROZEN_CONFIG_V9.txt` |
| `experiments/tools/` | Third-party tool suite (sqlmap, hydra, ffuf, ApacheBench), the counting relay with one browser User-Agent, the credential-stuffing sender and the VAmPI legitimate-user script |
| `kali_run/` | `run_v9_final.sh` (live run), `make_freeze_v9.sh`, `FROZEN_SHA256_V9.txt`, step-by-step instructions `KALI_STEPS_V9.md` |
| `results/offline/` | Raw JSON results of the offline experiments |
| `results/kali/` | Raw JSON results of the live run; `decision_logs/` holds the gateway decision logs; `preliminary_default_user_agent/` holds the tool run in which every tool sent its own User-Agent (Section 5.18 of the paper) |
| `results/runtime/` | Load-test and state-memory results |
| `figures/` | `make_figures.py` (Figures 6–11), `make_live_figures_v9.py` (Figures 12–15) and `diagrams/` (draw.io sources of Figures 1 and 2) |

## 2. Requirements

- Linux (tested on Kali Linux and Ubuntu 24.04), Python 3.11–3.13
- `pip install -r requirements.txt` (versions are pinned; **pandas must stay below 3.0**, because pandas 3 changes the timestamp resolution and silently breaks the 10-second windows)
- For the live tests: Docker (ModSecurity with the OWASP Core Rule Set, and VAmPI `erev0s/vampi:latest`), and the tools `sqlmap`, `hydra`, `ffuf` and `ab` (`sudo apt install sqlmap hydra ffuf apache2-utils`)
- PostgreSQL or SQLite for the test API (`APISENTRY_DB`, default SQLite)

## 3. Quick start: run the gateway

```bash
pip install -r requirements.txt
export APISENTRY_DB=sqlite:///$(pwd)/live.db
(cd test-api && python seed.py)
uvicorn main:app --app-dir test-api --port 8000 &
APISENTRY_POLICY=v9 APISENTRY_BACKEND=http://127.0.0.1:8000 uvicorn gateway:app --app-dir gateway --port 9000 &
curl -i http://127.0.0.1:9000/products
curl -i "http://127.0.0.1:9000/search?q=' OR 1=1 --"
```

Allowed requests are forwarded; blocked requests receive HTTP 403 and rate-limited requests HTTP 429, with the predicted class and risk score in the response. `APISENTRY_TEST_HOOKS=1` enables `POST /__apisentry/reset`, which clears the gateway state between test runs. `APISENTRY_PROFILE=gateway/artifacts/profile_vampi.json` declares the login path, the login-failure marker and the object-path patterns of another API.

## 4. Reproducing the tables and figures

The offline scripts import `features.py`, `common.py` and `stats.py` from the working directory and write their output to `out/`. Run them from `ml-pipeline/`:

```bash
cd ml-pipeline && mkdir -p out
export APISENTRY_DATA=../data/apishield_dataset_v1.csv
```

| Paper item | Command (from `ml-pipeline/`) | Reported result file |
|---|---|---|
| Tables 5, 6 (dataset) | computed from `data/apishield_dataset_v1.csv` | – |
| Tables 8, 9, 10, 11, 15, 18, 21; first row of Table 12; APISentry-SIG rows of Table 16; SQL-keyword, 10-s object and flood-floor rows of Table 22 | `python ../offline/e10_final.py ../gateway/artifacts/policy_v6.json` | `results/offline/e10_final.json` |
| Table 12 (partitioning protocols) | `python ../offline/e1_partition.py` and `python ../offline/e1b_lopo.py` | `results/offline/e1_partition.json`, `e1b_lopo.json` |
| Tables 13, 14 (external benchmarks) | `python ../offline/e11_external.py ../data/external` (see `data/external/README.md`) | `results/offline/e11_external.json` |
| Tables 16, 17; 60-s rows of Table 22; offline columns of Table 20 | `python ../offline/e15_v8_stages.py ../gateway/artifacts/policy_v6.json ../gateway/artifacts/policy_v8.json v8` | `results/offline/e15_v8_stages.json` |
| Supporting rule checks for Tables 17 and 22 | `python ../offline/e12_v7.py ../gateway/artifacts/policy_v6.json`; `python ../offline/e13_v7_stages.py ../gateway/artifacts/policy_v6.json ../gateway/artifacts/policy_v7.json` | `results/offline/e12_v7.json`, `e13_v7_stages.json` |
| Table 19 (shortcut and account features) | `python ../offline/e6_shortcut.py` | `results/offline/e6_shortcut.json`, `e6_shortcut_F19_robust_acct.json` |
| Figure 11 (Shapley values) | `python ../offline/e14_shap.py ../gateway/artifacts` | `results/offline/e14_shap.json` |
| Figures 6–11 | `python ../figures/make_figures.py figs ../results/kali ../results/runtime` (after `e10_final.py` and `e14_shap.py`) | – |

The gateway's offline decision logic is identical for policies v8 and v9: the URL-path SQL rule of v9 fires on no request of the dataset, because no dataset path contains an SQL keyword.

| Paper item | Command (from the archive root) | Reported result file |
|---|---|---|
| Live tables 20 (live columns), 23, 24, 25, 28, 29, 30; Figures 12, 13, 15 | `bash kali_run/run_v9_final.sh all` (Section 5) | `results/kali/*_final10*` |
| Table 20, live columns | `python analysis/event_level.py results/kali/decision_logs/dec_v9.csv 0` (original suite) and `... 40` (extended suite) | – |
| Tables 26, 27; Figure 14 (load test and state memory) | `bash experiments/live/load_run_v9.sh` | `results/runtime/` |
| Figures 12–15 | `python figures/make_live_figures_v9.py figs results/kali results/runtime` | – |
| Figures 1, 2 | open `figures/diagrams/*.drawio` in draw.io | – |

Tables 1, 2, 3, 4, 7 and 24 are descriptive. Figures 3, 4 and 5 show the monitoring dashboard, the testbed and the running services.

## 5. Live run

`kali_run/run_v9_final.sh` first verifies the SHA-256 checksums of the frozen configuration (`kali_run/FROZEN_SHA256_V9.txt`), then starts the systems and runs, on identical traffic:

- the original and extended live suites (seeds 10001–10005);
- six network-identity regimes (seeds 10101–10105);
- the evasion suite (seed 10201; gaps of 0.45, 1.4, 5.5, 2.8 and 3.8 s for medium and slow flooding, slow brute force, slow BOLA-like access and slow token replay);
- the third-party tool suite through the relay with one browser User-Agent (relay seed 10401; every tool job is stopped after 300 s);
- the second API, VAmPI, with and without its API profile (legitimate users with seeds 10301–10303, and the tool suite).

It expects the test API on port 8000 and ModSecurity with the Core Rule Set (paranoia level 1, default anomaly thresholds) on port 8081; it starts APISentry, APISentry-SIG (with and without state reset), the rate limiter and the relay itself. `KALI_STEPS_V9.md` lists every step. Results are written to `kali/results/` and decision logs to `kali/logs/`.

## 6. Demo with the monitoring dashboard

`setup.sh` creates the Python environments, `run.sh` starts the test API (port 8000), the gateway (port 9000) and the monitoring dashboard (port 8080), `demo.sh` runs a short attack simulation, `reset.sh` clears the dashboard and `stop.sh` stops all services. `DEMO_GUIDE.md` describes the demo step by step.

## 7. Earlier version

Release `v1.0.0` contains the first public version of the code, including the exploratory alternative models (isolation forest, LSTM, graph model, stacked ensemble) and the earlier validation notebooks.

## 8. Licence

Code: MIT licence. Dataset: Creative Commons Attribution 4.0 International.
