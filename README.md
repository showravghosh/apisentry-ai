# APISentry

**A real-time hybrid machine-learning gateway that protects REST APIs from behavioural and payload-based attacks.**

APISentry sits in front of your API as a reverse proxy. Every incoming request passes through APISentry *first*: it describes the request by payload features and by causal behavioural features (what the same source, token, identity and account did in the last seconds), scores it with a CatBoost classifier, and then decides with a graded policy:

- **ALLOW** – the request is forwarded to the real API;
- **RATE_LIMIT** – the client receives HTTP `429` and can retry later;
- **BLOCK** – the client receives HTTP `403` and the request never reaches the API.

Blocking is reserved for evidence that legitimate traffic does not produce, so legitimate users behind shared addresses, proxies or mobile networks are not blocked.

APISentry detects **seven API attack types**:

| # | Attack | What it looks like |
|---|--------|--------------------|
| 1 | **SQL injection** | SQL keywords inside the query string, the body or the URL path |
| 2 | **Parameter tampering** | Negative or out-of-range values, or client-supplied prices |
| 3 | **BOLA-like access** | One identity enumerating many object IDs (a behavioural pattern; object ownership is not verified) |
| 4 | **Brute force** | Many failed logins against one account |
| 5 | **Credential stuffing** | Leaked username/password pairs tried across many accounts, also from rotating addresses |
| 6 | **API flooding** | An abnormally high request rate from one source |
| 7 | **Token replay** | One token used from several source addresses (cross-source token reuse) |

> ⚠️ **Research project.** Run the attacks only against the included test API (or another system you own) in a controlled environment.

---

## Table of Contents
1. [How it works](#how-it-works)
2. [Project structure](#project-structure)
3. [Requirements](#1-requirements)
4. [Download](#2-download-the-project)
5. [Install](#3-install-one-time)
6. [Run](#4-start-the-tool)
7. [Open the dashboard](#5-open-the-dashboard)
8. [See attacks being stopped](#6-see-attacks-being-stopped)
9. [Stop everything](#7-stop-everything)
10. [Configuration](#configuration)
11. [Results](#results)
12. [Reproducing the research](#reproducing-the-research)
13. [Troubleshooting](#troubleshooting)
14. [Citation & licence](#citation--licence)

---

## How it works

```
                         ┌──────────────────────────────────────────┐
   Client request ─────► │            APISentry gateway             │
                         │  1. normalisation + feature extraction   │
                         │  2. CatBoost classifier (19 features)    │
                         │  3. hard evidence rules                  │
                         │  4. graded classifier policy             │
                         │  5. volume controls                      │
                         └───────┬──────────────┬──────────────┬────┘
                                 │              │              │
                          ALLOW  ▼   RATE_LIMIT ▼        BLOCK ▼
                    forwarded to the   HTTP 429          HTTP 403
                    real API           (client may       (never reaches
                                        retry)            the API)
                                 every decision is logged and shown on the dashboard
```

**Features.** Every request is described by two kinds of features:
- **Payload features** – SQL-keyword count (query, body and URL path, after repeated URL decoding and normalisation), special characters, numeric extremes and negative values, field count. They catch attacks whose evidence is *inside a single request* (injection, tampering).
- **Behavioural features** – requests, HTTP errors, logins and distinct endpoints per source in 10 s; distinct objects per identity; distinct sources per token; failed logins and distinct accounts per account and gateway-wide. They are **causal**: they use only requests that arrived before or with the current one. They catch attacks that are visible only *across requests* (BOLA-like access, brute force, credential stuffing, flooding, token replay).

**Decision layer.**
1. **Hard evidence rules → BLOCK**: SQL keywords ≥ 3 (body, query or URL path); one identity touching ≥ 7 distinct objects in 10 s or ≥ 12 in 60 s; a negative value or a client-supplied price field.
2. **Graded classifier policy** with the risk score r = 1 − P(normal): r ≥ 0.75 → RATE_LIMIT; r ≥ 0.99 *and* class-specific evidence → BLOCK. A flooding prediction is acted on only after ≥ 10 requests in 10 s and only with RATE_LIMIT; a BOLA-like prediction only after ≥ 2 distinct objects in 10 s.
3. **Volume controls → RATE_LIMIT**: ≥ 3 failed logins from an address in 60 s; ≥ 30 requests from an identity in 60 s; a token bucket of 10 requests/s with a burst of 20 (per identity when a token is present).

All thresholds were selected on validation data only. SHAP explanations of the classifier are computed offline and are not part of the request path.

---

## Project structure

```
apisentry-ai/
├── gateway/                  The APISentry gateway (the main tool)
│   ├── gateway.py                Reverse proxy, feature extraction, scoring and enforcement
│   └── artifacts/                CatBoost model, scaler, encoders, feature list,
│                                 policies (v6–v9) and the VAmPI API profile
│
├── dashboard/                Live monitoring dashboard
│   └── app.py                    Threat level, counts, attack breakdown, recent decisions
│
├── test-api/                 Target REST API (login, products, search, users, orders)
│   ├── main.py                   FastAPI app and routes
│   ├── auth.py                   Authentication and tokens
│   ├── database.py               Database connection (PostgreSQL, or SQLite via APISENTRY_DB)
│   ├── models.py  schemas.py     ORM models and request/response schemas
│   ├── seed.py                   Seeds demo users and data
│   ├── logger.py                 Request logging
│   └── docker-compose.yml        PostgreSQL container
│
├── traffic-generator/        Normal and attack traffic (builds the dataset)
│   ├── normal_traffic.py         Benign user journeys
│   ├── attack_*.py               The seven attack types
│   ├── adversarial_test.py       Evasion variants
│   ├── run_all.py                Generates the full labelled dataset
│   └── demo.py  live_demo.py     Live traffic for demos
│
├── data/
│   ├── apishield_dataset_v1.csv  11,415 labelled requests, 1,741 sessions, 8 classes
│   └── external/README.md        How to obtain CSIC 2010 and ECML/PKDD 2007
│
├── ml-pipeline/              Feature construction, model, statistics, model export
│   ├── features.py  common.py  stats.py
│   └── build_gateway_model.py
│
├── offline/                  Offline experiments (cross-validation, partitions, external
│                             benchmarks, ablations, decision-layer stages, SHAP)
├── experiments/
│   ├── live/                     Live coverage, network regimes, evasion, load test,
│   │                             state memory, stub backend, FROZEN_CONFIG_V9.txt
│   └── tools/                    sqlmap / hydra / ffuf / ApacheBench suite, User-Agent relay,
│                                 credential-stuffing sender, VAmPI legitimate users
├── analysis/event_level.py   Event-level summary of a live decision log
├── kali_run/                 run_v9_final.sh (complete live run), checksums, step-by-step guide
│
├── baseline/
│   ├── ratelimit_proxy.py        Token-bucket rate-limiter baseline
│   └── docker-compose.yml        ModSecurity with the OWASP Core Rule Set (port 8081)
├── original_with_reset_hook/ APISentry-SIG: signature-blocking baseline gateway
├── previous_v8/  previous_v7/    Earlier configurations from development
│
├── results/                  Raw results behind every table and figure
│   ├── offline/                  Offline experiments (JSON)
│   ├── kali/                     Live run (JSON) and decision_logs/
│   └── runtime/                  Load test and state memory
├── figures/                  Figure scripts and draw.io sources of Figures 1 and 2
│
├── setup.sh  run.sh  stop.sh  reset.sh  demo.sh    Helper scripts
├── DEMO_GUIDE.md             Exact commands to trigger all seven attacks
├── requirements.txt          Pinned Python packages for the research scripts
├── CITATION.cff              How to cite this work
└── LICENSE
```

---

## 1. Requirements

You need a **Linux machine** (developed and tested on **Kali Linux**). Install the tools below:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git docker.io docker-compose sqlmap hydra ffuf apache2-utils
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Then **log out and log back in once**, so Docker works without `sudo`.

---

## 2. Download the project

```bash
git clone https://github.com/showravghosh/apisentry-ai.git
cd apisentry-ai
```

---

## 3. Install (one time)

This creates the Python virtual environments for the test API, the gateway and the traffic generator:

```bash
./setup.sh
```

Wait until it prints **`Setup complete`**.

---

## 4. Start the tool

```bash
./run.sh
```

This starts four services:

| Service | Port | What it is |
|---------|------|------------|
| Database | 5432 | PostgreSQL (in Docker) |
| Backend API | `8000` | The target REST API |
| APISentry gateway | `9000` | The main tool (policy v9) |
| Dashboard | `8080` | Live monitoring dashboard |

When it prints that APISentry is **RUNNING**, everything is up. Send your requests to port **9000** instead of 8000; APISentry forwards the allowed ones.

```bash
curl -i http://localhost:9000/products
curl -i "http://localhost:9000/search?q=%27%20OR%201%3D1%20--"
```

The first request is forwarded (HTTP 200); the second is blocked (HTTP 403). Every response from APISentry carries the predicted class and the risk score.

---

## 5. Open the dashboard

In your browser, open:

```
http://localhost:8080
```

You will see live counts of allowed, rate-limited and blocked requests, the current threat level, the attack breakdown and a table of recent decisions.

---

## 6. See attacks being stopped

Clear the dashboard to zero (recommended before a demo):

```bash
./reset.sh
```

Then send live normal **and** attack traffic:

```bash
./demo.sh        # press Ctrl+C to stop
```

Or run real attacks yourself and watch them on the dashboard. **`DEMO_GUIDE.md`** lists the exact commands for all seven attacks, including `sqlmap` for SQL injection. Behavioural attacks are recognised after a few requests: flooding, brute force and credential stuffing are usually rate-limited (HTTP 429), while SQL injection, tampering and BOLA-like enumeration are blocked (HTTP 403).

---

## 7. Stop everything

```bash
./stop.sh
```

The PostgreSQL container keeps running; stop it with `(cd test-api && docker compose down)`.

---

## Configuration

The gateway is configured through environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `APISENTRY_POLICY` | `v9` | Decision policy (`gateway/artifacts/policy_<name>.json`) |
| `APISENTRY_BACKEND` | `http://localhost:8000` | The protected API |
| `APISENTRY_PROFILE` | built-in | JSON profile for another API: login paths, failed-login marker, object-path patterns (example: `gateway/artifacts/profile_vampi.json`) |
| `APISENTRY_DECISION_LOG` | `gateway/gateway_decisions.csv` | Decision log read by the dashboard |
| `APISENTRY_TEST_HOOKS` | off | `1` enables `POST /__apisentry/reset` (clears the gateway state between test runs) |
| `APISENTRY_DB` | PostgreSQL | Database of the test API, e.g. `sqlite:///live.db` |

Example: run APISentry manually in front of another API with its profile:

```bash
APISENTRY_BACKEND=http://127.0.0.1:5000 APISENTRY_PROFILE=gateway/artifacts/profile_vampi.json \
gateway/venv/bin/python -m uvicorn gateway:app --app-dir gateway --port 9000
```

---

## Results

Measured on the labelled dataset (**11,415 requests, 1,741 sessions, eight classes**) and in a live testbed with held-out seeds:

- **Classifier:** macro-F1 **0.929** (95% CI 0.920–0.937), false-positive rate 0.030, under five-fold cross-validation grouped by session with behavioural windows rebuilt inside every partition. Payload features alone reach 0.568 and behavioural features alone 0.814; the combination is clearly better than either view.
- **Full gateway, offline:** blocks **none** of the 6,716 benign requests, rate-limits 1.15%, and enforces 83.9% of the attack requests.
- **Live, held-out traffic:** enforces **87.7%** of 2,000 attack requests (95% CI 86.2–89.1%) while blocking **none of 2,750** legitimate requests, compared with 11.0% for ModSecurity with the OWASP Core Rule Set and 46.6% for a token-bucket rate limiter.
- **Network identity:** no legitimate user is blocked behind a shared NAT, a bursty client, a mobile network or a shared authenticated proxy; anonymous clients that share one address can be rate-limited.
- **Third-party tools and a second API:** tested with sqlmap, hydra, ffuf and ApacheBench, and on VAmPI, an independently developed API, with a four-line API profile. Only APISentry stops credential stuffing from rotating addresses.
- **Runtime:** a single gateway process adds a median of **2.0 ms** per request and sustains about 300–440 requests per second on two vCPUs.
- **Limits:** the payload features are specific to the evaluated API (CSIC 2010 F1 0.564 for the payload component), and slow, distributed evasions (slow flooding, slow token replay, disguised tampering, slow enumeration) are only partly detected.

---

## Reproducing the research

### A. Research environment

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The versions are pinned. **pandas must stay below 3.0**: pandas 3 changes the timestamp resolution and silently breaks the 10-second windows.

### B. Offline experiments (tables and figures from the dataset)

The scripts import `features.py`, `common.py` and `stats.py` from the working directory and write to `out/`, so run them from `ml-pipeline/`:

```bash
cd ml-pipeline && mkdir -p out
export APISENTRY_DATA=../data/apishield_dataset_v1.csv
../.venv/bin/python ../offline/e10_final.py ../gateway/artifacts/policy_v6.json
../.venv/bin/python ../offline/e1_partition.py
../.venv/bin/python ../offline/e1b_lopo.py
../.venv/bin/python ../offline/e11_external.py ../data/external
../.venv/bin/python ../offline/e15_v8_stages.py ../gateway/artifacts/policy_v6.json ../gateway/artifacts/policy_v8.json v8
../.venv/bin/python ../offline/e6_shortcut.py
../.venv/bin/python ../offline/e14_shap.py ../gateway/artifacts
../.venv/bin/python ../figures/make_figures.py figs ../results/kali ../results/runtime
cd ..
```

| Paper item | Script | Reported result file |
|---|---|---|
| Tables 8, 9, 10, 11, 15, 18, 21; Figures 6–10 | `e10_final.py` | `results/offline/e10_final.json` |
| Table 12 (partitioning protocols) | `e1_partition.py`, `e1b_lopo.py` | `results/offline/e1_partition.json`, `e1b_lopo.json` |
| Tables 13, 14 (external benchmarks; files in `data/external/`) | `e11_external.py` | `results/offline/e11_external.json` |
| Tables 16, 17, 22; offline columns of Table 20 | `e15_v8_stages.py` (and `e10_final.py`, `e12_v7.py`, `e13_v7_stages.py`) | `results/offline/e15_v8_stages.json` |
| Table 19 (shortcut and account features) | `e6_shortcut.py` | `results/offline/e6_shortcut.json` |
| Figure 11 (Shapley values) | `e14_shap.py` | `results/offline/e14_shap.json` |

The offline decision logic is identical for policies v8 and v9: the URL-path SQL rule of v9 fires on no request of the dataset.

### C. Live experiments on Kali Linux (Tables 20, 23–25, 28–30; Figures 12, 13, 15)

1. Start the test API on port 8000 (`./run.sh` does this; stop the demo gateway with `pkill -f "uvicorn gateway:app"`).
2. Start ModSecurity with the OWASP Core Rule Set on port 8081:
   ```bash
   docker compose -f baseline/docker-compose.yml up -d
   ```
3. Run every live experiment (about 40–70 minutes; Docker pulls the VAmPI image once):
   ```bash
   GP=.venv/bin/python TP=.venv/bin/python bash kali_run/run_v9_final.sh all 2>&1 | tee run_all.txt
   ```

The script first verifies the SHA-256 checksums of the frozen configuration (`kali_run/FROZEN_SHA256_V9.txt`), then runs on identical traffic: the original and extended live suites (seeds 10001–10005), six network-identity regimes (seeds 10101–10105), the evasion suite (seed 10201), the third-party tool suite through a relay with one browser User-Agent (relay seed 10401), and the second API VAmPI with and without its profile (seeds 10301–10303). It starts APISentry, APISentry-SIG (with and without state reset), the rate limiter and the relay itself. Results go to `kali/results/` and decision logs to `kali/logs/`; `kali_run/KALI_STEPS_V9.md` lists every step.

Live event-level numbers of Table 20 from a decision log:

```bash
.venv/bin/python analysis/event_level.py results/kali/decision_logs/dec_v9.csv 0     # original suite
.venv/bin/python analysis/event_level.py results/kali/decision_logs/dec_v9.csv 40    # extended suite
```

### D. Load test and state memory (Tables 26, 27; Figure 14)

```bash
source .venv/bin/activate
bash experiments/live/load_run_v9.sh
```

It runs a stub backend on port 8000 and the gateway on port 9000, so stop the demo services first (`./stop.sh`).

### E. Live figures (Figures 12–15) from the stored results

```bash
.venv/bin/python figures/make_live_figures_v9.py figs results/kali results/runtime
```

Figures 1 and 2 are drawn in draw.io (`figures/diagrams/`).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| **Dashboard does not open** | Run `pgrep -f uvicorn`; you should see three processes. If not, check `cat /tmp/apisentry_gateway.log`. |
| **`docker: permission denied`** | Log out and back in (so your user joins the `docker` group), or run with `sudo`. |
| **Port already in use** | Run `./stop.sh` first, then `./run.sh` again. |
| **Backend not seeded / empty data** | Re-run `./run.sh`; it re-seeds the database on start. |
| **`CHECKSUM MISMATCH` in the live run** | A frozen file was changed; restore it with `git checkout -- .` |
| **`port 8081 unreachable`** | Start ModSecurity (Section C, step 2). |
| **`MISSING <tool>`** | `sudo apt install -y sqlmap hydra ffuf apache2-utils` |
| **Wrong window counts with a new pandas** | Install the pinned versions (`requirements.txt`, pandas < 3.0). |

Logs are written to `/tmp/apisentry_backend.log`, `/tmp/apisentry_gateway.log` and `/tmp/apisentry_dashboard.log`.

---

## Citation & licence

If you use this software or dataset, please cite it using the metadata in **`CITATION.cff`**.

Code: MIT licence (see **`LICENSE`**). Dataset: Creative Commons Attribution 4.0 International. Release `v1.0.0` contains the first public version of the code, including the exploratory alternative models (isolation forest, LSTM, graph model, stacked ensemble) and the earlier validation notebooks.

## Authors

**Showrav Ghosh** — Author, developer, and researcher.
Department of Computer Science, American International University-Bangladesh (AIUB), Dhaka, Bangladesh.
Email: 23-50666-1@student.aiub.edu · ORCID: https://orcid.org/0009-0008-6639-9698

**Md. Manirul Islam** — Supervisor and corresponding author.
Associate Professor; Director, IT (Network Operations); and Director, Institute of Continuing Education, American International University-Bangladesh (AIUB), Dhaka, Bangladesh. A cybersecurity expert and IT strategist with over 23 years of experience in network architecture, digital security, and advanced computing.
Email: manirul@aiub.edu · ORCID: https://orcid.org/0009-0007-9779-7915 · Profile: https://www.aiub.edu/faculty-list/faculty-profile?q=manirul

American International University-Bangladesh (AIUB), 408/1, Kuratoli, Khilkhet, Dhaka 1229, Bangladesh.
