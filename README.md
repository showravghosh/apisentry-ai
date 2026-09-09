# APISentry AI

**A real-time, AI-powered security gateway that protects REST APIs from behavioural and payload-based attacks.**

APISentry AI sits in front of your API as a reverse proxy. Every incoming request passes through APISentry *first*: it extracts features from the request, scores it with machine-learning models, and either forwards the request to the real API (allow) or blocks it with an HTTP `403` before it ever reaches your server. Unlike a traditional firewall that only matches fixed signatures, APISentry also **learns what normal traffic looks like**, so it catches both known attacks and previously unseen (zero-day) ones.

It detects **seven API attack types**:

| # | Attack | What it looks like |
|---|--------|--------------------|
| 1 | **SQL Injection** | Malicious SQL inside request parameters or body |
| 2 | **Brute-Force Login** | Many failed logins against one account |
| 3 | **BOLA** (Broken Object Level Authorization) | One user enumerating other users' object IDs |
| 4 | **API Flooding** | Abnormally high request rate from one source |
| 5 | **Credential Stuffing** | Rotated username/password pairs across many accounts |
| 6 | **Parameter Tampering** | Negative or out-of-range values in parameters |
| 7 | **Token Replay** | One token reused from several different sources |

> ⚠️ **Research project.** All attacks are executed only against the included test API in a controlled environment. Never attack a system you do not own.

---

## Table of Contents
1. [How it works](#how-it-works)
2. [The AI inside](#the-ai-inside-layered-defence)
3. [Project structure](#project-structure)
4. [Requirements](#1-requirements)
5. [Download](#2-download-the-project)
6. [Install](#3-install-one-time)
7. [Run](#4-start-the-tool)
8. [Open the dashboard](#5-open-the-dashboard)
9. [See attacks being blocked](#6-see-attacks-being-blocked)
10. [Stop everything](#7-stop-everything)
11. [Results](#results)
12. [Reproducing the research](#reproducing-the-research)
13. [Troubleshooting](#troubleshooting)
14. [Citation & license](#citation--license)

---

## How it works

```
                          ┌─────────────────────────────┐
   User request  ───────► │      APISentry Gateway       │
                          │  (feature extraction + AI)   │
                          └──────────────┬──────────────┘
                                         │ decision
                          ┌──────────────┴──────────────┐
                          │                             │
                    Safe  ▼                      Attack ▼
              forwarded to the             BLOCKED (HTTP 403)
              real API (allowed)           shown on the dashboard
```

Every request is turned into two kinds of features:
- **Payload features** — SQL-keyword density, special-character counts, numeric anomalies, length and field structure. These catch attacks whose evidence is *inside a single request* (mainly injection and tampering).
- **Behavioural features** — request rate, failed-login ratio, login attempts, distinct objects touched, and token reuse, all computed over **causal per-source and per-token time windows**. These catch attacks that are only visible *across many requests* (BOLA, brute force, credential stuffing, flooding, token replay).

The gateway then produces a **risk score** and applies a graded policy: allow, rate-limit, or block. Because it adds only about **9 ms per request**, it works comfortably in real time.

---

## The AI inside (layered defence)

No single model is best at everything, so APISentry trains and evaluates several and deploys the strongest combination:

| Model | Role |
|-------|------|
| **CatBoost** (deployed classifier) | Fast, accurate detection of known attack classes |
| **Random Forest** | Baseline tree ensemble for comparison |
| **Isolation Forest** | Unsupervised anomaly detection — catches new / zero-day attacks it never saw in training |
| **LSTM** (deep learning) | Learns the temporal pattern of a whole session |
| **GNN** (graph neural network) | Models "who accesses whose data" for BOLA detection |

The deployed enforcement path uses the **CatBoost classifier + behavioural guard + high-precision signature rules + threshold policy**. The other models are trained and evaluated for research comparison. APISentry also explains its decisions with **SHAP** (why a given request was blocked).

---

## Project structure

```
apisentry-ai/
├── test-api/              Target REST API (login, products, cart, users, orders)
│   ├── main.py                FastAPI app and routes
│   ├── auth.py                Authentication / token handling
│   ├── database.py            DB connection
│   ├── models.py schemas.py   ORM models and request/response schemas
│   ├── seed.py                Seeds demo users and data
│   ├── logger.py              Request logging
│   └── docker-compose.yml     PostgreSQL container
│
├── traffic-generator/     Creates normal + attack traffic (builds the dataset)
│   ├── normal_traffic.py      Realistic benign user journeys
│   ├── attack_sql_injection.py
│   ├── attack_brute_force.py
│   ├── attack_bola.py
│   ├── attack_flooding.py
│   ├── attack_credential_stuffing.py
│   ├── attack_parameter_tampering.py
│   ├── attack_token_replay.py
│   ├── adversarial_test.py    Adversarial / evasion testing
│   ├── regime_test3.py        Network-regime robustness (NAT / rotation / bursty), 5 seeded runs
│   ├── run_all.py             Generate the full labelled dataset
│   ├── demo.py live_demo.py   Live traffic for demos
│   └── dataset/traffic_logs.csv   The generated labelled dataset
│
├── ml-pipeline/           Preprocessing, training, evaluation, figures
│   ├── preprocess.py          Causal, leakage-free feature engineering
│   ├── train.py               Train Random Forest + CatBoost
│   ├── train_anomaly.py       Train Isolation Forest
│   ├── train_noleak.py        Leakage-controlled training
│   ├── build_sequences.py     Session sequences for the LSTM
│   ├── build_graph.py         Access graph for the GNN
│   ├── ensemble.py            Combine models
│   ├── cross_validate.py      5-fold cross-validation
│   ├── ablation.py            Feature-view / component ablations
│   ├── disjoint_split.py      Source-address-disjoint generalisation split
│   ├── rule_threshold_sweep.py  Payload-signature threshold selection
│   ├── cred_feature_ablation.py Distinct-account feature ablation
│   ├── detection_latency.py   Event-level detection latency
│   ├── knn_benchmark.py       KNN inference-cost / scaling baseline
│   ├── session_level_test.py  Session-level significance test (Wilcoxon + bootstrap)
│   ├── latency_test.py        Per-request runtime measurement
│   ├── shap_explain.py        SHAP explainability figures
│   ├── build_gateway_model.py Export the deployed gateway model
│   ├── models/                Trained models (.cbm, .pkl, .pt)
│   ├── processed/             Processed dataset
│   └── results/               Metrics, CSVs and figures
│
├── gateway/               The AI security gateway (the main tool)
│   ├── gateway.py             Reverse proxy + scoring + enforcement
│   └── artifacts/             Deployed model + scaler + encoders + feature list
│
├── dashboard/             Live security dashboard
│   └── app.py                 Real-time stats and recent-decisions table
│
├── baseline/              ModSecurity (OWASP CRS) comparison
│   ├── run_comparison.py      Run the same traffic through a signature WAF
│   ├── run_comparison5.py     5-seed ModSecurity vs APISentry comparison (pooled, Wilson CIs)
│   ├── plot_results.py        Comparison chart
│   └── docker-compose.yml     ModSecurity container
│
├── validation/            Jupyter notebooks
│   ├── APISentry_Model_Validation.ipynb        Own dataset / own model
│   └── APISentry_Benchmark_Validation.ipynb    Public CSIC 2010 / ECML-PKDD
│
├── setup.sh   run.sh   stop.sh   reset.sh   demo.sh    Helper scripts
├── DEMO_GUIDE.md          Exact commands to trigger all 7 attacks
├── CITATION.cff           How to cite this work
└── LICENSE
```

---

## 1. Requirements

You need a **Linux machine** (developed and tested on **Kali Linux**). Install the tools below:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git docker.io docker-compose sqlmap
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

This creates the Python virtual environments and installs all libraries:

```bash
./setup.sh
```

Wait until it prints **`Setup complete`**.

---

## 4. Start the tool

```bash
./run.sh
```

This starts four services automatically:

| Service | Port | What it is |
|---------|------|------------|
| Database | — | PostgreSQL (in Docker) |
| Backend API | `8000` | The target REST API |
| AI security gateway | `9000` | APISentry — the main tool |
| Dashboard | `8080` | Live security dashboard |

When it prints **`APISentry AI is RUNNING`**, everything is up.

---

## 5. Open the dashboard

In your browser, open:

```
http://localhost:8080
```

You will see live stats: total requests, allowed, blocked, current threat level, attack types, and a table of recent decisions.

---

## 6. See attacks being blocked

Clear the dashboard to zero (recommended before a demo):

```bash
./reset.sh
```

Then send live normal **+** attack traffic:

```bash
./demo.sh        # press Ctrl+C to stop
```

Or run real attacks yourself and watch them get blocked in real time. See **`DEMO_GUIDE.md`** for the exact commands for all seven attacks, including `sqlmap` for SQL injection.

---

## 7. Stop everything

```bash
./stop.sh
```

---

## Results

Measured on the project's own labelled dataset (**11,415 requests across eight classes**):
- **~97% macro-F1** under 5-fold cross-validation, with stable results across folds.
- **Realistic, explainable performance** — not an artificial 100%; the residual errors (mostly BOLA vs. normal browsing) are interpretable.
- The **anomaly detector catches attacks it was never trained on** (zero-day setting).
- The gateway adds only **~9 ms per request**, keeping it usable in real time.
- The payload component **transfers to the public CSIC 2010 benchmark** at an F1 of about **0.98**.

All figures are generated by scripts in `ml-pipeline/` and saved to `ml-pipeline/results/`.

---

## Reproducing the research

The full experimental pipeline can be re-run end to end:

```bash
# 1. generate the labelled dataset (needs the API running)
traffic-generator/venv/bin/python traffic-generator/run_all.py

# 2. preprocess with causal, leakage-free features
ml-pipeline/venv/bin/python ml-pipeline/preprocess.py

# 3. train and evaluate
ml-pipeline/venv/bin/python ml-pipeline/train.py
ml-pipeline/venv/bin/python ml-pipeline/train_anomaly.py
ml-pipeline/venv/bin/python ml-pipeline/cross_validate.py
ml-pipeline/venv/bin/python ml-pipeline/ablation.py
ml-pipeline/venv/bin/python ml-pipeline/latency_test.py
ml-pipeline/venv/bin/python ml-pipeline/shap_explain.py

# 4. extended reviewer-response experiments
ml-pipeline/venv/bin/python ml-pipeline/disjoint_split.py         # source-address-disjoint split
ml-pipeline/venv/bin/python ml-pipeline/rule_threshold_sweep.py   # payload-signature threshold
ml-pipeline/venv/bin/python ml-pipeline/cred_feature_ablation.py  # distinct-account feature
ml-pipeline/venv/bin/python ml-pipeline/detection_latency.py      # event-level detection latency
ml-pipeline/venv/bin/python ml-pipeline/knn_benchmark.py          # KNN inference-cost baseline
ml-pipeline/venv/bin/python ml-pipeline/session_level_test.py     # session-level significance
traffic-generator/venv/bin/python traffic-generator/regime_test3.py   # network-regime robustness (gateway running)

# 5. (optional) ModSecurity comparison
baseline/venv/bin/python baseline/run_comparison.py     # single run
baseline/venv/bin/python baseline/run_comparison5.py    # 5 seeded runs, pooled with Wilson CIs
```

The two notebooks in `validation/` reproduce the primary evaluation on the own dataset and the external validation on public benchmarks (CSIC 2010 and ECML/PKDD 2007).

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| **Dashboard does not open** | Run `pgrep -f uvicorn` — you should see three process IDs. If not, check `cat /tmp/apisentry_gateway.log`. |
| **`docker: permission denied`** | Log out and back in (so your user joins the `docker` group), or run with `sudo`. |
| **Port already in use** | Run `./stop.sh` first, then `./run.sh` again. |
| **Backend not seeded / empty data** | Re-run `./run.sh`; it re-seeds the database on start. |

Logs are written to `/tmp/apisentry_backend.log`, `/tmp/apisentry_gateway.log`, and `/tmp/apisentry_dashboard.log`.

---

## Citation & license

If you use this software or dataset, please cite it using the metadata in **`CITATION.cff`**.

The dataset, code and trained models are archived at **https://doi.org/10.5281/zenodo.22671029** (dataset under CC BY 4.0). Source code is released under the terms in **`LICENSE`**.

## Authors

**Showrav Ghosh** — Author, developer, and researcher.
Department of Computer Science, American International University-Bangladesh (AIUB), Dhaka, Bangladesh.
Email: 23-50666-1@student.aiub.edu · ORCID: https://orcid.org/0009-0008-6639-9698

**Md. Manirul Islam** — Supervisor and corresponding author.
Associate Professor; Director, IT (Network Operations); and Director, Institute of Continuing Education, American International University-Bangladesh (AIUB), Dhaka, Bangladesh. A cybersecurity expert and IT strategist with over 23 years of experience in network architecture, digital security, and advanced computing.
Email: manirul@aiub.edu · Profile: https://www.aiub.edu/faculty-list/faculty-profile?q=manirul

American International University-Bangladesh (AIUB), 408/1, Kuratoli, Khilkhet, Dhaka 1229, Bangladesh.
