# Live run on Kali Linux

The run uses the frozen configuration v9 and the seeds 10001–10005 (coverage), 10101–10105 (network regimes), 10201 (evasion), 10301–10303 (VAmPI legitimate users) and 10401 (tool relay). The script verifies the SHA-256 checksums of all frozen files before it starts. Every third-party tool sends one browser User-Agent through the relay, so that all systems judge the requests rather than the tool names.

## 1. Unpack the archive

```
cd ~
unzip -o apisentry_review_archive.zip
cd ~/apisentry_review_archive
mkdir -p kali/logs kali/results
```

The script expects Python environments with the packages of `requirements.txt` at `$HOME/apisentry-ai/gateway/venv` and `$HOME/apisentry-ai/traffic-generator/venv`; other locations can be given with `GP=<python>` and `TP=<python>`.

## 2. Start the two prerequisite services

Start the test API (`test-api/`) on port 8000 and ModSecurity with the OWASP Core Rule Set (paranoia level 1, default anomaly thresholds) on port 8081, proxying to port 8000. The script starts VAmPI itself with Docker (`erev0s/vampi:latest` on port 5000). Check both services:

```
curl -s -o /dev/null -w "8000 -> %{http_code}\n" http://127.0.0.1:8000/
curl -s -o /dev/null -w "8081 -> %{http_code}\n" http://127.0.0.1:8081/
```

## 3. Run all experiments (about 40–70 minutes; the VAmPI image is pulled once)

```
bash kali_run/run_v9_final.sh all 2>&1 | tee kali/logs/run_all.txt
```

Results are written to `kali/results/` and decision logs to `kali/logs/`.

## 4. Troubleshooting

- `CHECKSUM MISMATCH`: a frozen file differs; unpack the archive again.
- `port 8081 unreachable`: start ModSecurity (step 2).
- `MISSING <tool>`: `sudo apt install -y sqlmap hydra ffuf apache2-utils`.
- A tool that does not finish is stopped after 5 minutes and the run continues.
