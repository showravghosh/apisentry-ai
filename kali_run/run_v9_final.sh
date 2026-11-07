#!/bin/bash
set -u
P=$(cd "$(dirname "$0")/.." && pwd)
GP=${GP:-$HOME/apisentry-ai/gateway/venv/bin/python}
TP=${TP:-$HOME/apisentry-ai/traffic-generator/venv/bin/python}
MODSEC_ID=${MODSEC_ID:-a0c18bd57e5b}
STEP=${1:-all}
K=$P/kali
mkdir -p $K/results $K/logs $K/pids
cd $P

up() {
  local port=$1
  for i in $(seq 1 90); do curl -s -o /dev/null http://127.0.0.1:$port/ && return 0; sleep 1; done
  echo "service on port $port did not start"; return 1
}

startgw() {
  local name=$1 port=$2 dir=$3; shift 3
  env "$@" APISENTRY_TEST_HOOKS=1 APISENTRY_DECISION_LOG=$K/logs/dec_$name.csv nohup $GP -m uvicorn gateway:app --host 127.0.0.1 --port $port --app-dir $dir --log-level warning > $K/logs/$name.log 2>&1 &
  echo $! > $K/pids/$name.pid
  up $port
}

startrl() {
  local name=$1 port=$2 backend=$3
  RL_BACKEND=$backend nohup $GP -m uvicorn ratelimit_proxy:app --host 127.0.0.1 --port $port --app-dir $P/baseline --log-level warning > $K/logs/$name.log 2>&1 &
  echo $! > $K/pids/$name.pid
  up $port
}

startrelay() {
  RELAY_SEED=10401 nohup $GP -m uvicorn tool_relay_ua:app --host 127.0.0.1 --port 9900 --app-dir $P/experiments/tools --log-level warning > $K/logs/relay.log 2>&1 &
  echo $! > $K/pids/relay.pid
  up 9900
}

stopall() {
  for f in $K/pids/*.pid; do [ -f "$f" ] && kill $(cat "$f") 2>/dev/null; rm -f "$f"; done
  sleep 2
}

check() {
  echo "== checksums"
  sha256sum -c kali_run/FROZEN_SHA256_V9.txt || { echo "CHECKSUM MISMATCH - stop"; exit 1; }
  echo "== prerequisites (test API on 8000, ModSecurity CRS on 8081 must be started by you first)"
  for p in 8000 8081; do curl -s -o /dev/null -w "port $p -> %{http_code}\n" http://127.0.0.1:$p/ || echo "port $p unreachable"; done
  for t in sqlmap hydra ffuf ab docker; do command -v $t > /dev/null && echo "$t ok" || { echo "$t MISSING (sudo apt install sqlmap hydra ffuf apache2-utils)"; exit 1; }; done
}

main_api() {
  stopall
  # Submitted gateway AS DEPLOYED on 9000: no test hooks, so the reset calls the coverage
  # harness makes between attack types are no-ops and state carries over (reproduces 994/1000).
  APISENTRY_BACKEND=http://127.0.0.1:8000 APISENTRY_DECISION_LOG=$K/logs/dec_subm.csv nohup $GP -m uvicorn gateway:app --host 127.0.0.1 --port 9000 --app-dir $P/original_with_reset_hook --log-level warning > $K/logs/subm.log 2>&1 &
  echo $! > $K/pids/subm.pid; up 9000 || exit 1
  startgw v9 9010 $P/gateway APISENTRY_POLICY=v9 APISENTRY_BACKEND=http://127.0.0.1:8000 || exit 1
  startgw v8 9007 $P/previous_v8/gateway APISENTRY_POLICY=v8 APISENTRY_BACKEND=http://127.0.0.1:8000 || exit 1
  startgw subm_reset 9006 $P/original_with_reset_hook APISENTRY_BACKEND=http://127.0.0.1:8000 || exit 1
  startrl ratelimit 9008 http://127.0.0.1:8000 || exit 1
  cd $K
  ALL='{"ModSecurity_CRS": "http://127.0.0.1:8081", "RateLimit_baseline": "http://127.0.0.1:9008", "APISentry_original": "http://127.0.0.1:9000", "APISentry_original_fresh": "http://127.0.0.1:9006", "APISentry_v8": "http://127.0.0.1:9007", "APISentry_v9": "http://127.0.0.1:9010"}'
  echo "== coverage, original suite"
  COVERAGE_SEEDS=10001,10002,10003,10004,10005 COVERAGE_TARGETS="$ALL" $TP $P/experiments/live/live_coverage.py final10 2>&1 | tee $K/logs/cov_original.txt
  echo "== coverage, extended suite"
  COVERAGE_SEEDS=10001,10002,10003,10004,10005 COVERAGE_TARGETS="$ALL" $TP $P/experiments/live/live_coverage.py final10 extended 2>&1 | tee $K/logs/cov_extended.txt
  echo "== network regimes"
  for s in "v9 9010" "v8 9007" "original_fresh 9006"; do set -- $s
    REGIME_SEEDS=10101,10102,10103,10104,10105 APISENTRY_GW=http://127.0.0.1:$2 $TP $P/experiments/live/live_regimes.py ${1}_final10 2>&1 | tee -a $K/logs/regimes.txt
  done
  for s in "ratelimit 9008" "modsecurity 8081"; do set -- $s
    REGIME_SEEDS=10101,10102,10103,10104,10105 APISENTRY_GW=http://127.0.0.1:$2 $TP $P/experiments/live/live_regimes_baseline.py ${1}_final10 2>&1 | tee -a $K/logs/regimes.txt
  done
  echo "== evasion suite"
  ADV_SEED=10201 ADV_PACE='{"flood_medium": 0.45, "flood_slow": 1.4, "brute_slow": 5.5, "bola_slow": 2.8, "replay_slow": 3.8}' \
  ADV_TARGETS='{"ModSecurity_CRS": "http://127.0.0.1:8081", "RateLimit_baseline": "http://127.0.0.1:9008", "APISentry_original_fresh": "http://127.0.0.1:9006", "APISentry_v8": "http://127.0.0.1:9007", "APISentry_v9": "http://127.0.0.1:9010"}' \
  $TP $P/experiments/live/adv_suite.py final10 2>&1 | tee $K/logs/adv.txt
  echo "== third-party tools (browser User-Agent), original API"
  startrelay || exit 1
  TOOLS_API=testapi TOOLS_BACKEND=http://127.0.0.1:8000 \
  TOOLS_TARGETS='{"ModSecurity_CRS": "http://127.0.0.1:8081", "RateLimit_baseline": "http://127.0.0.1:9008", "APISentry_original_fresh": "http://127.0.0.1:9006", "APISentry_v8": "http://127.0.0.1:9007", "APISentry_v9": "http://127.0.0.1:9010"}' \
  $TP $P/experiments/tools/tools_suite_ua.py final10_testapi 2>&1 | tee $K/logs/tools_testapi.txt
  cd $P
  stopall
}

vampi() {
  stopall
  docker rm -f vampi modsec_vampi > /dev/null 2>&1
  docker run -d --name vampi -p 5000:5000 -e vulnerable=1 -e tokentimetolive=7200 erev0s/vampi:latest > /dev/null || exit 1
  up 5000 || exit 1
  curl -s http://127.0.0.1:5000/createdb; echo
  MODSEC_VAMPI=""
  # A second ModSecurity in front of VAmPI is OPTIONAL. Enable it only if MODSEC_VAMPI_IMG is set
  # to a CRS image that proxies BACKEND; otherwise the VAmPI comparison runs without ModSecurity.
  if [ -n "${MODSEC_VAMPI_IMG:-}" ]; then
    docker run -d --name modsec_vampi --network host -e PARANOIA=1 -e BACKEND=http://127.0.0.1:5000 -e PORT=8082 $MODSEC_VAMPI_IMG > /dev/null 2>&1 \
      && up 8082 && MODSEC_VAMPI='"ModSecurity_CRS": "http://127.0.0.1:8082", '
  fi
  startgw v9_vampi_profile 9110 $P/gateway APISENTRY_POLICY=v9 APISENTRY_BACKEND=http://127.0.0.1:5000 APISENTRY_PROFILE=$P/gateway/artifacts/profile_vampi.json || exit 1
  startgw v9_vampi_default 9111 $P/gateway APISENTRY_POLICY=v9 APISENTRY_BACKEND=http://127.0.0.1:5000 || exit 1
  startgw subm_reset_vampi 9116 $P/original_with_reset_hook APISENTRY_BACKEND=http://127.0.0.1:5000 || exit 1
  startrl ratelimit_vampi 9118 http://127.0.0.1:5000 || exit 1
  startrelay || exit 1
  cd $K
  VT='{'"$MODSEC_VAMPI"'"RateLimit_baseline": "http://127.0.0.1:9118", "APISentry_original_fresh": "http://127.0.0.1:9116", "APISentry_v9_default_profile": "http://127.0.0.1:9111", "APISentry_v9_vampi_profile": "http://127.0.0.1:9110"}'
  echo "== VAmPI legitimate users"
  VAMPI_SEEDS=10301,10302,10303 VAMPI_TARGETS="$VT" $TP $P/experiments/tools/vampi_benign.py final10 2>&1 | tee $K/logs/vampi_benign.txt
  echo "== third-party tools (browser User-Agent), VAmPI"
  TOOLS_API=vampi TOOLS_BACKEND=http://127.0.0.1:5000 TOOLS_TITLES=$K/results/vampi_titles_final10.txt TOOLS_TARGETS="$VT" \
  $TP $P/experiments/tools/tools_suite_ua.py final10_vampi 2>&1 | tee $K/logs/tools_vampi.txt
  cd $P
  stopall
  docker rm -f vampi modsec_vampi > /dev/null 2>&1
}

case $STEP in
  check) check ;;
  main) check; main_api ;;
  vampi) check; vampi ;;
  all) check; main_api; vampi ;;
esac
echo "== finished $STEP"
