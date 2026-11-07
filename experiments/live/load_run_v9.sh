#!/bin/bash
cd $(dirname "$0")
L=.
G=../../gateway
T=${LOAD_TMP:-/tmp/apisentry_load_v9}
mkdir -p $T results
nohup python3 -m uvicorn stub_backend:app --host 127.0.0.1 --port 8000 --app-dir $L/stub --log-level warning > $T/stub.log 2>&1 & echo $! > $T/stub.pid
sleep 3
python3 $L/load_test.py stub_direct http://127.0.0.1:8000 $(cat $T/stub.pid)
APISENTRY_POLICY=v9 APISENTRY_TEST_HOOKS=1 APISENTRY_DECISION_LOG=$T/dl.csv nohup python3 -m uvicorn gateway:app --host 127.0.0.1 --port 9000 --app-dir $G --log-level warning > $T/gw.log 2>&1 & echo $! > $T/gw.pid
until curl -s -o /dev/null http://127.0.0.1:9000/__apisentry/state; do sleep 1; done
python3 $L/load_test.py gateway_v9 http://127.0.0.1:9000 $(cat $T/gw.pid)
curl -s http://127.0.0.1:9000/__apisentry/state > results/state_after_load.json
kill $(cat $T/gw.pid); sleep 2
APISENTRY_POLICY=v9 APISENTRY_TEST_HOOKS=1 APISENTRY_DECISION_LOG=$T/dl2.csv nohup python3 -m uvicorn gateway:app --host 127.0.0.1 --port 9000 --app-dir $G --log-level warning > $T/gw.log 2>&1 & echo $! > $T/gw.pid
until curl -s -o /dev/null http://127.0.0.1:9000/__apisentry/state; do sleep 1; done
LOAD_LEVELS=64,64,64 LOAD_DURATION=20 python3 $L/load_test.py gateway_v9_identity_churn http://127.0.0.1:9000 $(cat $T/gw.pid) churn
curl -s http://127.0.0.1:9000/__apisentry/state > results/state_after_churn.json
kill $(cat $T/gw.pid) $(cat $T/stub.pid)
python3 $L/state_mem_v9.py $G results/state_mem_v9.json
echo finished
