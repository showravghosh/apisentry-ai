#!/bin/bash
cd $(dirname "$0")
L=.
G=../../gateway
nohup python3 -m uvicorn stub_backend:app --host 127.0.0.1 --port 8000 --app-dir $L/stub --log-level warning > /tmp/stub.log 2>&1 & echo $! > /tmp/stub.pid
sleep 3
python3 $L/load_test.py stub_direct http://127.0.0.1:8000 $(cat /tmp/stub.pid)
APISENTRY_POLICY=v7 APISENTRY_DECISION_LOG=/tmp/dl_v7.csv nohup python3 -m uvicorn gateway:app --host 127.0.0.1 --port 9000 --app-dir $G --log-level warning > /tmp/gwl.log 2>&1 & echo $! > /tmp/gwl.pid
until curl -s -o /dev/null http://127.0.0.1:9000/__apisentry/state; do sleep 1; done
python3 $L/load_test.py gateway_v7 http://127.0.0.1:9000 $(cat /tmp/gwl.pid)
curl -s http://127.0.0.1:9000/__apisentry/state > results/state_after_load.json
kill $(cat /tmp/gwl.pid); sleep 2
APISENTRY_POLICY=v7 APISENTRY_DECISION_LOG=/tmp/dl_v7b.csv nohup python3 -m uvicorn gateway:app --host 127.0.0.1 --port 9000 --app-dir $G --log-level warning > /tmp/gwl.log 2>&1 & echo $! > /tmp/gwl.pid
until curl -s -o /dev/null http://127.0.0.1:9000/__apisentry/state; do sleep 1; done
LOAD_LEVELS=64,64,64 LOAD_DURATION=20 python3 $L/load_test.py gateway_v7_identity_churn http://127.0.0.1:9000 $(cat /tmp/gwl.pid) churn
curl -s http://127.0.0.1:9000/__apisentry/state > results/state_after_churn.json
kill $(cat /tmp/gwl.pid) $(cat /tmp/stub.pid)
echo finished
