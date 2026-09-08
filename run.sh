#!/bin/bash
cd "$(dirname "$0")"
echo "=========================================="
echo "  Starting APISentry AI ..."
echo "=========================================="

echo "[1/4] Starting database..."
( cd test-api && docker compose up -d >/dev/null 2>&1 )
sleep 4

echo "[2/4] Seeding + starting backend (port 8000)..."
test-api/venv/bin/python test-api/seed.py >/dev/null 2>&1
nohup test-api/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir test-api > /tmp/apisentry_backend.log 2>&1 &

echo "[3/4] Starting AI gateway (port 9000)..."
nohup gateway/venv/bin/python -m uvicorn gateway:app --host 0.0.0.0 --port 9000 --app-dir gateway > /tmp/apisentry_gateway.log 2>&1 &

echo "[4/4] Starting dashboard (port 8080)..."
nohup gateway/venv/bin/python -m uvicorn app:app --host 0.0.0.0 --port 8080 --app-dir dashboard > /tmp/apisentry_dashboard.log 2>&1 &

sleep 5
echo ""
echo "=========================================="
echo "  APISentry AI is RUNNING"
echo "  Dashboard : http://localhost:8080"
echo "  Gateway   : http://localhost:9000"
echo "  (attack simulation: ./demo.sh  |  stop demo with Ctrl+C)"
echo "  (reset dashboard: ./reset.sh)"
echo "  (stop all: ./stop.sh)"
echo "=========================================="
(command -v xdg-open >/dev/null && xdg-open http://localhost:8080 >/dev/null 2>&1) || \
(command -v firefox >/dev/null && firefox http://localhost:8080 >/dev/null 2>&1 &)
