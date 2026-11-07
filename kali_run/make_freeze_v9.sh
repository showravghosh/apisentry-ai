#!/bin/bash
cd "$(dirname "$0")/.."
sha256sum gateway/gateway.py gateway/artifacts/model.cbm gateway/artifacts/policy_v9.json gateway/artifacts/profile_vampi.json gateway/artifacts/scaler.pkl gateway/artifacts/encoders.json gateway/artifacts/feature_columns.json \
 previous_v8/gateway/gateway.py previous_v8/gateway/artifacts/policy_v8.json original_with_reset_hook/gateway.py baseline/ratelimit_proxy.py \
 experiments/live/live_coverage.py experiments/live/live_regimes.py experiments/live/live_regimes_baseline.py experiments/live/adv_suite.py \
 experiments/tools/tool_relay_ua.py experiments/tools/tools_suite_ua.py experiments/tools/cred_sender.py experiments/tools/vampi_benign.py kali_run/run_v9_final.sh > kali_run/FROZEN_SHA256_V9.txt
cat kali_run/FROZEN_SHA256_V9.txt
