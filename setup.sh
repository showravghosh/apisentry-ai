#!/bin/bash
cd "$(dirname "$0")"
echo "Installing APISentry AI ..."
python3 -m venv test-api/venv
test-api/venv/bin/pip install --quiet fastapi "uvicorn[standard]" sqlalchemy psycopg2-binary "passlib[bcrypt]" "bcrypt==4.0.1" python-multipart "pydantic[email]" "python-jose[cryptography]"
python3 -m venv gateway/venv
gateway/venv/bin/pip install --quiet fastapi "uvicorn[standard]" httpx catboost scikit-learn joblib numpy
python3 -m venv traffic-generator/venv
traffic-generator/venv/bin/pip install --quiet requests faker
echo "Setup complete. Now run: ./run.sh"
