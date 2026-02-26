#!/usr/bin/env bash
# Environment Bootstrap Script for Google Cloud Shell

set -e

echo "========================================="
echo "APISecurityEngine Bootstrap Initializing "
echo "========================================="

echo "[1/3] Setting up Python environment..."
# Install uv using the standalone installer for fast installation
curl -LsSf https://astral.sh/uv/install.sh | sh
# Add both standard cargo bin and new standalone installer local bin to PATH
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

echo "[2/3] Syncing Project Dependencies..."
uv sync

echo "[3/3] Setting up local mock target..."
# Background mock server using python http.server to reply instantly for demo purposes
# A comprehensive setup would 'docker compose up -d' a vulnerable app here
echo '{"status": "ok"}' > mock_response.json
python -m http.server 8080 --bind 127.0.0.1 > /dev/null 2>&1 &
echo $! > mock_server.pid

echo "Local environment is ready! Mock server running on port 8080."
echo "Proceed to the next step in your tutorial."
