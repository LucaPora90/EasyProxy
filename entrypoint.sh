#!/bin/bash
export PYTHONPATH=/app

# Start FlareSolverr in the background
echo "🚀 Starting FlareSolverr (v3 Python)..."
cd /app/flaresolverr && PORT=8191 python3 src/flaresolverr.py &

# Start Byparr in the background
echo "🛡️ Starting Byparr..."
cd /app/byparr_src && PORT=8192 python3 main.py &

# Start EasyProxy (Gunicorn)
echo "🎬 Starting EasyProxy..."
cd /app
WORKERS_COUNT=${WORKERS:-$(nproc 2>/dev/null || echo 1)}
xvfb-run -a --server-args='-screen 0 1366x768x24' gunicorn --bind 0.0.0.0:${PORT:-7860} --workers $WORKERS_COUNT --worker-class aiohttp.worker.GunicornWebWorker --timeout 120 --graceful-timeout 120 app:app
