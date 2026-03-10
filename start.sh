#!/bin/bash
cd "$(dirname "$0")"

# Check .env
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
  echo "Please edit .env and set TERMINAL_PASSWORD"
  exit 1
fi

# Check venv
if [ ! -d venv ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv --with-pip
  venv/bin/pip install aiohttp asyncssh
fi

echo "Starting Web Terminal..."
exec venv/bin/python server.py
