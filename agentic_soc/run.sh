#!/usr/bin/env bash
# One-command start for Mac/Linux:  ./run.sh
set -e
cd "$(dirname "$0")"
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt
python server.py
