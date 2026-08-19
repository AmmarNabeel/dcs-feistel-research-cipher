#!/usr/bin/env sh
set -eu
python -m pip install -e '.[dev]'
python examples.py
python -m pytest
echo "Quick verification completed successfully."
