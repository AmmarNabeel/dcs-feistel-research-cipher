$ErrorActionPreference = "Stop"
python -m pip install -e ".[dev]"
python examples.py
python -m pytest
Write-Host "Quick verification completed successfully."
