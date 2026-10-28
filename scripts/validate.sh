#!/usr/bin/env bash
set -euo pipefail
python -m unittest discover -s tests -v
python -m sentinel tests/data/auth.log --year 2026 --failures 4 --usernames 3 --sources 4 --format json | python -m json.tool >/dev/null
python -m sentinel tests/data/auth.log --year 2026 --format html | grep -q "<!DOCTYPE html>"
echo "Validation checks passed."
