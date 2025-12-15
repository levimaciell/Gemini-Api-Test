#!/bin/sh

bandit -r "Gemini-Api-Test/vulnerable_files/files" -f json -o results/bandit.json
semgrep scan "Gemini-Api-Test/vulnerable_files/files" --json --json-output=results/semgrep.json

python Gemini-Api-Test/bandit_parser.py -i results/bandit.json -o results/formatted_bandit.json
python Gemini-Api-Test/semgrep_parser.py -i results/semgrep.json -o results/formatted_semgrep.json
python Gemini-Api-Test/unify.py -d /app/results -o results/fused.json