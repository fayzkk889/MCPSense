#!/usr/bin/env bash
# Audit-only: harmless stand-in for Actions expression substitution of inputs.version.
# No downloads, file mutation, or scanner execution.
VERSION="audit"; printf 'synthetic_input_executed_as_shell=true\n'; #"
printf 'version_after_substitution=%s\n' "$VERSION"
# JSONReporter uses indentation; reproduce the Action's compact-JSON expression.
JSON='{ "score": 75, "summary": { "total": 2 }, "findings": [{ "severity": "high" }] }'
SCORE=$(printf '%s' "$JSON" | grep -o '"score":[0-9]*' | head -1 | cut -d: -f2 || true)
HAS_HIGH=$(printf '%s' "$JSON" | grep -c '"severity":"high"' || true)
printf 'action_score=%s actual_score=75 action_high_count=%s actual_high_count=1\n' "${SCORE:-0}" "$HAS_HIGH"
