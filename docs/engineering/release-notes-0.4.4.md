# MCPSense 0.4.4

This release addresses the missed hostile descriptions and benign false alarms reproduced in the public 0.4.3 audit. Metadata checks now share context and value provenance rather than interpreting the same text independently.

- Distinguish active instructions from prohibitions, observed predicates, quoted data operands and fixed placeholders, preserving original evidence positions through Unicode normalization.
- Follow private values through named intermediates, encoding, transformation and reassignment. A public value named `password` is not automatically private; an actual secret named `redacted_api_key` is not automatically public. Metadata-defined names cannot shadow host-owned credentials.
- Share exfiltration analysis across supported advertised metadata fields and inspect changes to approval, identity validation, monitoring and audit/reporting integrity.
- Return an explicit incomplete-analysis/manual-review error (exit 2) when the 256-binding analysis capacity is exceeded, including with SEC-001 or SEC-011 selected alone.
- Require nine unchanged corpora in native/npm acceptance: 718 authored observations per route, with 353 hostile detections, zero misses, zero benign security false alarms and 365 benign quiet observations on the tested candidate. Also retain live metadata, required-reference and real user workflows.

The original failed public audit and failed intermediate evaluations remain in the [verification record](https://github.com/fayzkk889/MCPSense/blob/main/docs/engineering/metadata-trust-verification-2026-11-01.md). Repeated authored examples establish regression behavior, not field accuracy or future zero-miss protection. MCPSense remains bounded metadata/source inspection, not runtime authorization or proof that a server is safe.

Install or update through either independent route:

```sh
npm install -g mcpsense@latest
# Or, for Go users:
go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest
mcpsense version --check
```

npm requires Node.js 22+ and no Go compiler, archive utility, MCPSense native executable or install hook. Go remains independent of Node/npm. MIT is unchanged. Optional native Windows archives remain unsigned and may be restricted by device policy; no Windows protections are disabled.
