# Steward remediation matrix

| Requested correction | Implementation | Verification |
| --- | --- | --- |
| Do not silently truncate policy, document, or release bodies | `_fetch` rejects responses over 14,000 bytes and invalid UTF-8 before any digest or review is accepted. | Contract lint passes; focused direct tests are included in `tests/direct/`. |
| Revalidate frozen inputs before a public flag changes state | `raise_public_flag` refetches both the frozen policy and reviewed release and compares each digest before changing the accession state. | The deployed source is byte-for-byte identical to `contracts/contract.py`; SHA-256 is recorded in `deployment.json`. |
| Provide a finalized network record | Record `REMEDIATION-1790253471` reached `SEALED` with successful leader execution. | Exact transaction, policy digest, and Explorer address are in `network-run.json`. |

The current local direct-test runner cannot load this contract's legacy StudioNet SDK header, so the focused direct tests are supplied but are not represented as executed evidence. The deployment source match, lint, and live sealed record are independently recorded.
