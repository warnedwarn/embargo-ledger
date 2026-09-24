# EMBARGO LEDGER / ACCESSION DOCKET

**Archive rule:** a promise to disclose later is measurable only when the original bytes, the clock, and the redaction policy are fixed before publication.

The filer stores a SHA-256 commitment and nominates a custodian and reviewer. The custodian may reveal only inside the embargo window. Validators fetch the revealed bytes and refuse any document that does not match the original commitment. The reviewer then publishes a separate redacted release from a third origin.

Validators compare the full document, public release, and frozen policy rule by rule. A compliant review opens a public scrutiny window. Fresh-origin evidence can still flag a material redaction breach; otherwise anyone may close the accession as `RELEASED`. A missed reveal becomes `MISSED_REVEAL` without relying on the filer.

Every retrieved body must be valid UTF-8 and at most 14,000 bytes. Larger policy, document, release, or flag bodies fail closed instead of being truncated. A public flag also refetches and digest-checks the frozen policy and exact reviewed release before it can change the accession state.

```text
SEALED -> REVEALED -> REVIEWED -> RELEASED
                    |          -> FLAGGED
                    -> BREACHED
SEALED ------------------------> MISSED_REVEAL
```

## Clerk checks

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```

Files under `evidence/` are technical fixtures. They prove the workflow, not independent authority.
