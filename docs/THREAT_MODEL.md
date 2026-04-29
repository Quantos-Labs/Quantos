# Threat Model

## Assets to Protect

- Consensus safety and liveness.
- Account keys and transaction authorization.
- Asset/resource ownership invariants.
- Runtime determinism and replay resistance.
- Validator and network state integrity.

## Main Risk Areas

- Consensus divergence or finality failure.
- Invalid state transitions accepted by execution.
- Signature verification bypass or misuse.
- Resource duplication, unauthorized movement, or loss.
- DoS vectors in networking, mempool, execution, or validation.
- Unsafe upgrade or migration paths.

## Review Expectations

CertiK should review protocol-level assumptions, implementation correctness, cryptographic integration, transaction lifecycle, and resource-model invariants.
