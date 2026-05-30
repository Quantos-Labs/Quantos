import {
  L0FinalityProof,
  ValidatorSetSnapshot,
  VerificationReport,
  PqcSignatureAlgo,
  L0_PROOF_VERSION,
} from "./types";

export function verifyProof(
  proof: L0FinalityProof,
  snapshot: ValidatorSetSnapshot
): VerificationReport {
  if (proof.header.version !== L0_PROOF_VERSION) {
    throw new Error(`Unsupported proof version: ${proof.header.version}`);
  }
  if (proof.header.validator_set_root !== snapshot.root) {
    throw new Error(
      `Validator set root mismatch: expected ${proof.header.validator_set_root}, got ${snapshot.root}`
    );
  }
  if (proof.validators.length !== snapshot.validators.length) {
    throw new Error("Validator set length mismatch");
  }

  const totalStake = snapshot.validators.reduce(
    (acc, v) => acc + BigInt(v.stake),
    0n
  );
  if (BigInt(proof.header.total_stake) !== totalStake) {
    throw new Error("Total stake mismatch with snapshot");
  }

  let signedStake = 0n;
  let validSignatures = 0;
  let invalidSignatures = 0;

  for (const sig of proof.signatures) {
    const validator = proof.validators[sig.validator_index];
    if (!validator) {
      invalidSignatures++;
      continue;
    }

    const ok = validateSignatureStructure(sig, validator);
    if (ok) {
      validSignatures++;
      signedStake += BigInt(validator.stake);
    } else {
      invalidSignatures++;
    }
  }

  const isFinal =
    invalidSignatures === 0 &&
    signedStake >= BigInt(proof.header.stake_threshold);

  return {
    signed_stake: Number(signedStake),
    stake_threshold: proof.header.stake_threshold,
    valid_signatures: validSignatures,
    invalid_signatures: invalidSignatures,
    is_final: isFinal,
  };
}

function validateSignatureStructure(
  sig: { validator_index: number; algo: PqcSignatureAlgo; signature: string },
  validator: { public_key: string; stake: number }
): boolean {
  if (
    sig.algo !== PqcSignatureAlgo.Falcon512 &&
    sig.algo !== PqcSignatureAlgo.Dilithium3
  ) {
    return false;
  }

  if (!sig.signature || sig.signature.length === 0) return false;
  if (!validator.public_key || validator.public_key.length === 0) return false;

  return true;
}
