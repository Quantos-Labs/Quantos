//// Quantos L0 Verifier for Cardano (Aiken)
//// On-chain validation of PQC finality proofs produced by Quantos.
////
//// Aiken compiles to UPLC (Untyped Plutus Core) for execution on Cardano.
//// We keep validator logic pure and rely on Datum/Redeemer patterns.

use aiken/collection/dict
use aiken/collection/list

// ================================================================
// Types
// ================================================================

/// A 32-byte hash represented as a List<Byte> of length 32.
/// In Aiken, ByteArray is available; we use it directly.
pub type Hash32 = ByteArray

pub type ValidatorSet {
  root: Hash32,
  total_stake: Int,
  threshold: Int,
  active: Bool,
  registered_at: Int,
}

pub type ProofState {
  verified: Bool,
  validator_set_root: Hash32,
  epoch: Int,
  slot: Int,
  accepted_at: Int,
}

pub type DepositState {
  relayed: Bool,
  quantos_deposit_id: Hash32,
  amount: Int,
}

/// Action (redeemer) that describes what the user wants to do.
pub type Action {
  RegisterValidatorSet { root: Hash32, total_stake: Int, threshold: Int }
  RevokeValidatorSet { root: Hash32 }
  VerifyProof { proof_hash: Hash32, validator_set_root: Hash32, epoch: Int, slot: Int, signed_stake: Int }
  AuthorizeRelay { proof_hash: Hash32, quantos_deposit_id: Hash32, amount: Int }
  ForceMarkRelayed { quantos_deposit_id: Hash32, amount: Int }
}

// ================================================================
// Datum: the global registry state stored at a UTxO
// ================================================================

pub type Registry {
  admin: Hash32,         // pub key hash of the admin
  challenge_window: Int, // in slots
  validator_sets: List<(Hash32, ValidatorSet)>,
  proofs: List<(Hash32, ProofState)>,
  deposits: List<(Hash32, DepositState)>,
}

// ================================================================
// Helpers
// ================================================================

fn is_admin(ctx: ScriptContext, registry: Registry) -> Bool {
  let Transaction { extra_signatories, .. } = ctx.transaction
  list.any(extra_signatories, fn(sig) { sig == registry.admin })
}

fn find_set(sets: List<(Hash32, ValidatorSet)>, root: Hash32) -> Option<ValidatorSet> {
  list.find_map(sets, fn(pair) {
    let (r, set) = pair
    if r == root { Some(set) } else { None }
  })
}

fn has_proof(proofs: List<(Hash32, ProofState)>, proof_hash: Hash32) -> Bool {
  list.any(proofs, fn(pair) { let (h, _) = pair; h == proof_hash })
}

fn has_deposit(deposits: List<(Hash32, DepositState)>, deposit_id: Hash32) -> Bool {
  list.any(deposits, fn(pair) { let (h, _) = pair; h == deposit_id })
}

fn replace_set(sets: List<(Hash32, ValidatorSet)>, root: Hash32, new_set: ValidatorSet) -> List<(Hash32, ValidatorSet)> {
  list.map(sets, fn(pair) {
    let (r, set) = pair
    if r == root { (root, new_set) } else { pair }
  })
}

fn insert_or_replace_proof(proofs: List<(Hash32, ProofState)>, proof_hash: Hash32, state: ProofState) -> List<(Hash32, ProofState)> {
  if has_proof(proofs, proof_hash) {
    list.map(proofs, fn(pair) {
      let (h, s) = pair
      if h == proof_hash { (proof_hash, state) } else { pair }
    })
  } else {
    list.push(proofs, (proof_hash, state))
  }
}

fn insert_or_replace_deposit(deposits: List<(Hash32, DepositState)>, deposit_id: Hash32, deposit: DepositState) -> List<(Hash32, DepositState)> {
  if has_deposit(deposits, deposit_id) {
    list.map(deposits, fn(pair) {
      let (h, d) = pair
      if h == deposit_id { (deposit_id, deposit) } else { pair }
    })
  } else {
    list.push(deposits, (deposit_id, deposit))
  }
}

// ================================================================
// Main validator
// ================================================================

validator quantos_l0_verifier {
  fn(registry: Registry, action: Action, ctx: ScriptContext) -> Bool {
    when action is {
      // Admin: register a validator set
      RegisterValidatorSet { root, total_stake, threshold } -> {
        expect is_admin(ctx, registry)
        expect !list.any(registry.validator_sets, fn(pair) { let (r, _) = pair; r == root })
        let new_set = ValidatorSet { root, total_stake, threshold, active: True, registered_at: ctx.transaction.validity_range.lower_bound }
        let new_sets = list.push(registry.validator_sets, (root, new_set))
        let new_registry = Registry { ..registry, validator_sets: new_sets }
        // Enforce that the continuing output datum matches new_registry
        let outputs = ctx.transaction.outputs
        expect list.any(outputs, fn(output) {
          when output.datum is {
            InlineDatum(d) -> {
              expect d as Registry == new_registry
              True
            }
            _ -> False
          }
        })
        True
      }

      // Admin: revoke a validator set
      RevokeValidatorSet { root } -> {
        expect is_admin(ctx, registry)
        let maybe_set = find_set(registry.validator_sets, root)
        expect Some(set) = maybe_set
        let new_set = ValidatorSet { ..set, active: False }
        let new_sets = replace_set(registry.validator_sets, root, new_set)
        let new_registry = Registry { ..registry, validator_sets: new_sets }
        let outputs = ctx.transaction.outputs
        expect list.any(outputs, fn(output) {
          when output.datum is {
            InlineDatum(d) -> {
              expect d as Registry == new_registry
              True
            }
            _ -> False
          }
        })
        True
      }

      // Anyone: verify a proof
      VerifyProof { proof_hash, validator_set_root, epoch, slot, signed_stake } -> {
        let maybe_set = find_set(registry.validator_sets, validator_set_root)
        expect Some(set) = maybe_set
        expect set.active
        expect !has_proof(registry.proofs, proof_hash)
        expect signed_stake >= set.threshold
        let state = ProofState {
          verified: True,
          validator_set_root,
          epoch,
          slot,
          accepted_at: ctx.transaction.validity_range.lower_bound,
        }
        let new_proofs = insert_or_replace_proof(registry.proofs, proof_hash, state)
        let new_registry = Registry { ..registry, proofs: new_proofs }
        let outputs = ctx.transaction.outputs
        expect list.any(outputs, fn(output) {
          when output.datum is {
            InlineDatum(d) -> {
              expect d as Registry == new_registry
              True
            }
            _ -> False
          }
        })
        True
      }

      // Anyone: authorize relay from a verified proof
      AuthorizeRelay { proof_hash, quantos_deposit_id, amount } -> {
        let maybe_state = find_set(registry.proofs, proof_hash)
        expect Some(state) = maybe_state
        expect state.verified
        expect !has_deposit(registry.deposits, quantos_deposit_id)
        let current_slot = ctx.transaction.validity_range.lower_bound
        expect current_slot >= state.accepted_at + registry.challenge_window
        let deposit = DepositState { relayed: True, quantos_deposit_id, amount }
        let new_deposits = insert_or_replace_deposit(registry.deposits, quantos_deposit_id, deposit)
        let new_registry = Registry { ..registry, deposits: new_deposits }
        let outputs = ctx.transaction.outputs
        expect list.any(outputs, fn(output) {
          when output.datum is {
            InlineDatum(d) -> {
              expect d as Registry == new_registry
              True
            }
            _ -> False
          }
        })
        True
      }

      // Admin: emergency override
      ForceMarkRelayed { quantos_deposit_id, amount } -> {
        expect is_admin(ctx, registry)
        let deposit = DepositState { relayed: True, quantos_deposit_id, amount }
        let new_deposits = insert_or_replace_deposit(registry.deposits, quantos_deposit_id, deposit)
        let new_registry = Registry { ..registry, deposits: new_deposits }
        let outputs = ctx.transaction.outputs
        expect list.any(outputs, fn(output) {
          when output.datum is {
            InlineDatum(d) -> {
              expect d as Registry == new_registry
              True
            }
            _ -> False
          }
        })
        True
      }
    }
  }
}
