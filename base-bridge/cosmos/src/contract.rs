use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Quantos L0 Verifier for Cosmos SDK / CosmWasm
/// On-chain validation of PQC finality proofs produced by Quantos.

// ================================================================
// State
// ================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub admin: String,
    pub challenge_window: u64, // seconds
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ValidatorSet {
    pub root: String,      // hex-encoded 32-byte root
    pub total_stake: u128,
    pub threshold: u128,
    pub active: bool,
    pub registered_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ProofState {
    pub verified: bool,
    pub validator_set_root: String,
    pub epoch: u64,
    pub slot: u64,
    pub accepted_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct DepositState {
    pub relayed: bool,
    pub quantos_deposit_id: String,
    pub amount: u64,
}

pub const STATE: Item<State> = Item::new("state");
pub const VALIDATOR_SETS: Map<&str, ValidatorSet> = Map::new("validator_sets");
pub const PROOFS: Map<&str, ProofState> = Map::new("proofs");
pub const DEPOSITS: Map<&str, DepositState> = Map::new("deposits");

// ================================================================
// Messages
// ================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub admin: String,
    pub challenge_window: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    RegisterValidatorSet {
        root: String,
        total_stake: u128,
        threshold: u128,
    },
    RevokeValidatorSet {
        root: String,
    },
    SetChallengeWindow {
        window: u64,
    },
    VerifyProof {
        proof_hash: String,
        validator_set_root: String,
        epoch: u64,
        slot: u64,
        state_root: String,
        signed_stake: u128,
    },
    AuthorizeRelay {
        proof_hash: String,
        quantos_deposit_id: String,
        amount: u64,
    },
    ForceMarkRelayed {
        quantos_deposit_id: String,
        amount: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    IsProofVerified { proof_hash: String },
    IsDepositRelayed { deposit_id: String },
    GetValidatorSet { root: String },
    GetProofState { proof_hash: String },
    GetChallengeWindow {},
}

// ================================================================
// Instantiate
// ================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        admin: msg.admin,
        challenge_window: msg.challenge_window.unwrap_or(300),
    };
    STATE.save(deps.storage, &state)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

// ================================================================
// Execute
// ================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::RegisterValidatorSet { root, total_stake, threshold } => {
            let state = STATE.load(deps.storage)?;
            if info.sender.as_str() != state.admin {
                return Err(StdError::generic_err("not admin"));
            }
            let set = ValidatorSet {
                root: root.clone(),
                total_stake,
                threshold,
                active: true,
                registered_at: env.block.time.seconds(),
            };
            VALIDATOR_SETS.save(deps.storage, &root, &set)?;
            Ok(Response::new()
                .add_attribute("action", "register_validator_set")
                .add_attribute("root", root))
        }
        ExecuteMsg::RevokeValidatorSet { root } => {
            let state = STATE.load(deps.storage)?;
            if info.sender.as_str() != state.admin {
                return Err(StdError::generic_err("not admin"));
            }
            let mut set = VALIDATOR_SETS.load(deps.storage, &root)?;
            set.active = false;
            VALIDATOR_SETS.save(deps.storage, &root, &set)?;
            Ok(Response::new().add_attribute("action", "revoke_validator_set").add_attribute("root", root))
        }
        ExecuteMsg::SetChallengeWindow { window } => {
            let mut state = STATE.load(deps.storage)?;
            if info.sender.as_str() != state.admin {
                return Err(StdError::generic_err("not admin"));
            }
            state.challenge_window = window;
            STATE.save(deps.storage, &state)?;
            Ok(Response::new().add_attribute("action", "set_challenge_window"))
        }
        ExecuteMsg::VerifyProof {
            proof_hash,
            validator_set_root,
            epoch,
            slot,
            state_root: _,
            signed_stake,
        } => {
            let set = VALIDATOR_SETS.load(deps.storage, &validator_set_root)?;
            if !set.active {
                return Err(StdError::generic_err("unknown or inactive set"));
            }
            if PROOFS.may_load(deps.storage, &proof_hash)?.is_some() {
                return Err(StdError::generic_err("proof already verified"));
            }
            if signed_stake < set.threshold {
                return Err(StdError::generic_err("insufficient stake"));
            }
            let pstate = ProofState {
                verified: true,
                validator_set_root,
                epoch,
                slot,
                accepted_at: env.block.time.seconds(),
            };
            PROOFS.save(deps.storage, &proof_hash, &pstate)?;
            Ok(Response::new().add_attribute("action", "verify_proof").add_attribute("proof_hash", proof_hash))
        }
        ExecuteMsg::AuthorizeRelay { proof_hash, quantos_deposit_id, amount } => {
            let pstate = PROOFS.load(deps.storage, &proof_hash)?;
            if !pstate.verified {
                return Err(StdError::generic_err("proof not verified"));
            }
            if DEPOSITS.may_load(deps.storage, &quantos_deposit_id)?.is_some() {
                return Err(StdError::generic_err("deposit already relayed"));
            }
            let state = STATE.load(deps.storage)?;
            if env.block.time.seconds() < pstate.accepted_at + state.challenge_window {
                return Err(StdError::generic_err("challenge window active"));
            }
            let deposit = DepositState {
                relayed: true,
                quantos_deposit_id: quantos_deposit_id.clone(),
                amount,
            };
            DEPOSITS.save(deps.storage, &quantos_deposit_id, &deposit)?;
            Ok(Response::new().add_attribute("action", "authorize_relay").add_attribute("deposit_id", quantos_deposit_id))
        }
        ExecuteMsg::ForceMarkRelayed { quantos_deposit_id, amount } => {
            let state = STATE.load(deps.storage)?;
            if info.sender.as_str() != state.admin {
                return Err(StdError::generic_err("not admin"));
            }
            let deposit = DepositState {
                relayed: true,
                quantos_deposit_id: quantos_deposit_id.clone(),
                amount,
            };
            DEPOSITS.save(deps.storage, &quantos_deposit_id, &deposit)?;
            Ok(Response::new().add_attribute("action", "force_mark_relayed"))
        }
    }
}

// ================================================================
// Query
// ================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsProofVerified { proof_hash } => {
            let verified = match PROOFS.may_load(deps.storage, &proof_hash)? {
                Some(state) => state.verified,
                None => false,
            };
            to_json_binary(&verified)
        }
        QueryMsg::IsDepositRelayed { deposit_id } => {
            let relayed = match DEPOSITS.may_load(deps.storage, &deposit_id)? {
                Some(d) => d.relayed,
                None => false,
            };
            to_json_binary(&relayed)
        }
        QueryMsg::GetValidatorSet { root } => {
            let set = VALIDATOR_SETS.load(deps.storage, &root)?;
            to_json_binary(&set)
        }
        QueryMsg::GetProofState { proof_hash } => {
            let state = PROOFS.load(deps.storage, &proof_hash)?;
            to_json_binary(&state)
        }
        QueryMsg::GetChallengeWindow {} => {
            let state = STATE.load(deps.storage)?;
            to_json_binary(&state.challenge_window)
        }
    }
}
