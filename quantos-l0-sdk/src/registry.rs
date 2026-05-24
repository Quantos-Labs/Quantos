use crate::error::ValidatorSetSnapshot;
use crate::types::ValidatorRecord;

pub fn register_validator_set(
    validators: Vec<ValidatorRecord>,
) -> ValidatorSetSnapshot {
    let root = ValidatorSetSnapshot::compute_root(&validators);
    ValidatorSetSnapshot { root, validators }
}
