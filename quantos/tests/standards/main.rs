//! Comprehensive tests for Token Standards (QN4, QN8, QN12)

use quantos::standards::*;
use quantos::types::Address;

// ── Helpers ──────────────────────────────────────────────

fn addr(i: u8) -> Address {
    [i; 32]
}

// ══════════════════════════════════════════════════════════
//  QN4 — Fungible Token
// ══════════════════════════════════════════════════════════

fn create_qn4() -> QN4Token {
    QN4Token::new_full(
        "Quantos Token".to_string(),
        "QNT".to_string(),
        18,
        1_000_000,
        addr(1), // owner
        true,  // mintable
        true,  // burnable
        true,  // pausable
    )
}

#[test]
fn test_qn4_creation() {
    let token = create_qn4();
    assert_eq!(token.name, "Quantos Token");
    assert_eq!(token.symbol, "QNT");
    assert_eq!(token.decimals, 18);
    assert_eq!(token.total_supply, 1_000_000);
    assert_eq!(token.owner, addr(1));
}

#[test]
fn test_qn4_balance_of_owner() {
    let token = create_qn4();
    assert_eq!(QN4::balance_of(&token, &addr(1)), 1_000_000);
}

#[test]
fn test_qn4_balance_of_unknown() {
    let token = create_qn4();
    assert_eq!(QN4::balance_of(&token, &addr(99)), 0);
}

#[test]
fn test_qn4_transfer() {
    let mut token = create_qn4();
    let owner = addr(1);
    let recipient = addr(2);

    let event = QN4::transfer(&mut token, &owner, &recipient, 1000).unwrap();
    assert_eq!(QN4::balance_of(&token, &owner), 999_000);
    assert_eq!(QN4::balance_of(&token, &recipient), 1000);
    match event {
        TokenEvent::Transfer { from, to, value } => {
            assert_eq!(from, owner);
            assert_eq!(to, recipient);
            assert_eq!(value, 1000);
        }
        _ => panic!("Expected Transfer event"),
    }
}

#[test]
fn test_qn4_transfer_insufficient() {
    let mut token = create_qn4();
    let result = QN4::transfer(&mut token, &addr(1), &addr(2), 2_000_000);
    assert!(result.is_err());
}

#[test]
fn test_qn4_transfer_to_zero_address() {
    let mut token = create_qn4();
    let zero = [0u8; 32];
    let result = QN4::transfer(&mut token, &addr(1), &zero, 100);
    assert!(result.is_err());
}

#[test]
fn test_qn4_approve_and_allowance() {
    let mut token = create_qn4();
    let owner = addr(1);
    let spender = addr(2);

    QN4::approve(&mut token, &owner, &spender, 500).unwrap();
    assert_eq!(QN4::allowance(&token, &owner, &spender), 500);
}

#[test]
fn test_qn4_transfer_from() {
    let mut token = create_qn4();
    let owner = addr(1);
    let spender = addr(2);
    let recipient = addr(3);

    QN4::approve(&mut token, &owner, &spender, 500).unwrap();
    QN4::transfer_from(&mut token, &spender, &owner, &recipient, 300).unwrap();

    assert_eq!(QN4::balance_of(&token, &recipient), 300);
    assert_eq!(QN4::allowance(&token, &owner, &spender), 200);
}

#[test]
fn test_qn4_transfer_from_insufficient_allowance() {
    let mut token = create_qn4();
    let owner = addr(1);
    let spender = addr(2);

    QN4::approve(&mut token, &owner, &spender, 100).unwrap();
    let result = QN4::transfer_from(&mut token, &spender, &owner, &addr(3), 200);
    assert!(result.is_err());
}

#[test]
fn test_qn4_mint() {
    let mut token = create_qn4();
    let owner = addr(1);
    let recipient = addr(2);

    QN4Mintable::mint(&mut token, &owner, &recipient, 5000).unwrap();
    assert_eq!(QN4::balance_of(&token, &recipient), 5000);
    assert_eq!(QN4::total_supply(&token), 1_005_000);
}

#[test]
fn test_qn4_mint_non_owner_fails() {
    let mut token = create_qn4();
    let non_owner = addr(99);
    let result = QN4Mintable::mint(&mut token, &non_owner, &addr(2), 100);
    assert!(result.is_err());
}

#[test]
fn test_qn4_burn() {
    let mut token = create_qn4();
    let owner = addr(1);

    QN4Burnable::burn(&mut token, &owner, 1000).unwrap();
    assert_eq!(QN4::balance_of(&token, &owner), 999_000);
    assert_eq!(QN4::total_supply(&token), 999_000);
}

#[test]
fn test_qn4_burn_insufficient() {
    let mut token = create_qn4();
    let result = QN4Burnable::burn(&mut token, &addr(1), 2_000_000);
    assert!(result.is_err());
}

#[test]
fn test_qn4_pause_unpause() {
    let mut token = create_qn4();
    let owner = addr(1);

    assert!(!QN4Pausable::is_paused(&token));
    QN4Pausable::pause(&mut token, &owner).unwrap();
    assert!(QN4Pausable::is_paused(&token));

    // Transfers should fail when paused
    let result = QN4::transfer(&mut token, &owner, &addr(2), 100);
    assert!(result.is_err());

    QN4Pausable::unpause(&mut token, &owner).unwrap();
    assert!(!QN4Pausable::is_paused(&token));

    // Transfers work again
    QN4::transfer(&mut token, &owner, &addr(2), 100).unwrap();
}

#[test]
fn test_qn4_pause_non_owner_fails() {
    let mut token = create_qn4();
    let result = QN4Pausable::pause(&mut token, &addr(99));
    assert!(result.is_err());
}

#[test]
fn test_qn4_name_symbol_decimals() {
    let token = create_qn4();
    assert_eq!(QN4::name(&token), "Quantos Token");
    assert_eq!(QN4::symbol(&token), "QNT");
    assert_eq!(QN4::decimals(&token), 18);
}

// ══════════════════════════════════════════════════════════
//  QN8 — Non-Fungible Token
// ══════════════════════════════════════════════════════════

fn create_qn8() -> QN8Token {
    QN8Token::new(
        "Quantos NFT".to_string(),
        "QNFT".to_string(),
        addr(1), // owner
        "https://nft.quantos.io/".to_string(),
    )
}

#[test]
fn test_qn8_creation() {
    let token = create_qn8();
    assert_eq!(token.name, "Quantos NFT");
    assert_eq!(token.symbol, "QNFT");
}

#[test]
fn test_qn8_mint_and_owner() {
    let mut token = create_qn8();
    let owner = addr(1);
    let recipient = addr(2);

    let (token_id, _event) = QN8Mintable::mint(&mut token, &owner, &recipient, None).unwrap();
    assert_eq!(QN8::owner_of(&token, token_id).unwrap(), recipient);
    assert_eq!(QN8::balance_of(&token, &recipient), 1);
}

#[test]
fn test_qn8_transfer() {
    let mut token = create_qn8();
    let owner = addr(1);
    let holder = addr(2);
    let recipient = addr(3);

    let (token_id, _) = QN8Mintable::mint(&mut token, &owner, &holder, None).unwrap();
    QN8::transfer_from(&mut token, &holder, &holder, &recipient, token_id).unwrap();

    assert_eq!(QN8::owner_of(&token, token_id).unwrap(), recipient);
    assert_eq!(QN8::balance_of(&token, &holder), 0);
    assert_eq!(QN8::balance_of(&token, &recipient), 1);
}

#[test]
fn test_qn8_transfer_not_owner_fails() {
    let mut token = create_qn8();
    let owner = addr(1);

    let (token_id, _) = QN8Mintable::mint(&mut token, &owner, &addr(2), None).unwrap();
    let result = QN8::transfer_from(&mut token, &addr(3), &addr(2), &addr(4), token_id);
    assert!(result.is_err());
}

#[test]
fn test_qn8_approve_and_get() {
    let mut token = create_qn8();
    let owner = addr(1);
    let holder = addr(2);
    let approved = addr(3);

    let (token_id, _) = QN8Mintable::mint(&mut token, &owner, &holder, None).unwrap();
    QN8::approve(&mut token, &holder, &approved, token_id).unwrap();
    assert_eq!(QN8::get_approved(&token, token_id), Some(approved));
}

#[test]
fn test_qn8_owner_of_nonexistent() {
    let token = create_qn8();
    assert!(QN8::owner_of(&token, 999).is_err());
}

// ══════════════════════════════════════════════════════════
//  QN12 — Multi-Token
// ══════════════════════════════════════════════════════════

fn create_qn12() -> QN12Token {
    QN12Token::new("Multi Token".to_string(), addr(1), "https://tokens.quantos.io/".to_string())
}

#[test]
fn test_qn12_creation() {
    let token = create_qn12();
    assert_eq!(token.name, "Multi Token");
}

#[test]
fn test_qn12_mint_fungible() {
    let mut token = create_qn12();
    let owner = addr(1);
    let recipient = addr(2);

    QN12Mintable::mint(&mut token, &owner, &recipient, 1, 1000, None).unwrap();
    assert_eq!(QN12::balance_of(&token, &recipient, 1), 1000);
}

#[test]
fn test_qn12_batch_balance() {
    let mut token = create_qn12();
    let owner = addr(1);
    let holder = addr(2);

    QN12Mintable::mint(&mut token, &owner, &holder, 1, 100, None).unwrap();
    QN12Mintable::mint(&mut token, &owner, &holder, 2, 200, None).unwrap();
    QN12Mintable::mint(&mut token, &owner, &holder, 3, 300, None).unwrap();

    let balances = QN12::balance_of_batch(&token, &[holder, holder, holder], &[1, 2, 3]).unwrap();
    assert_eq!(balances, vec![100, 200, 300]);
}

#[test]
fn test_qn12_transfer() {
    let mut token = create_qn12();
    let owner = addr(1);
    let from = addr(2);
    let to = addr(3);

    QN12Mintable::mint(&mut token, &owner, &from, 1, 500, None).unwrap();
    QN12::safe_transfer_from(&mut token, &from, &from, &to, 1, 200, &[]).unwrap();

    assert_eq!(QN12::balance_of(&token, &from, 1), 300);
    assert_eq!(QN12::balance_of(&token, &to, 1), 200);
}

#[test]
fn test_qn12_transfer_insufficient() {
    let mut token = create_qn12();
    let owner = addr(1);
    let from = addr(2);

    QN12Mintable::mint(&mut token, &owner, &from, 1, 100, None).unwrap();
    let result = QN12::safe_transfer_from(&mut token, &from, &from, &addr(3), 1, 200, &[]);
    assert!(result.is_err());
}
