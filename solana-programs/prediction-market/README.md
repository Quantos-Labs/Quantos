# Solana Prediction Market

Dedicated Solana program for the Vybss multichain prediction market.

## Core behavior

- Multi-outcome AMM markets (`2..8` outcomes)
- Resolver-based settlement after market close
- Fee split on each trade:
  - `0.5%` to the protocol fee recipient token account
  - `1.5%` to the LP fee vault, claimable by LPs
- Separate SPL token vaults for:
  - market backstop collateral
  - LP fee accrual
  - protocol fee recipient ATA
- LP positions and trader outcome positions stored per market

## Workspace layout

- `programs/solana-prediction-market/src/lib.rs` — Anchor program
- `Anchor.toml` — workspace config
- `Cargo.toml` — workspace manifest

## Commands

```bash
cargo check
anchor build
anchor deploy --provider.cluster devnet
```

## Accounts model

- `Config` PDA: global authority and protocol fee recipient
- `Market` PDA: market config, pools, backstop and fee accounting
- `LpPosition` PDA: LP shares and accrued fees
- `OutcomePosition` PDA: user shares per outcome
- PDA token vaults: market collateral and LP fee vault

## Notes

- This program is separate from the existing Quantos-native prediction contract.
- The intended supported service set is: Base, Polygon, BSC, Hyperliquid, Arbitrum and Solana.
- Solana protocol fees are routed to the protocol fee recipient wallet's token account for the market collateral mint.
