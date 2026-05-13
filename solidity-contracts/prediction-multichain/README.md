# Multichain Prediction Market

Dedicated EVM prediction market contract for Vybss on Base, Polygon, BSC, Hyperliquid and Arbitrum.

## Core behavior

- Multi-outcome AMM markets (`2..8` outcomes)
- Fees on every trade: `2.0%`
- `0.5%` protocol fee sent immediately to `protocolFeeRecipient`
- `1.5%` LP fee accrued to LP positions and claimable via `claimLpFees`
- LP funding via `createMarket` and `addLiquidity`
- LP redemption after market resolution via `redeemLiquidity`
- Resolver-based settlement with winning outcome payout via `claimWinnings`

## Project layout

- `contracts/MultichainPredictionMarket.sol` — core contract
- `scripts/deploy.ts` — deploy one contract per EVM chain
- `hardhat.config.ts` — Base, Polygon, BSC, HyperEVM, Arbitrum networks
- `.env.example` — RPC and fee recipient config

## Commands

```bash
npm install
npx hardhat compile
npx hardhat run scripts/deploy.ts --network base
npx hardhat run scripts/deploy.ts --network polygon
npx hardhat run scripts/deploy.ts --network bsc
npx hardhat run scripts/deploy.ts --network arbitrum
npx hardhat run scripts/deploy.ts --network hyperevm
```

## Constructor

```solidity
constructor(address initialOwner, address protocolFeeRecipient)
```

## Notes

- The existing Quantos-native prediction contract is intentionally untouched.
- This project is the dedicated multichain EVM branch for the new prediction market service.
- Per-market metadata such as question text and labels can stay offchain while the contract enforces outcome count, AMM pricing, LP accounting and fee routing.
