# Quantos CLI & SDK

Compile, deploy, and interact with Solidity smart contracts on QuantosVM.

## Install

```bash
cd sdk
npm install
npm link  # makes 'quantos' available globally
```

## CLI Commands

### Compile Solidity → WASM
```bash
quantos compile contracts/MyToken.sol --output build/
```

### Deploy contract
```bash
quantos deploy build/MyToken.wasm \
  --from QTS:aabbccddee... \
  --selector 5816c425 \
  --args uint256:1000000
```

### Call read-only function
```bash
quantos call QTS:contract... "totalSupply()" --type uint256
quantos call QTS:contract... "balanceOf(address)" --args address:QTS:aabbcc... --type uint256
```

### Send state-changing transaction
```bash
quantos send QTS:contract... "transfer(address,uint256)" \
  --args address:QTS:recipient...,uint256:100000 \
  --from QTS:sender...
```

### Utility commands
```bash
quantos info                              # Node + Solang status
quantos selector "transfer(address,uint256)"  # => 0xa9059cbb
quantos encode uint256 1000000            # => 0x40420f00...
quantos decode 0x40420f00... --type uint256   # => 1000000
```

## SDK (programmatic)

```js
const quantos = require('@quantos/cli');

// Compile
const result = quantos.compile('MyToken.sol', './build');

// Encode calldata (Solang LE)
const calldata = quantos.buildCalldata('a9059cbb', [
  { type: 'address', value: 'QTS:aabbccddee...' },
  { type: 'uint256', value: '100000' },
]);

// Deploy
const addr = await quantos.deploy('http://127.0.0.1:8545', wasmHex, deployer, ctorData);

// Call
const result = await quantos.call('http://127.0.0.1:8545', contract, caller, calldata);
```

## Encoding

Quantos uses **Solang/Polkadot** encoding:
- **uint256**: 32 bytes, **little-endian**
- **address**: 32 bytes, always prefixed `QTS:` (not 20-byte 0x like Ethereum)
- **bool**: 1 byte (0x00 or 0x01)
- **Function selectors**: Keccak-256 (first 4 bytes), same as Ethereum

## Address Convention

All Quantos addresses (wallets, contracts, recipients) use the **`QTS:` prefix**:
```
QTS:7f88946d8beb923205b80c0aff63067361fe7d30ad27c691727e12b2581bf460
```
The CLI accepts both `QTS:` and `0x` as input, but always displays `QTS:`.
