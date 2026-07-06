---
sidebar_position: 40
slug: /smart-contracts
---

# Smart Contract Development on Quantos

This guide covers everything needed to write, compile, deploy, and interact with smart contracts on the Quantos testnet.

---

## Overview

Quantos runs **QuantosVM**, a WebAssembly (WASM) execution environment. Smart contracts are written in **Solidity** and compiled to WASM using [Solang](https://solang.readthedocs.io/) (Substrate/Polkadot target).

Key differences from Ethereum:
| Feature | Ethereum | Quantos |
|---|---|---|
| Bytecode | EVM | WASM (via Solang) |
| Encoding | Big-Endian uint256 | **Little-Endian** uint256 |
| Addresses | 20 bytes, `0x` prefix | **32 bytes**, `QTS:` prefix |
| Fees | Gas (ETH) | Zero-gas (STACC bandwidth) |
| Compiler | solc | **solang** (`--target polkadot`) |
| Signatures | ECDSA / secp256k1 | **ML-DSA-65** (Dilithium, FIPS 204) |
| Wallet | MetaMask | **Quantos Wallet** (PQC keys) |

> Solidity function selectors (Keccak-256, first 4 bytes) are **identical** to Ethereum.

---

## 1. Prerequisites

### Install Rust + Solang

```bash
# Rust (required for Solang)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Solang compiler
cargo install solang
```

Verify:
```bash
solang --version
```

### Install the Quantos CLI

```bash
cd quantos/sdk
npm install
npm link
```

Verify:
```bash
quantos info
```

Expected output:
```
Quantos CLI v1.0.0

  Solang:   solang 0.x.x
  Path:     /Users/.../.cargo/bin/solang
  Node:     connected (http://127.0.0.1:8545)

  Encoding: Little-Endian uint256 (Solang/Polkadot)
  Addresses: 32 bytes
```

### Environment variable (optional)

```bash
export QUANTOS_RPC=http://127.0.0.1:8545
```

If not set, the CLI defaults to `http://127.0.0.1:8545`.

---

## 2. Write a Smart Contract

Quantos supports standard Solidity syntax. The compiler is Solang, which is largely compatible with `pragma solidity ^0.8.x`.

**Example — `SimpleStorage.sol`:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 public storedValue;
    address public owner;

    event ValueSet(address indexed setter, uint256 value);

    constructor(uint256 _initial) {
        storedValue = _initial;
        owner = msg.sender;
        emit ValueSet(msg.sender, _initial);
    }

    function set(uint256 _value) public {
        storedValue = _value;
        emit ValueSet(msg.sender, _value);
    }

    function get() public view returns (uint256) {
        return storedValue;
    }
}
```

### Known Solang limitations

- `abi.encode` / `abi.decode` with dynamic types (strings, arrays) have partial support
- `delegatecall` is not supported
- `ecrecover` is not available (use `qnt_crypto_*` host functions for PQC signatures)
- Inline assembly is not supported

---

## 3. Compile to WASM

```bash
quantos compile SimpleStorage.sol --output ./build
```

Output:
```
✔ Compiled SimpleStorage
  WASM: ./build/SimpleStorage.wasm (45.2 KB)
  ABI:  ./build/SimpleStorage.contract
```

Two files are generated:
- **`SimpleStorage.wasm`** — compiled WASM bytecode to deploy
- **`SimpleStorage.contract`** — Polkadot metadata (ABI + constructor selectors)

### Compile directly with Solang (advanced)

```bash
solang compile SimpleStorage.sol --target polkadot --output ./build
```

---

## 4. Deploy

```bash
quantos deploy build/SimpleStorage.wasm \
  --from QTS:<your-address> \
  --args uint256:42 \
  --abi build/SimpleStorage.contract
```

If you know the constructor selector manually:
```bash
quantos deploy build/SimpleStorage.wasm \
  --from QTS:<your-address> \
  --selector <4-byte-hex> \
  --args uint256:42
```

Successful output:
```
✔ Deployed at QTS:7f88946d8beb923205b80c0aff63067361fe7d30ad27c691727e12b2581bf460
  Tx: 0xabc123...
```

> Save the deployed contract address — you will need it for all subsequent calls.

### Get the constructor selector from the ABI

```bash
quantos selector "constructor(uint256)"
# => constructor(uint256) => 0x5816c425
```

Or read it directly from the `.contract` metadata file:
```json
{
  "spec": {
    "constructors": [
      { "selector": "0x5816c425", "label": "new" }
    ]
  }
}
```

---

## 5. Interact with a Deployed Contract

### Read-only call

```bash
quantos call QTS:<contract> "get()" --type uint256
# => get() => 42
```

With arguments:
```bash
quantos call QTS:<contract> "balanceOf(address)" \
  --args address:QTS:<user-address> \
  --type uint256
```

### State-changing transaction

```bash
quantos send QTS:<contract> "set(uint256)" \
  --args uint256:100 \
  --from QTS:<your-address>
```

### Utility commands

```bash
# Compute a function selector
quantos selector "transfer(address,uint256)"
# => transfer(address,uint256) => 0xa9059cbb

# Encode a value (uint256 → Little-Endian hex)
quantos encode uint256 1000000
# => 0x40420f000000000000000000000000000000000000000000000000000000000000

# Encode an address
quantos encode address QTS:7f88946d...
# => QTS:7f88946d...

# Decode return data
quantos decode 0x40420f00... --type uint256
# => 1000000
```

---

## 6. Ethereum Tooling Compatibility

| Tool | Compatible ? | Note |
|---|---|---|
| Solidity (language) | ✅ | Via Solang → WASM |
| Hardhat (compile/test) | ✅ | For contract compilation only |
| ethers.js (encoding) | ⚠️ | ABI encoding differs (Big-Endian vs Little-Endian) |
| MetaMask | ❌ | Signs with ECDSA — rejected by Quantos validators (ML-DSA-65 required) |
| wagmi / RainbowKit | ❌ | Depend on MetaMask / ECDSA signing |
| Quantos Wallet | ✅ | Native PQC wallet for transaction signing |

> **Why MetaMask doesn't work**: Quantos validators verify **ML-DSA-65** (Dilithium) signatures. MetaMask produces **ECDSA/secp256k1** signatures. Any transaction signed by MetaMask will be rejected at the consensus layer regardless of VM compatibility.

---

## 7. SDK (Programmatic)

Install as a library:
```bash
npm install @quantos/cli
```

```js
const quantos = require('@quantos/cli');

const RPC = 'http://127.0.0.1:8545';

// 1. Compile
const result = quantos.compile('SimpleStorage.sol', './build');
if (!result.success) throw new Error(result.errors.join('\n'));

// 2. Build constructor calldata
const calldata = quantos.buildCalldata('5816c425', [
  { type: 'uint256', value: '42' },
]);

// 3. Deploy
const wasmBytes = quantos.loadWasm(result.wasmPath);
const wasmHex = wasmBytes.toString('hex');
const deployed = await quantos.deploy(RPC, wasmHex, 'QTS:<deployer>', calldata);
console.log('Contract address:', deployed.address);

// 4. Call (read-only)
const selector = quantos.computeSelector('get()');
const readCalldata = quantos.buildCalldata(selector, []);
const raw = await quantos.call(RPC, deployed.address, 'QTS:<caller>', readCalldata);
const value = quantos.decodeReturnData(raw.return_data, 'uint256');
console.log('storedValue:', value); // => 42

// 5. Send (state-changing)
const setCalldata = quantos.buildCalldata(
  quantos.computeSelector('set(uint256)'),
  [{ type: 'uint256', value: '100' }]
);
await quantos.sendTx(RPC, deployed.address, 'QTS:<sender>', setCalldata);
```

---

## 7. ABI Encoding — Important Differences

Quantos uses **Solang/Polkadot encoding**. The critical difference from Ethereum:

| Type | Ethereum (EVM) | Quantos (Solang) |
|---|---|---|
| `uint256` | 32 bytes **Big-Endian** | 32 bytes **Little-Endian** |
| `address` | 20 bytes, `0x` | **32 bytes**, `QTS:` |
| `bool` | 32 bytes BE | 32 bytes LE (1 byte significant) |
| Function selector | Keccak-256 (4 bytes) | **Same** |

**Do not use `ethers.js` ABI encoding directly** — it will produce incorrect calldata. Use the Quantos SDK encoding functions or the CLI.

```js
// Correct: Quantos SDK
const calldata = quantos.buildCalldata('a9059cbb', [
  { type: 'address', value: 'QTS:7f88946d...' },
  { type: 'uint256', value: '1000' },
]);

// Wrong: ethers ABI encoder — produces Big-Endian uint256
```

---

## 8. Address Format

All Quantos addresses are 32 bytes and use the `QTS:` prefix:

```
QTS:7f88946d8beb923205b80c0aff63067361fe7d30ad27c691727e12b2581bf460
```

The CLI accepts both `QTS:` and raw hex as input, but always displays `QTS:`.

To convert:
```bash
# hex → QTS
QTS:7f88946d...

# The prefix is purely cosmetic — the underlying bytes are identical
```

---

## 9. JSON-RPC Reference

The Quantos node exposes a JSON-RPC API at port `8545`.

### Deploy a contract

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qnt_deployContract",
    "params": [{
      "bytecode": "0x<wasm-hex>",
      "deployer": "QTS:<address>",
      "constructor_data": "0x<calldata>"
    }],
    "id": 1
  }'
```

Response:
```json
{ "result": { "address": "QTS:...", "tx_hash": "0x..." } }
```

### Call a contract (read-only)

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qnt_callContract",
    "params": [{
      "contract_address": "QTS:<address>",
      "caller": "QTS:<caller>",
      "input_data": "0x<calldata>"
    }],
    "id": 1
  }'
```

Response:
```json
{ "result": { "return_data": "0x2a000000..." } }
```

### Send a transaction (state-changing)

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qnt_sendTransaction",
    "params": [{
      "contract_address": "QTS:<address>",
      "caller": "QTS:<sender>",
      "input_data": "0x<calldata>"
    }],
    "id": 1
  }'
```

### Other methods

| Method | Description |
|---|---|
| `qnt_getBalance` | Get QTS balance of an address |
| `qnt_nodeInfo` | Get node status and version |
| `qdag_getBalance` | Get account balance (alternative) |
| `qdag_getNonce` | Get account nonce |
| `qdag_sendTransaction` | Submit a signed transaction |
| `qdag_getTransaction` | Get transaction by hash |
| `qdag_getMetrics` | Node performance metrics |
| `qdag_chainId` | Get chain ID |

---

## 10. Full Example — ERC-20 Token (QTEST)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract QTEST {
    string public constant name = "Quantos Test Token";
    string public constant symbol = "QTEST";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public constant CLAIM_AMOUNT = 1000 * 10**18;
    uint256 public constant CLAIM_COOLDOWN = 24 hours;
    mapping(address => uint256) public lastClaim;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function claim() public returns (bool) {
        require(block.timestamp >= lastClaim[msg.sender] + CLAIM_COOLDOWN, "Cooldown active");
        lastClaim[msg.sender] = block.timestamp;
        totalSupply += CLAIM_AMOUNT;
        balanceOf[msg.sender] += CLAIM_AMOUNT;
        emit Transfer(address(0), msg.sender, CLAIM_AMOUNT);
        return true;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
```

Deploy and interact:

```bash
# Compile
quantos compile QTEST.sol --output ./build

# Deploy (no constructor args)
quantos deploy build/QTEST.wasm --from QTS:<deployer>

# Claim tokens
quantos send QTS:<contract> "claim()" --from QTS:<your-address>

# Check balance
quantos call QTS:<contract> "balanceOf(address)" \
  --args address:QTS:<your-address> \
  --type uint256

# Transfer
quantos send QTS:<contract> "transfer(address,uint256)" \
  --args address:QTS:<recipient>,uint256:1000000000000000000000 \
  --from QTS:<your-address>
```

---

## 11. Troubleshooting

### `Solang not found`
```bash
cargo install solang
# then verify:
solang --version
```

### `No .wasm output produced`
Solang compilation failed silently. Run directly to see errors:
```bash
solang compile MyContract.sol --target polkadot --output ./build
```

### Wrong return value / garbled numbers
You are decoding Big-Endian (ethers.js). Quantos uses **Little-Endian** for `uint256`. Use `quantos decode` or `quantos.decodeReturnData()` from the SDK.

### `RPC timeout` or `Node: offline`
The Quantos node is not running. Start it:
```bash
cargo run --release
# or
docker compose up
```

### `Deploy failed: Invalid constructor_data`
The constructor selector is wrong. Get the correct one:
```bash
quantos selector "constructor(uint256)"
# use the output hex as --selector
```

Or pass `--abi build/MyContract.contract` and let the CLI read it automatically.

---

## 12. QuantosVM Limits

| Resource | Limit |
|---|---|
| Max memory | 64 MB (1024 WASM pages) |
| Max stack | 1 MB |
| Max compute units | 100,000,000 CU per execution |
| Storage write cost | 5,000 CU |
| Storage read cost | 1,000 CU |
| Hash per byte | 1 CU |

Exceeding the compute unit budget aborts the execution with `OutOfGas`. There is **no fee** — Quantos is zero-gas.

---

## 13. What's Coming

- Native Rust resource-based contracts (mainnet model)
- Cross-shard contract calls
- Light client support
- On-chain ABI registry
