// Verification for the canonical serializer (spec §4) + digest (spec §3).
// Run: npx tsx src/canonical.check.ts
//
// Checks:
//   1. digestForChain("evm", ...) == authorizationDigest(...)  (EVM parity)
//   2. canonical blob round-trips through a JS decoder mirroring the on-chain one
//   3. per-chain toField normalization is distinct and deterministic
//
// TESTNET ONLY.

import { keccak256 } from "ethers";
import { authorizationDigest, type AttestorProofStruct } from "./account.js";
import {
  encodeAttestationCanonical,
  canonicalDigest,
  digestForChain,
  normalizeTo,
  CHAIN_IDS,
} from "./canonical.js";

let failures = 0;
function assert(cond: boolean, msg: string) {
  if (cond) {
    console.log(`  ok  ${msg}`);
  } else {
    failures++;
    console.error(`FAIL  ${msg}`);
  }
}

const W = (byte: number) => "0x" + byte.toString(16).padStart(2, "0").repeat(32);

// ── 1. EVM parity ───────────────────────────────────────────────────────────

{
  const account = W(0xab);
  const to = "0x" + "11".repeat(20);
  const value = 123456789n;
  const data = "0xdeadbeef";
  const nonce = 7n;
  const chainId = 8453n; // Base mainnet

  const evm = authorizationDigest({ account, to, value, data, nonce, chainId });
  const canon = digestForChain("evm", { account, to, value, data, nonce, chainId });
  assert(evm === canon, `EVM digest parity (${evm.slice(0, 10)}…)`);
}

// ── 2. canonical blob round-trip ──────────────────────────────────────────────

function decodeCanonical(blob: Uint8Array) {
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  let off = 0;
  const u32 = () => { const v = dv.getUint32(off, false); off += 4; return v; };
  const u64 = () => { const v = dv.getBigUint64(off, false); off += 8; return v; };
  const word = () => {
    let s = "0x";
    for (let i = 0; i < 32; i++) s += blob[off + i].toString(16).padStart(2, "0");
    off += 32;
    return s;
  };
  const words = (n: number) => Array.from({ length: n }, () => word());

  const count = u32();
  const proofs: AttestorProofStruct[] = [];
  for (let i = 0; i < count; i++) {
    const attestorId = word();
    const wotsRoot = word();
    const leafIndex = u64();
    const wotsSig = words(u32());
    const merklePath = words(u32());
    const setIndex = u64();
    const setProof = words(u32());
    proofs.push({ attestorId, wotsRoot, leafIndex, wotsSig, merklePath, setIndex, setProof });
  }
  return { proofs, consumed: off, total: blob.length };
}

{
  const proofs: AttestorProofStruct[] = [
    {
      attestorId: W(0x11),
      wotsRoot: W(0x22),
      leafIndex: 0n,
      wotsSig: Array.from({ length: 67 }, (_, i) => W(i & 0xff)),
      merklePath: [W(0xaa), W(0xbb)],
      setIndex: 3n,
      setProof: [W(0xcc)],
    },
    {
      attestorId: W(0x33),
      wotsRoot: W(0x44),
      leafIndex: 5n,
      wotsSig: Array.from({ length: 67 }, () => W(0xee)),
      merklePath: [],
      setIndex: 1n,
      setProof: [W(0xdd), W(0xee), W(0xff)],
    },
  ];

  const blob = encodeAttestationCanonical(proofs);
  const { proofs: back, consumed, total } = decodeCanonical(blob);
  assert(consumed === total, `blob fully consumed (${consumed}/${total} bytes)`);
  assert(back.length === proofs.length, "proof count round-trips");
  assert(JSON.stringify(serializable(back)) === JSON.stringify(serializable(proofs)), "proofs round-trip byte-exact");
}

function serializable(ps: AttestorProofStruct[]) {
  return ps.map((p) => ({
    ...p,
    leafIndex: p.leafIndex.toString(),
    setIndex: p.setIndex.toString(),
  }));
}

// ── 3. per-chain toField normalization ────────────────────────────────────────

{
  const evmAddr = "0x" + "ab".repeat(20);
  const tfEvm = normalizeTo("evm", evmAddr);
  assert(tfEvm === "0x" + "00".repeat(12) + "ab".repeat(20), "evm toField = left-padded address");

  const native32 = W(0x7c);
  assert(normalizeTo("sui", native32) === native32, "sui toField = native 32-byte");
  assert(normalizeTo("solana", native32) === native32, "solana toField = native 32-byte");

  const nearAcct = "alice.near";
  assert(normalizeTo("near", nearAcct) === keccak256(new TextEncoder().encode(nearAcct)), "near toField = keccak(utf8)");

  const xlm = "GCEXAMPLE";
  assert(normalizeTo("stellar", xlm) === keccak256(new TextEncoder().encode(xlm)), "stellar toField = keccak(utf8)");

  // Distinct chain ids produce distinct digests for the same intent.
  const base = { account: W(1), to: native32, value: 1n, data: "0x", nonce: 0n };
  const dSui = digestForChain("sui", base);
  const dAptos = digestForChain("aptos", base);
  assert(dSui !== dAptos, "distinct chainId ⇒ distinct digest (sui≠aptos)");
  assert(CHAIN_IDS.sui !== CHAIN_IDS.aptos, "chain id table is distinct");

  // canonicalDigest is deterministic
  const a = canonicalDigest({ account: W(1), toField: native32, value: 1n, data: "0x", nonce: 0n, chainId: CHAIN_IDS.sui });
  assert(a === dSui, "canonicalDigest matches digestForChain");
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
if (failures !== 0) process.exit(1);
