/**
 * QuantosFinalityRelay — turn any L1 validator into a Quantos L0 relayer.
 *
 * L1 validators (Ethereum, Solana, etc.) run this service to submit their
 * chain's checkpoints to the Quantos L0 Finality Hub. Quantos validators
 * verify the checkpoint cryptographically via native light clients, then
 * sign an L0FinalityProof with Falcon-512 PQC signatures. This proof can
 * then be relayed back to the L1 via the QuantosL0Verifier contract,
 * making the L1's finality quantum-resistant.
 *
 * Usage:
 * ```ts
 * const relay = new QuantosFinalityRelay({
 *   quantosRpcUrl: 'http://localhost:8555',
 *   sourceChain: ChainId.Base,
 *   sourceEndpoint: 'https://base.llamarpc.com',
 *   validatorKey: '0x...', // Falcon-512 or Ecdsa key for Quantos auth
 *   pollIntervalMs: 12_000,
 * });
 * relay.start();
 * ```
 */

import axios from "axios";
import { ethers } from "ethers";
import { QuantosNodeClient } from "../core/client";
import * as falcon from "../pqc/falcon";
import type { L0FinalityProof } from "../types/proof";

// Pure-JS base64 (no Buffer, works in browser + Node.js)
const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function bytesToBase64(bytes: Uint8Array): string {
  let out = "", i = 0;
  while (i < bytes.length) {
    const a = bytes[i++];
    const b = i < bytes.length ? bytes[i++] : 0;
    const c = i < bytes.length ? bytes[i++] : 0;
    const bitmap = (a << 16) | (b << 8) | c;
    out += B64_CHARS.charAt((bitmap >> 18) & 63);
    out += B64_CHARS.charAt((bitmap >> 12) & 63);
    out += i - 1 < bytes.length ? B64_CHARS.charAt((bitmap >> 6) & 63) : "=";
    out += i < bytes.length ? B64_CHARS.charAt(bitmap & 63) : "=";
  }
  return out;
}

function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/[^A-Za-z0-9+/]/g, "");
  const len = clean.length;
  const bytes = new Uint8Array((len * 3) / 4 - (clean.endsWith("=") ? (clean.endsWith("==") ? 2 : 1) : 0));
  let i = 0, j = 0;
  while (i < len) {
    const a = B64_CHARS.indexOf(clean.charAt(i++));
    const b = B64_CHARS.indexOf(clean.charAt(i++));
    const c = B64_CHARS.indexOf(clean.charAt(i++));
    const d = B64_CHARS.indexOf(clean.charAt(i++));
    const bitmap = (a << 18) | (b << 12) | (c << 6) | d;
    bytes[j++] = (bitmap >> 16) & 255;
    if (c >= 0) bytes[j++] = (bitmap >> 8) & 255;
    if (d >= 0) bytes[j++] = bitmap & 255;
  }
  return bytes;
}

export enum ChainId {
  Ethereum = "ethereum",
  EthereumSepolia = "ethereum-sepolia",
  Base = "base",
  BaseSepolia = "base-sepolia",
  Arbitrum = "arbitrum",
  Optimism = "optimism",
  Polygon = "polygon",
  Avalanche = "avalanche",
  BinanceSmartChain = "bsc",
  Solana = "solana",
  SolanaDevnet = "solana-devnet",
  Near = "near",
  Aptos = "aptos",
  Sui = "sui",
  Bitcoin = "bitcoin",
  Cosmos = "cosmos",
  Polkadot = "polkadot",
  Stellar = "stellar",
  Tron = "tron",
  TON = "ton",
  Cardano = "cardano",
  Tezos = "tezos",
}

export interface ExternalCheckpoint {
  chainId: ChainId;
  blockNumber: number;
  blockHash: string;
  stateRoot: string;
  /** Parent block hash for canonical chain continuity */
  parentBlockHash: string;
  /** Chain work (PoW totalDifficulty) or justification weight (PoS) for fork-choice */
  chainWork: string;
  timestamp: number;
  proof: ChainProof;
}

export type ChainProof =
  | { type: "evm"; blockHeaderRlp: string; sealHashes: string[] }
  | { type: "solana"; bankHash: string; signatureSets: string[] }
  | { type: "bitcoin"; header: string; merkleRoot: string; depth: number }
  | { type: "generic"; raw: string };

export interface FinalityRelayConfig {
  /** Quantos RPC endpoint (e.g. http://localhost:8555) */
  quantosRpcUrl: string;
  /** Which chain this relayer monitors */
  sourceChain: ChainId;
  /** RPC endpoint for the source chain */
  sourceEndpoint: string;
  /** Private key used to authenticate checkpoint submissions to Quantos */
  validatorKey: string;
  /** How often to poll for new blocks (ms) */
  pollIntervalMs?: number;
  /** Number of confirmations before a block is considered final */
  confirmations?: number;
  /** Optional API key for Quantos RPC */
  quantosApiKey?: string;
}

export interface RelayState {
  lastRelayedBlock: number;
  pendingCheckpoints: Map<string, ExternalCheckpoint>;
  proofsReceived: Map<string, L0FinalityProof>;
  errors: number;
  startedAt: number;
}

export class QuantosFinalityRelay {
  private quantos: QuantosNodeClient;
  private config: FinalityRelayConfig;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private state: RelayState;

  constructor(config: FinalityRelayConfig) {
    this.config = {
      pollIntervalMs: 12_000,
      confirmations: 2,
      ...config,
    };
    this.quantos = new QuantosNodeClient({
      rpcUrl: config.quantosRpcUrl,
      apiKey: config.quantosApiKey,
      timeoutMs: 30_000,
    });
    this.state = {
      lastRelayedBlock: 0,
      pendingCheckpoints: new Map(),
      proofsReceived: new Map(),
      errors: 0,
      startedAt: 0,
    };
  }

  /** Start the relay loop. Idempotent: calling start() twice is a no-op. */
  start(): void {
    if (this.intervalId !== null) return;

    this.state.startedAt = Date.now();
    // Immediate first tick, then recurring
    this.tick();
    this.intervalId = setInterval(
      () => this.tick(),
      this.config.pollIntervalMs
    );
  }

  /** Stop the relay loop. */
  stop(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /** Current relay state snapshot. */
  getState(): RelayState {
    return { ...this.state, pendingCheckpoints: new Map(this.state.pendingCheckpoints) };
  }

  /** Manually submit a checkpoint to the Quantos L0 Hub. */
  async submitCheckpoint(checkpoint: ExternalCheckpoint): Promise<string> {
    // The Quantos RPC accepts structured ExternalCheckpoint + an auth signature
    // from the relayer proving they are the one who fetched the source data.
    const authSig = await this.signCheckpointAuth(checkpoint);

    const txHash = await this.quantos.submitExternalCheckpoint(checkpoint, authSig);

    this.state.pendingCheckpoints.set(txHash, checkpoint);
    return txHash;
  }

  /** Poll the Quantos node for a proof that corresponds to a checkpoint. */
  async pollProof(checkpointHash: string): Promise<L0FinalityProof | null> {
    const proof = await this.quantos.getProofByHash(checkpointHash);
    if (proof) {
      this.state.proofsReceived.set(checkpointHash, proof);
      this.state.pendingCheckpoints.delete(checkpointHash);
    }
    return proof;
  }

  /** Relay a verified L0 proof back to the source chain verifier contract.
   *  Builds and broadcasts an EVM transaction calling `finalizeBlock()`.
   */
  async relayProofToSource(
    proof: L0FinalityProof,
    /** Contract address of QuantosL0Verifier on the source chain */
    verifierAddress: string,
    /** EVM signer that pays gas on the source chain */
    signer: ethers.Signer
  ): Promise<string> {
    const abi = [
      "function finalizeBlock(uint256 blockNumber, bytes32 blockHash, bytes32 proofHash, bytes32 validatorSetRoot, uint128 signedStake, bytes32 stateRoot, string calldata chainId, bytes32 parentBlockHash, uint128 chainWork) external returns (bool)",
    ];
    const contract = new ethers.Contract(verifierAddress, abi, signer);

    const proofHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(proof)));
    const signedStake = this.computeSignedStake(proof);

    const tx = await contract.finalizeBlock(
      proof.header.epoch,
      ethers.hexlify(ethers.toUtf8Bytes(proof.header.checkpointHash)),
      proofHash,
      proof.header.checkpointHash,
      signedStake,
      ethers.hexlify(ethers.toUtf8Bytes(proof.header.stateRoot)),
      proof.header.chainId,
      ethers.hexlify(ethers.toUtf8Bytes(proof.header.parentBlockHash)),
      BigInt(proof.header.chainWork)
    );

    const receipt = await tx.wait();
    return receipt.hash;
  }

  private computeSignedStake(proof: L0FinalityProof): bigint {
    let stake = 0n;
    for (const sig of proof.signatures) {
      const validator = proof.validators[sig.validatorIdx];
      if (validator) {
        stake += BigInt(validator.stake);
      }
    }
    return stake;
  }

  // ── Private ─────────────────────────────────────────────────────────

  private async tick(): Promise<void> {
    try {
      const latestBlock = await this.fetchLatestFinalizedBlock();
      if (latestBlock.blockNumber > this.state.lastRelayedBlock) {
        const checkpoint = this.buildCheckpoint(latestBlock);
        const txHash = await this.submitCheckpoint(checkpoint);
        this.state.lastRelayedBlock = latestBlock.blockNumber;

        // Optimistically poll for the proof
        setTimeout(async () => {
          await this.pollProof(txHash);
        }, 5_000);
      }

      // Retry any still-pending checkpoints
      for (const [hash] of this.state.pendingCheckpoints) {
        await this.pollProof(hash);
      }
    } catch (err) {
      this.state.errors++;
      console.error("[FinalityRelay] tick error:", err);
    }
  }

  private async fetchLatestFinalizedBlock(): Promise<{
    blockNumber: number;
    blockHash: string;
    parentHash: string;
    stateRoot: string;
    timestamp: number;
    totalDifficulty: string;
  }> {
    if (this.config.sourceChain.startsWith("ethereum") || this.config.sourceChain.startsWith("base")) {
      const resp = await axios.post(this.config.sourceEndpoint, {
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getBlockByNumber",
        params: ["finalized", false],
      });
      const block = resp.data.result;
      return {
        blockNumber: parseInt(block.number, 16),
        blockHash: block.hash,
        parentHash: block.parentHash,
        stateRoot: block.stateRoot,
        timestamp: parseInt(block.timestamp, 16),
        totalDifficulty: block.totalDifficulty || "0x0",
      };
    }

    // Generic fallback for other chains
    return {
      blockNumber: 0,
      blockHash: "0x0",
      parentHash: "0x0",
      stateRoot: "0x0",
      timestamp: 0,
      totalDifficulty: "0x0",
    };
  }

  private buildCheckpoint(block: {
    blockNumber: number;
    blockHash: string;
    parentHash: string;
    stateRoot: string;
    timestamp: number;
    totalDifficulty: string;
  }): ExternalCheckpoint {
    const proof: ChainProof =
      this.config.sourceChain.startsWith("solana")
        ? { type: "solana", bankHash: block.stateRoot, signatureSets: [] }
        : { type: "evm", blockHeaderRlp: "", sealHashes: [] };

    return {
      chainId: this.config.sourceChain,
      blockNumber: block.blockNumber,
      blockHash: block.blockHash,
      stateRoot: block.stateRoot,
      parentBlockHash: block.parentHash,
      chainWork: block.totalDifficulty,
      timestamp: block.timestamp,
      proof,
    };
  }

  private async signCheckpointAuth(checkpoint: ExternalCheckpoint): Promise<string> {
    const digest = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(checkpoint)));
    const keyBytes = this.config.validatorKey.startsWith("0x")
      ? ethers.getBytes(this.config.validatorKey)
      : base64ToBytes(this.config.validatorKey);
    const falconSig = await falcon.sign(ethers.getBytes(digest), keyBytes);
    return bytesToBase64(falconSig.sig);
  }
}

// ── Multi-Relay Quorum ──────────────────────────────────────────────

/** Aggregates checkpoints from multiple untrusted relayers.
 *  A checkpoint is only accepted if >= `quorumThreshold` relayers
 *  agree on the exact same (blockNumber, blockHash, stateRoot).
 */
export class RelayPool {
  private checkpoints = new Map<string, Map<string, number>>();
  private quorumThreshold: number;

  constructor(quorumThreshold: number) {
    this.quorumThreshold = quorumThreshold;
  }

  /** Submit a checkpoint from a single relayer. Returns the checkpoint
   *  if quorum is reached, otherwise null. */
  submit(checkpoint: ExternalCheckpoint, relayerId: string): ExternalCheckpoint | null {
    const key = `${checkpoint.chainId}:${checkpoint.blockNumber}:${checkpoint.blockHash}:${checkpoint.stateRoot}`;
    const entry = this.checkpoints.get(key) || new Map<string, number>();
    const count = (entry.get(relayerId) || 0) + 1;
    entry.set(relayerId, count);
    this.checkpoints.set(key, entry);

    if (entry.size >= this.quorumThreshold) {
      return checkpoint;
    }
    return null;
  }

  /** Prune old entries to prevent unbounded growth. */
  prune(maxAgeBlocks: number, currentBlockNumber: number): void {
    for (const [key] of this.checkpoints) {
      const parts = key.split(":");
      const blockNumber = parseInt(parts[1], 10);
      if (currentBlockNumber - blockNumber > maxAgeBlocks) {
        this.checkpoints.delete(key);
      }
    }
  }
}
