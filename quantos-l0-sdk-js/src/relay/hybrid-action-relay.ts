/**
 * HybridActionRelay — auto-confirmation pipeline for PQCSignatureRegistry.
 *
 * Runs as part of the Quantos L0 relayer (or standalone).
 * Subscribes to HybridActionSubmitted events, verifies Falcon/Dilithium
 * signatures off-chain, then calls either:
 *  - verifyPqcSignature(actionHash)     — for individual actions
 *  - confirmBatchStark(hashes, commit)  — for batches of actions (gas-efficient)
 *
 * The batch path accumulates pending actions up to BATCH_SIZE or BATCH_TIMEOUT_MS,
 * then submits them all at once with a 32-byte STARK commitment produced by
 * the Quantos L0 hub (stark_prover::prove_batch).
 *
 * Usage:
 * ```ts
 * const relay = new HybridActionRelay({
 *   provider: new ethers.JsonRpcProvider("https://base.llamarpc.com"),
 *   registryAddress: "0x...",
 *   verifierKey: "0x...",  // trusted verifier private key
 *   quantosRpcUrl: "http://localhost:8555",
 *   batchSize: 50,
 *   batchTimeoutMs: 10_000,
 * });
 * relay.start();
 * ```
 */

import { ethers } from "ethers";
import axios from "axios";
import * as falcon from "../pqc/falcon";
import { base64ToBytes } from "../pqc/falcon";
import { computeFalconDigest, computeDomainSeparator } from "../pqc/hybrid-wallet";

export interface HybridActionRelayConfig {
  /** Ethers provider for the chain where PQCSignatureRegistry is deployed */
  provider: ethers.Provider;
  /** Address of the PQCSignatureRegistry contract */
  registryAddress: string;
  /** Private key of a trusted verifier (added via addVerifier() by owner) */
  verifierKey: string;
  /** Quantos L0 node RPC URL — used to generate STARK batch proofs */
  quantosRpcUrl: string;
  /** Maximum actions to accumulate before sending a batch (default 50) */
  batchSize?: number;
  /** Maximum ms to wait before flushing a partial batch (default 10s) */
  batchTimeoutMs?: number;
  /** Chain ID (auto-detected from provider if omitted) */
  chainId?: number;
}

interface PendingConfirmation {
  actionHash: string;
  actor: string;
  payloadHash: string;
  pqcSignature: Uint8Array;
  pqcPublicKey: Uint8Array;
  algo: number; // 0=Falcon512, 1=Dilithium3
  falconDigest: Uint8Array;
  submittedAt: number;
}

const REGISTRY_ABI = [
  "event HybridActionSubmitted(bytes32 indexed actionHash, address indexed actor, bytes32 payloadHash, uint8 algo)",
  "function getPendingAction(bytes32 actionHash) external view returns (tuple(address actor, bytes32 payloadHash, bytes pqcSignature, uint8 algo, uint64 submittedAt, bool ecdsaVerified, bool pqcVerified))",
  "function getPqcIdentity(address account) external view returns (tuple(bytes publicKey, uint8 algo, uint64 registeredAt, bool active, bytes pendingPublicKey, uint64 rotationActivatesAt))",
  "function nonces(address account) external view returns (uint256)",
  "function verifyPqcSignature(bytes32 actionHash) external",
  "function confirmBatchStark(bytes32[] calldata actionHashes, bytes32 starkCommitment) external",
  "function DOMAIN_SEPARATOR() external view returns (bytes32)",
];

export class HybridActionRelay {
  private config: Required<HybridActionRelayConfig>;
  private verifierWallet: ethers.Wallet;
  private registry: ethers.Contract;
  private pending: Map<string, PendingConfirmation> = new Map();
  private batchTimer: ReturnType<typeof setTimeout> | null = null;
  private chainId: number = 0;
  private domainSeparator: string = "";
  private running = false;

  constructor(config: HybridActionRelayConfig) {
    this.config = {
      batchSize: 50,
      batchTimeoutMs: 10_000,
      chainId: 0,
      ...config,
    };
    this.verifierWallet = new ethers.Wallet(config.verifierKey, config.provider);
    this.registry = new ethers.Contract(
      config.registryAddress,
      REGISTRY_ABI,
      this.verifierWallet
    );
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    const network = await this.config.provider.getNetwork();
    this.chainId = this.config.chainId || Number(network.chainId);
    this.domainSeparator = computeDomainSeparator(this.chainId, this.config.registryAddress);

    console.log(
      `[HybridActionRelay] started — chain ${this.chainId}, registry ${this.config.registryAddress}`
    );

    this.registry.on(
      "HybridActionSubmitted",
      (actionHash: string, actor: string, payloadHash: string, algo: number) => {
        this.onHybridActionSubmitted(actionHash, actor, payloadHash, algo).catch((e) =>
          console.error("[HybridActionRelay] event handler error:", e)
        );
      }
    );
  }

  stop(): void {
    this.running = false;
    this.registry.removeAllListeners("HybridActionSubmitted");
    if (this.batchTimer) clearTimeout(this.batchTimer);
  }

  // ── Private ─────────────────────────────────────────────────────────────

  private async onHybridActionSubmitted(
    actionHash: string,
    actor: string,
    payloadHash: string,
    algo: number
  ): Promise<void> {
    try {
      // Fetch on-chain action and PQC identity
      const [actionData, identityData, nonce] = await Promise.all([
        this.registry.getPendingAction(actionHash),
        this.registry.getPqcIdentity(actor),
        this.registry.nonces(actor),
      ]);

      if (actionData.pqcVerified) return; // already confirmed
      if (!identityData.active) {
        console.warn(`[HybridActionRelay] actor ${actor} has no active PQC identity`);
        return;
      }

      const pqcSignature = ethers.getBytes(actionData.pqcSignature);
      const pqcPublicKey = ethers.getBytes(identityData.publicKey);

      // The nonce used when submitting was nonces[actor] - 1 (already incremented on-chain)
      const usedNonce = Number(nonce) - 1;
      const falconDigestBytes = computeFalconDigest(
        this.domainSeparator,
        actor,
        payloadHash,
        usedNonce
      );

      // Verify Falcon/Dilithium signature off-chain
      const valid = await this.verifyPqcSig(algo, falconDigestBytes, pqcSignature, pqcPublicKey);
      if (!valid) {
        console.warn(`[HybridActionRelay] invalid PQC sig for action ${actionHash} — skipping`);
        return;
      }

      this.pending.set(actionHash, {
        actionHash,
        actor,
        payloadHash,
        pqcSignature,
        pqcPublicKey,
        algo,
        falconDigest: falconDigestBytes,
        submittedAt: Date.now(),
      });

      console.log(
        `[HybridActionRelay] queued ${actionHash} (batch size: ${this.pending.size})`
      );

      if (this.pending.size >= this.config.batchSize) {
        await this.flushBatch();
      } else if (!this.batchTimer) {
        this.batchTimer = setTimeout(
          () => this.flushBatch().catch(console.error),
          this.config.batchTimeoutMs
        );
      }
    } catch (err) {
      console.error(`[HybridActionRelay] error processing ${actionHash}:`, err);
    }
  }

  private async verifyPqcSig(
    algo: number,
    digest: Uint8Array,
    sig: Uint8Array,
    pubkey: Uint8Array
  ): Promise<boolean> {
    // algo 0 = Falcon512, algo 1 = Dilithium3
    // Both use the same JS verify interface in the SDK
    return falcon.verify(digest, sig, pubkey);
  }

  private async flushBatch(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }
    if (this.pending.size === 0) return;

    const batch = Array.from(this.pending.values());
    this.pending.clear();

    const actionHashes = batch.map((p) => p.actionHash);

    if (batch.length === 1) {
      // Single action — cheaper to confirm individually
      await this.confirmSingle(actionHashes[0]);
      return;
    }

    // Request a STARK batch commitment from the Quantos L0 hub
    const starkCommitment = await this.requestStarkCommitment(batch);
    if (!starkCommitment) {
      // Fallback: confirm individually if STARK generation fails
      console.warn("[HybridActionRelay] STARK batch failed, falling back to individual confirms");
      for (const hash of actionHashes) {
        await this.confirmSingle(hash);
      }
      return;
    }

    try {
      const tx = await this.registry.confirmBatchStark(actionHashes, starkCommitment);
      await tx.wait();
      console.log(
        `[HybridActionRelay] batch confirmed — ${batch.length} actions, STARK ${starkCommitment}`
      );
    } catch (err) {
      console.error("[HybridActionRelay] confirmBatchStark failed:", err);
      // Retry individually on failure
      for (const hash of actionHashes) {
        await this.confirmSingle(hash);
      }
    }
  }

  private async confirmSingle(actionHash: string): Promise<void> {
    try {
      const tx = await this.registry.verifyPqcSignature(actionHash);
      await tx.wait();
      console.log(`[HybridActionRelay] confirmed single action ${actionHash}`);
    } catch (err) {
      console.error(`[HybridActionRelay] failed to confirm ${actionHash}:`, err);
    }
  }

  private async requestStarkCommitment(
    batch: PendingConfirmation[]
  ): Promise<string | null> {
    try {
      const signerInputs = batch.map((p) => ({
        publicKey: Buffer.from(p.pqcPublicKey).toString("base64"),
        message: Buffer.from(p.falconDigest).toString("base64"),
        signature: Buffer.from(p.pqcSignature).toString("base64"),
        stake: 1, // uniform weight for registry batch
      }));

      const resp = await axios.post(
        `${this.config.quantosRpcUrl}/l0/prove_pqc_batch`,
        { signers: signerInputs },
        { timeout: 30_000 }
      );

      if (resp.data?.commitment) {
        return resp.data.commitment as string;
      }
      return null;
    } catch (err) {
      console.warn("[HybridActionRelay] STARK RPC request failed:", err);
      return null;
    }
  }
}
