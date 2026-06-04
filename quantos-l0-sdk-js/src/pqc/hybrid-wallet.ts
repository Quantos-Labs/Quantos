/**
 * HybridWallet — PQC-ready signer for any L1 chain.
 *
 * Every account holds two keypairs:
 * 1. A classical keypair (ECDSA secp256k1) compatible with Ethereum/EVM
 * 2. A post-quantum keypair (Falcon-512) stored locally (IndexedDB / Worker)
 *
 * Transactions are signed with BOTH algorithms:
 *  - ECDSA: verified natively by the L1 chain
 *  - Falcon-512: stored in PQCSignatureRegistry, confirmed by Quantos L0 validators
 *
 * v1.1:
 *  - Domain-separated Falcon digest (anti cross-chain replay)
 *  - Browser wallet mode: ECDSA delegated to window.ethereum (MetaMask/Rabby)
 *    → private key never exposed to the app
 *  - Key rotation helper (rotatePqcKey)
 *  - Falcon secret key stored in a WebWorker context when possible
 */

import { ethers } from "ethers";
import * as falcon from "./falcon";
import { bytesToBase64, base64ToBytes } from "./falcon";
import type { FalconKeypair, FalconSignature } from "./falcon";

/** PQC identity metadata stored alongside the classical address */
export interface PqcIdentity {
  publicKey: string; // base64-encoded Falcon pubkey
  algo: "Falcon512" | "Dilithium3";
  registeredAt: number;
}

/** A hybrid-signed payload ready for submission */
export interface HybridSignature {
  payloadHash: string;    // hex(keccak256(payload))
  falconDigest: string;   // hex(keccak256(domainSeparator || actor || payloadHash || nonce))
  ecdsaSig: string;       // ECDSA sig over payloadHash (eth_sign format)
  pqcSig: string;         // base64-encoded Falcon signature over falconDigest
  nonce: number;          // account nonce used in actionHash derivation
  chainId: number;        // chain the action targets (for cross-chain replay protection)
  registryAddress: string; // contract address used in domain separator
}

export interface HybridWalletConfig {
  /**
   * EVM private key (hex, 32 bytes).
   * Leave empty when using browser wallet mode (window.ethereum).
   */
  evmPrivateKey?: string;
  /** Optional pre-existing Falcon keypair. If omitted, a new one is generated. */
  falconKeypair?: falcon.FalconKeypair;
  /** Chain ID for ECDSA signing (e.g. 8453 for Base mainnet) */
  chainId: number;
  /**
   * Address of the PQCSignatureRegistry contract on this chain.
   * Required for correct domain-separated Falcon digests.
   */
  registryAddress: string;
  /**
   * Optional ethers.Signer for browser wallet mode (MetaMask/Rabby).
   * When provided, evmPrivateKey is ignored for ECDSA signing.
   */
  browserSigner?: ethers.Signer;
}

// ── Domain Separation ───────────────────────────────────────────────────────

const DOMAIN_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes("QuantosPQC(uint256 chainId,address registry)")
);

/**
 * Compute the domain separator matching PQCSignatureRegistry.DOMAIN_SEPARATOR.
 * Must match the on-chain value exactly.
 */
export function computeDomainSeparator(chainId: number, registryAddress: string): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address"],
      [DOMAIN_TYPEHASH, chainId, registryAddress]
    )
  );
}

/**
 * Compute the domain-separated digest that Falcon must sign.
 * Matches PQCSignatureRegistry.falconDigest(actor, payloadHash, nonce).
 */
export function computeFalconDigest(
  domainSeparator: string,
  actor: string,
  payloadHash: string,
  nonce: number
): Uint8Array {
  const digest = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "bytes32", "uint256"],
      [domainSeparator, actor, payloadHash, nonce]
    )
  );
  return ethers.getBytes(digest);
}

// ── HybridWallet ────────────────────────────────────────────────────────────

export class HybridWallet {
  private _evmSigner: ethers.Wallet | null;
  private _browserSigner: ethers.Signer | null;
  private falconKeypair: FalconKeypair;
  private chainId: number;
  private registryAddress: string;
  private domainSeparator: string;

  constructor(config: HybridWalletConfig) {
    this.chainId = config.chainId;
    this.registryAddress = config.registryAddress;
    this.domainSeparator = computeDomainSeparator(config.chainId, config.registryAddress);

    // Browser mode: delegate ECDSA to MetaMask/Rabby
    if (config.browserSigner) {
      this._browserSigner = config.browserSigner;
      this._evmSigner = null;
    } else if (config.evmPrivateKey) {
      this._evmSigner = new ethers.Wallet(config.evmPrivateKey);
      this._browserSigner = null;
    } else {
      throw new Error("HybridWallet: provide evmPrivateKey or browserSigner");
    }

    this.falconKeypair = config.falconKeypair ?? {
      publicKey: new Uint8Array(0),
      secretKey: new Uint8Array(0),
    };
  }

  /**
   * Create a HybridWallet connected to the browser wallet (MetaMask/Rabby).
   * The ECDSA private key never leaves the wallet extension.
   */
  static async fromBrowserWallet(
    chainId: number,
    registryAddress: string,
    falconKeypair?: FalconKeypair
  ): Promise<HybridWallet> {
    if (typeof window === "undefined" || !(window as any).ethereum) {
      throw new Error("No browser wallet found (window.ethereum is undefined)");
    }
    const provider = new ethers.BrowserProvider((window as any).ethereum);
    const signer = await provider.getSigner();
    return new HybridWallet({ browserSigner: signer, chainId, registryAddress, falconKeypair });
  }

  /** Generate Falcon keypair if not already present. Must be awaited before any signing. */
  async init(): Promise<void> {
    if (this.falconKeypair.publicKey.length === 0) {
      this.falconKeypair = await falcon.generateKeypair();
    }
  }

  /** The EVM address derived from the active signer */
  async getEvmAddress(): Promise<string> {
    if (this._browserSigner) return this._browserSigner.getAddress();
    return this._evmSigner!.address;
  }

  /** @deprecated Use getEvmAddress() — kept for backwards compat with non-browser mode */
  get evmAddress(): string {
    if (this._evmSigner) return this._evmSigner.address;
    throw new Error("Use getEvmAddress() in browser wallet mode");
  }

  /** The raw Falcon-512 public key bytes */
  get falconPublicKey(): Uint8Array {
    return this.falconKeypair.publicKey;
  }

  /** Base64-encoded Falcon public key for on-chain registration */
  get falconPublicKeyBase64(): string {
    return bytesToBase64(this.falconKeypair.publicKey);
  }

  /** Export the Falcon identity for backup / IndexedDB storage */
  exportFalconIdentity(): { falconPublicKey: string; falconSecretKey: string } {
    const exported = falcon.exportKeypair(this.falconKeypair);
    return { falconPublicKey: exported.publicKey, falconSecretKey: exported.secretKey };
  }

  /** Import a previously exported Falcon identity */
  importFalconIdentity(identity: { falconPublicKey: string; falconSecretKey: string }): void {
    this.falconKeypair = falcon.importKeypair(identity.falconPublicKey, identity.falconSecretKey);
  }

  /** Import a previously exported identity (legacy full-export format) */
  static fromExported(identity: {
    falconPublicKey: string;
    falconSecretKey: string;
    evmPrivateKey: string;
    chainId: number;
    registryAddress: string;
  }): HybridWallet {
    const falconKp = falcon.importKeypair(identity.falconPublicKey, identity.falconSecretKey);
    return new HybridWallet({
      evmPrivateKey: identity.evmPrivateKey,
      falconKeypair: falconKp,
      chainId: identity.chainId,
      registryAddress: identity.registryAddress,
    });
  }

  /**
   * Sign an arbitrary payload with both ECDSA and Falcon-512.
   *
   * The Falcon signature covers a domain-separated digest:
   *   keccak256(DOMAIN_SEPARATOR || actor || payloadHash || nonce)
   * This prevents cross-chain replay: the same Falcon sig is invalid on
   * a different chain or a different registry contract.
   *
   * @param payload Raw bytes or string to sign
   * @param nonce Account-specific nonce (fetch from contract: nonces[actor])
   * @returns HybridSignature ready for submitHybridAction on-chain
   */
  async signPayload(payload: string | Uint8Array, nonce: number): Promise<HybridSignature> {
    await this.init();

    const actor = await this.getEvmAddress();
    const payloadBytes = typeof payload === "string" ? ethers.toUtf8Bytes(payload) : payload;
    const payloadHash = ethers.keccak256(payloadBytes);

    // ECDSA over payloadHash — delegated to browser wallet or local key
    const ecdsaSig = this._browserSigner
      ? await this._browserSigner.signMessage(ethers.getBytes(payloadHash))
      : await this._evmSigner!.signMessage(ethers.getBytes(payloadHash));

    // Falcon-512 over domain-separated digest (anti cross-chain replay)
    const falconDigestBytes = computeFalconDigest(this.domainSeparator, actor, payloadHash, nonce);
    const falconSig: FalconSignature = await falcon.sign(falconDigestBytes, this.falconKeypair.secretKey);
    const falconDigestHex = ethers.hexlify(falconDigestBytes);

    return {
      payloadHash,
      falconDigest: falconDigestHex,
      ecdsaSig,
      pqcSig: bytesToBase64(falconSig.sig),
      nonce,
      chainId: this.chainId,
      registryAddress: this.registryAddress,
    };
  }

  /**
   * Build and sign an EVM transaction with hybrid PQC backing.
   * In browser mode the EVM tx is signed by MetaMask; Falcon stays local.
   *
   * @param tx The unsigned EVM transaction
   * @param nonce Registry nonce (separate from EVM tx nonce)
   */
  async signEvmTransaction(
    tx: ethers.TransactionRequest,
    nonce: number
  ): Promise<{ evmTx: string; hybridSig: HybridSignature }> {
    if (this._browserSigner) {
      throw new Error(
        "signEvmTransaction is not available in browser wallet mode. " +
        "Use provider.getSigner().sendTransaction(tx) for the EVM tx, " +
        "then call signPayload(txHash, nonce) for the hybrid PQC envelope."
      );
    }
    const evmTx = await this._evmSigner!.signTransaction(tx);
    const payload = ethers.toUtf8Bytes(evmTx);
    const hybridSig = await this.signPayload(payload, nonce);
    return { evmTx, hybridSig };
  }

  /**
   * Helper: initiate a Falcon key rotation on-chain.
   * Returns the encoded calldata for rotatePqcKey(newPublicKey).
   * The caller is responsible for sending the EVM transaction.
   */
  async buildKeyRotationCalldata(newFalconKeypair: FalconKeypair): Promise<string> {
    const abi = ["function rotatePqcKey(bytes calldata newPublicKey) external"];
    const iface = new ethers.Interface(abi);
    return iface.encodeFunctionData("rotatePqcKey", [newFalconKeypair.publicKey]);
  }

  /**
   * Verify that a hybrid signature was correctly formed.
   * Off-chain sanity check before on-chain submission.
   */
  async verifyOwnSignature(hybridSig: HybridSignature): Promise<boolean> {
    await this.init();
    const actor = await this.getEvmAddress();

    // Verify ECDSA
    const recovered = ethers.verifyMessage(
      ethers.getBytes(hybridSig.payloadHash),
      hybridSig.ecdsaSig
    );
    if (recovered.toLowerCase() !== actor.toLowerCase()) return false;

    // Recompute expected Falcon digest and verify it matches
    const expectedDigest = computeFalconDigest(
      this.domainSeparator,
      actor,
      hybridSig.payloadHash,
      hybridSig.nonce
    );
    if (ethers.hexlify(expectedDigest) !== hybridSig.falconDigest) return false;

    // Verify Falcon signature over the domain-separated digest
    const pqcSigBytes = base64ToBytes(hybridSig.pqcSig);
    return falcon.verify(expectedDigest, pqcSigBytes, this.falconKeypair.publicKey);
  }
}
