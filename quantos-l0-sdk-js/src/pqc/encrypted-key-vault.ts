/**
 * EncryptedKeyVault — AES-256-GCM encrypted storage for the Falcon-512 secret key.
 *
 * Problem it solves: if an attacker steals the ECDSA seed phrase, they get
 * access to the EVM account but NOT the Falcon secret key — because it is
 * encrypted with a separate PIN that never touches the seed phrase flow.
 *
 * The vault uses the Web Crypto API (browser-native, zero deps):
 *   - PBKDF2 key derivation (100 000 iterations, SHA-256)
 *   - AES-256-GCM encryption
 *   - Random 16-byte salt + 12-byte IV per seal operation
 *
 * Storage is pluggable: pass a custom `VaultStorage` for React Native,
 * Node.js (fs), or hardware enclaves. Default uses `localStorage`.
 */

export interface VaultStorage {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export interface SealedVault {
  salt: string;   // hex
  iv: string;     // hex
  ciphertext: string; // hex
  version: number;
}

const VAULT_VERSION = 1;
const PBKDF2_ITERATIONS = 100_000;
const STORAGE_KEY = "quantos_falcon_vault_v1";

// ── Default storage: localStorage (browser) ──────────────────────────────────

const localStorageAdapter: VaultStorage = {
  get: (key) => (typeof localStorage !== "undefined" ? localStorage.getItem(key) : null),
  set: (key, value) => { if (typeof localStorage !== "undefined") localStorage.setItem(key, value); },
  remove: (key) => { if (typeof localStorage !== "undefined") localStorage.removeItem(key); },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function deriveKey(
  pin: string,
  salt: Uint8Array,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    usage
  );
}

// ── EncryptedKeyVault ────────────────────────────────────────────────────────

export class EncryptedKeyVault {
  private readonly storage: VaultStorage;
  private readonly storageKey: string;

  constructor(storage: VaultStorage = localStorageAdapter, storageKey = STORAGE_KEY) {
    this.storage = storage;
    this.storageKey = storageKey;
  }

  /**
   * Encrypt and persist the Falcon secret key with `pin`.
   *
   * The PIN is NOT the ECDSA seed phrase — it should be a separate,
   * short memorable passphrase (6+ chars). Even if the seed phrase is
   * compromised, the Falcon secret key remains protected.
   *
   * @param secretKey  Raw Falcon-512 secret key bytes
   * @param pin        User-chosen PIN (never stored; used only to derive AES key)
   */
  async seal(secretKey: Uint8Array, pin: string): Promise<void> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveKey(pin, salt, ["encrypt"]);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      secretKey
    );

    const vault: SealedVault = {
      salt: toHex(salt),
      iv: toHex(iv),
      ciphertext: toHex(new Uint8Array(ciphertext)),
      version: VAULT_VERSION,
    };
    this.storage.set(this.storageKey, JSON.stringify(vault));
  }

  /**
   * Decrypt and return the Falcon secret key.
   *
   * @param pin  Same PIN used during `seal()`
   * @throws     If PIN is wrong (AES-GCM auth tag fails) or vault not found
   */
  async unseal(pin: string): Promise<Uint8Array> {
    const raw = this.storage.get(this.storageKey);
    if (!raw) throw new Error("No Falcon vault found. Call seal() first.");

    const vault: SealedVault = JSON.parse(raw);
    if (vault.version !== VAULT_VERSION) {
      throw new Error(`Vault version mismatch: expected ${VAULT_VERSION}, got ${vault.version}`);
    }

    const salt = fromHex(vault.salt);
    const iv = fromHex(vault.iv);
    const ciphertext = fromHex(vault.ciphertext);

    const aesKey = await deriveKey(pin, salt, ["decrypt"]);
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        ciphertext
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new Error("Vault decryption failed: wrong PIN or corrupted data.");
    }
  }

  /**
   * Check whether a sealed vault exists in storage.
   */
  exists(): boolean {
    return this.storage.get(this.storageKey) !== null;
  }

  /**
   * Permanently delete the sealed vault from storage.
   * Call this only after confirming the key has been backed up elsewhere.
   */
  destroy(): void {
    this.storage.remove(this.storageKey);
  }

  /**
   * Export the raw SealedVault blob (for backup to server / QR code).
   * The blob is safe to store anywhere — it cannot be decrypted without the PIN.
   */
  export(): SealedVault | null {
    const raw = this.storage.get(this.storageKey);
    return raw ? (JSON.parse(raw) as SealedVault) : null;
  }

  /**
   * Import a previously exported SealedVault blob.
   * Useful for cross-device restore: user imports blob + enters PIN.
   */
  import(vault: SealedVault): void {
    this.storage.set(this.storageKey, JSON.stringify(vault));
  }
}

// ── SDK helpers on HybridWallet ──────────────────────────────────────────────

/**
 * Compute the on-chain commitment for `commitPqcKey()`.
 *
 * @param publicKey  Raw Falcon-512 public key bytes
 * @param salt       Random bytes32 (keep secret until reveal)
 * @returns          bytes32 hex string to pass to commitPqcKey()
 */
export async function buildPqcCommitment(
  publicKey: Uint8Array,
  salt: Uint8Array
): Promise<string> {
  const combined = new Uint8Array(publicKey.length + salt.length);
  combined.set(publicKey, 0);
  combined.set(salt, publicKey.length);
  const hashBuf = await crypto.subtle.digest("SHA-256", combined);
  return "0x" + toHex(new Uint8Array(hashBuf));
}

/**
 * Generate a cryptographically random bytes32 salt for the commitment.
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}
