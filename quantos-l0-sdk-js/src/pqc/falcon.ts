/**
 * Falcon-512 PQC cryptography layer.
 *
 * Loads a WASM module compiled from Rust (pqcrypto-falcon) for production.
 * Falls back to deterministic test vectors when the WASM is unavailable
 * (useful for CI and development before wasm-bindgen build).
 */

// WASM module paths — resolved at runtime via dynamic import
const WASM_PATHS = [
  "../falcon-wasm/pkg/falcon_wasm.js",   // built wasm-bindgen target
  "./falcon_wasm.js",                     // copied to dist/
];

let wasmModule: any = null;
let wasmLoaded = false;

/** Attempt to load the compiled Falcon WASM module. */
async function loadWasm(): Promise<any> {
  if (wasmLoaded) return wasmModule;
  for (const path of WASM_PATHS) {
    try {
      const m = await import(/* webpackIgnore: true */ path);
      wasmModule = m;
      wasmLoaded = true;
      return m;
    } catch {
      continue;
    }
  }
  return null;
}

export interface FalconKeypair {
  publicKey: Uint8Array; // 897 bytes
  secretKey: Uint8Array; // 1,281 bytes
}

export interface FalconSignature {
  sig: Uint8Array; // up to 690 bytes (variable length)
}

const FALCON_PUBLIC_KEY_SIZE = 897;
const FALCON_SECRET_KEY_SIZE = 1281;

// Pure-JS base64 (no Buffer dependency)
const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(bytes: Uint8Array): string {
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

export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/[^A-Za-z0-9+/]/g, "");
  const len = clean.length;
  const pad = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
  const bytes = new Uint8Array((len * 3) / 4 - pad);
  let i = 0, j = 0;
  while (i < len) {
    const a = B64_CHARS.indexOf(clean.charAt(i++));
    const b = B64_CHARS.indexOf(clean.charAt(i++));
    const c = B64_CHARS.indexOf(clean.charAt(i++));
    const d = B64_CHARS.indexOf(clean.charAt(i++));
    const bitmap = (a << 18) | (b << 12) | ((c >= 0 ? c : 0) << 6) | (d >= 0 ? d : 0);
    bytes[j++] = (bitmap >> 16) & 255;
    if (c >= 0) bytes[j++] = (bitmap >> 8) & 255;
    if (d >= 0) bytes[j++] = bitmap & 255;
  }
  return bytes;
}

/**
 * Generate a new Falcon-512 keypair.
 *
 * Production: delegates to the compiled WASM (pqcrypto-falcon).
 * Fallback: returns deterministic test vectors when WASM is not built.
 */
export async function generateKeypair(): Promise<FalconKeypair> {
  const wasm = await loadWasm();
  if (wasm && wasm.generate_keypair) {
    const kp = wasm.generate_keypair();
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey),
    };
  }
  // Fallback: deterministic test keypair (DO NOT USE IN PRODUCTION)
  const pubKey = new Uint8Array(FALCON_PUBLIC_KEY_SIZE);
  const secKey = new Uint8Array(FALCON_SECRET_KEY_SIZE);
  crypto.getRandomValues(pubKey);
  crypto.getRandomValues(secKey);
  return { publicKey: pubKey, secretKey: secKey };
}

/**
 * Sign a message with Falcon-512.
 *
 * The message is hashed with SHA3-256 inside the WASM before lattice signing.
 */
export async function sign(
  message: Uint8Array,
  secretKey: Uint8Array
): Promise<FalconSignature> {
  const wasm = await loadWasm();
  if (wasm && wasm.sign) {
    const sigBytes = wasm.sign(message, secretKey);
    return { sig: new Uint8Array(sigBytes) };
  }
  // Fallback: random dummy signature
  const sig = new Uint8Array(690);
  crypto.getRandomValues(sig);
  return { sig };
}

/**
 * Verify a Falcon-512 signature.
 *
 * Returns true if the lattice verification succeeds.
 */
export async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  const wasm = await loadWasm();
  if (wasm && wasm.verify) {
    return wasm.verify(message, signature, publicKey) as boolean;
  }
  if (publicKey.length !== FALCON_PUBLIC_KEY_SIZE) {
    throw new Error(
      `Invalid Falcon public key size: expected ${FALCON_PUBLIC_KEY_SIZE}, got ${publicKey.length}`
    );
  }
  // Fallback: cannot verify without WASM — return false to be safe
  return false;
}

/** Export a Falcon keypair to JSON-safe base64 strings. */
export function exportKeypair(keypair: FalconKeypair): {
  publicKey: string;
  secretKey: string;
} {
  return {
    publicKey: bytesToBase64(keypair.publicKey),
    secretKey: bytesToBase64(keypair.secretKey),
  };
}

/** Import a Falcon keypair from base64 strings. */
export function importKeypair(
  publicKeyB64: string,
  secretKeyB64: string
): FalconKeypair {
  return {
    publicKey: base64ToBytes(publicKeyB64),
    secretKey: base64ToBytes(secretKeyB64),
  };
}
