// ── Quantos Wallet Crypto ──
// PIN-based encryption/decryption using Web Crypto API (AES-256-GCM + PBKDF2)

const PBKDF2_ITERATIONS = 100_000
const SALT_LENGTH = 16
const IV_LENGTH = 12

/**
 * Derive an AES-256-GCM key from a PIN using PBKDF2.
 */
async function deriveKey(pin: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

/**
 * Encrypt data with a PIN. Returns base64-encoded string containing:
 * [16 bytes salt][12 bytes IV][ciphertext]
 */
export async function encryptWithPin(data: string, pin: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const key = await deriveKey(pin, salt)

  const encoder = new TextEncoder()
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  )

  // Combine: salt + iv + ciphertext
  const combined = new Uint8Array(SALT_LENGTH + IV_LENGTH + encrypted.byteLength)
  combined.set(salt, 0)
  combined.set(iv, SALT_LENGTH)
  combined.set(new Uint8Array(encrypted), SALT_LENGTH + IV_LENGTH)

  return btoa(String.fromCharCode(...combined))
}

/**
 * Decrypt data with a PIN. Expects base64-encoded string from encryptWithPin.
 * Throws if PIN is wrong.
 */
export async function decryptWithPin(encryptedBase64: string, pin: string): Promise<string> {
  const combined = Uint8Array.from(atob(encryptedBase64), (c) => c.charCodeAt(0))

  const salt = combined.slice(0, SALT_LENGTH)
  const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
  const ciphertext = combined.slice(SALT_LENGTH + IV_LENGTH)

  const key = await deriveKey(pin, salt)

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    )
    return new TextDecoder().decode(decrypted)
  } catch {
    throw new Error('Invalid PIN')
  }
}
