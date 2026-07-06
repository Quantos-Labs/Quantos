/**
 * Quantos ABI Encoding — Solang/Polkadot convention
 * 
 * KEY: uint256 uses LITTLE-ENDIAN, addresses are 32 bytes.
 */

const { keccak256 } = require('js-sha3');

/**
 * Compute 4-byte Keccak-256 function selector.
 */
function computeSelector(signature) {
  const hash = keccak256(signature);
  return hash.slice(0, 8);
}

/**
 * Encode uint256 as 32 bytes LE (Solang/Polkadot).
 */
function encodeUint256LE(value) {
  const buf = Buffer.alloc(32);
  let n = BigInt(value);
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return buf;
}

/**
 * Decode 32-byte LE uint256 to BigInt.
 */
function decodeUint256LE(buf) {
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(buf[i]);
  }
  return n;
}

/**
 * Encode address as 32 bytes.
 */
function encodeAddress(addr) {
  const cleaned = addr.replace(/^(QTS:|0x)/, '');
  const bytes = Buffer.from(cleaned, 'hex');
  const buf = Buffer.alloc(32);
  bytes.copy(buf, 0, 0, Math.min(32, bytes.length));
  return buf;
}

/**
 * Encode bool as 32 bytes LE.
 */
function encodeBool(val) {
  const buf = Buffer.alloc(32);
  buf[0] = val ? 1 : 0;
  return buf;
}

/**
 * Encode a single arg by Solidity type.
 */
function encodeArg(type, value) {
  const t = type.toLowerCase();
  if (t === 'bool') return encodeBool(value === 'true' || value === '1' || value === true);
  if (t === 'address') return encodeAddress(String(value));
  if (t.startsWith('uint') || t.startsWith('int')) return encodeUint256LE(value);
  if (t.startsWith('bytes') && !t.includes('[]')) {
    const cleaned = String(value).replace(/^0x/, '');
    const bytes = Buffer.from(cleaned, 'hex');
    const buf = Buffer.alloc(32);
    bytes.copy(buf, 0, 0, Math.min(32, bytes.length));
    return buf;
  }
  // Fallback: uint256
  try { return encodeUint256LE(value); } catch {}
  const cleaned = String(value).replace(/^0x/, '');
  return Buffer.from(cleaned.padEnd(64, '0'), 'hex');
}

/**
 * Build calldata: 4-byte selector + encoded args.
 */
function buildCalldata(selectorHex, args) {
  const selector = Buffer.from(selectorHex.replace(/^0x/, ''), 'hex');
  const parts = [selector];
  for (const { type, value } of args) {
    parts.push(encodeArg(type, value));
  }
  return '0x' + Buffer.concat(parts).toString('hex');
}

/**
 * Decode return data.
 */
function decodeReturnData(hexData, type) {
  const buf = Buffer.from(hexData.replace(/^0x/, ''), 'hex');
  if (buf.length === 0) return '(empty)';
  if (buf.length === 1) return buf[0] ? 'true' : 'false';
  if (buf.length === 32) {
    if (type === 'address') return 'QTS:' + buf.toString('hex');
    return decodeUint256LE(buf).toString();
  }
  return 'QTS:' + buf.toString('hex');
}

module.exports = {
  computeSelector,
  encodeUint256LE,
  decodeUint256LE,
  encodeAddress,
  encodeBool,
  encodeArg,
  buildCalldata,
  decodeReturnData,
};
