/**
 * Quick unit tests for encoding module.
 */

const { computeSelector, encodeUint256LE, decodeUint256LE, encodeAddress, buildCalldata, decodeReturnData } = require('../src/encoding');

let passed = 0, failed = 0;

function assert(cond, msg) {
  if (cond) { passed++; } 
  else { failed++; console.error(`FAIL: ${msg}`); }
}

// Keccak selectors
assert(computeSelector('transfer(address,uint256)') === 'a9059cbb', 'transfer selector');
assert(computeSelector('balanceOf(address)') === '70a08231', 'balanceOf selector');
assert(computeSelector('totalSupply()') === '18160ddd', 'totalSupply selector');

// LE uint256
const enc = encodeUint256LE(1000000);
assert(enc[0] === 0x40, 'LE byte 0');
assert(enc[1] === 0x42, 'LE byte 1');
assert(enc[2] === 0x0f, 'LE byte 2');
assert(enc[3] === 0x00, 'LE byte 3');
assert(decodeUint256LE(enc) === 1000000n, 'roundtrip 1M');

const big = encodeUint256LE('115792089237316195423570985008687907853269984665640564039457584007913129639935');
assert(decodeUint256LE(big).toString() === '115792089237316195423570985008687907853269984665640564039457584007913129639935', 'max uint256');

// Address
const addr = encodeAddress('QTS:' + 'aa'.repeat(32));
assert(addr[0] === 0xaa, 'address byte 0');
assert(addr[31] === 0xaa, 'address byte 31');

// buildCalldata
const cd = buildCalldata('a9059cbb', [
  { type: 'address', value: '0x' + 'bb'.repeat(32) },
  { type: 'uint256', value: '100000' },
]);
assert(cd.startsWith('0xa9059cbb'), 'calldata starts with selector');
assert(cd.length === 2 + (4 + 32 + 32) * 2, 'calldata length = 68 bytes hex');

// decodeReturnData
assert(decodeReturnData('0x' + enc.toString('hex')) === '1000000', 'decode 1M');
assert(decodeReturnData('0x01', 'bool') === 'true', 'decode bool true');
assert(decodeReturnData('0x00', 'bool') === 'false', 'decode bool false');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
