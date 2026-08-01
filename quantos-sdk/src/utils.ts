// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// Quantos hex utilities — QTS: prefix handling, BigInt parsing.
// ============================================================================

/** Strip the QTS: / qts: / 0x prefix from a hex string. */
export function stripPrefix(value: string): string {
  if (value.startsWith('QTS:')) return value.slice(4)
  if (value.startsWith('qts:')) return value.slice(4)
  if (value.startsWith('0x') || value.startsWith('0X')) return value.slice(2)
  return value
}

/** Add the QTS: prefix if not already present. */
export function withPrefix(value: string): string {
  if (value.startsWith('QTS:')) return value
  if (value.startsWith('qts:')) return 'QTS:' + value.slice(4)
  if (value.startsWith('0x') || value.startsWith('0X')) return 'QTS:' + value.slice(2)
  return 'QTS:' + value
}

/** Parse a QTS:-prefixed hex amount into a BigInt. */
export function qtsToBigInt(value: string): bigint {
  return BigInt('0x' + stripPrefix(value))
}

/** Format a BigInt as a QTS:-prefixed hex amount. */
export function bigIntToQts(value: bigint): string {
  return 'QTS:' + value.toString(16)
}

/** Parse a QTS:-prefixed hex number into a number (safe up to 2^53). */
export function qtsToNumber(value: string): number {
  return Number('0x' + stripPrefix(value))
}

/** Format a number as a QTS:-prefixed hex string. */
export function numberToQts(value: number): string {
  return 'QTS:' + value.toString(16)
}

/** 1 QTS in smallest units (18 decimals). */
export const QTS_DECIMALS = 18
export const ONE_QTS = 10n ** 18n

/** Format a QTS amount (BigInt) into a human-readable string with 18 decimals. */
export function formatQts(value: string | bigint, decimals = QTS_DECIMALS): string {
  const raw = typeof value === 'bigint' ? value : qtsToBigInt(value)
  const divisor = 10n ** BigInt(decimals)
  const whole = raw / divisor
  const frac = raw % divisor
  if (frac === 0n) return `${whole}.0 QTS`
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${whole}.${fracStr} QTS`
}
