import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function shortenHash(hash: string, chars = 6): string {
  if (!hash) return '';
  if (hash.length <= chars * 2 + 2) return hash;
  return `${hash.slice(0, chars + 2)}...${hash.slice(-chars)}`;
}

export function formatTimestamp(ts: bigint | number | null | undefined): string {
  if (!ts || ts === 0n) return '—';
  const n = typeof ts === 'bigint' ? Number(ts) : ts;
  if (n === 0) return '—';
  return new Date(n * 1000).toLocaleString();
}

export function timeRemaining(deadline: bigint | number): string {
  const now = Math.floor(Date.now() / 1000);
  const target = typeof deadline === 'bigint' ? Number(deadline) : deadline;
  const diff = target - now;
  if (diff <= 0) return 'Ready';
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function idleRemaining(lastActivity: bigint | number, timeout: bigint | number): string {
  const last = typeof lastActivity === 'bigint' ? Number(lastActivity) : lastActivity;
  const tout = typeof timeout === 'bigint' ? Number(timeout) : timeout;
  const deadline = last + tout;
  const now = Math.floor(Date.now() / 1000);
  const diff = deadline - now;
  if (diff <= 0) return 'Idle — recovery available';
  const days = Math.floor(diff / 86400);
  const hours = Math.floor((diff % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const mins = Math.floor((diff % 3600) / 60);
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}
