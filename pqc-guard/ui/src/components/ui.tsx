'use client';

import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';
import type { ReactNode } from 'react';

export function StatCard({
  label,
  value,
  badge,
  icon,
  className,
}: {
  label: string;
  value: ReactNode;
  badge?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('card', className)}>
      <div className="flex items-center justify-between mb-2">
        <span className="label mb-0">{label}</span>
        {icon}
      </div>
      <div className="text-lg font-semibold font-mono break-all">{value}</div>
      {badge && <div className="mt-2">{badge}</div>}
    </div>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  loading,
  variant = 'primary',
  className,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  loading?: boolean;
  variant?: 'primary' | 'ghost' | 'danger';
  className?: string;
}) {
  const cls = {
    primary: 'btn-primary',
    ghost: 'btn-ghost',
    danger: 'btn-danger',
  }[variant];

  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={cn(cls, className)}
    >
      {loading && <Loader2 className="w-4 h-4 animate-spin" />}
      {children}
    </button>
  );
}

export function CopyableField({
  label,
  value,
  className,
}: {
  label: string;
  value: string;
  className?: string;
}) {
  const copy = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(value);
    }
  };
  return (
    <div className={className}>
      <label className="label">{label}</label>
      <div className="flex gap-2">
        <code className="flex-1 bg-bg-input border border-border rounded-lg px-3 py-2 text-xs font-mono break-all">
          {value || '—'}
        </code>
        {value && (
          <button onClick={copy} className="btn-ghost shrink-0 px-2">
            Copy
          </button>
        )}
      </div>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="rounded-lg bg-err/10 border border-err/20 px-4 py-3 text-sm text-err mb-4">
      {message}
    </div>
  );
}

export function SuccessBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="rounded-lg bg-ok/10 border border-ok/20 px-4 py-3 text-sm text-ok mb-4">
      {message}
    </div>
  );
}

export function PageHeader({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div className="mb-6">
      <h1 className="text-xl md:text-2xl font-bold">{title}</h1>
      {description && <p className="text-sm text-muted mt-1">{description}</p>}
    </div>
  );
}
