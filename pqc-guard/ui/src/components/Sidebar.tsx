'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  ArrowRightLeft,
  Send,
  PenTool,
  ShieldAlert,
  LifeBuoy,
  ShieldCheck,
} from 'lucide-react';

const NAV = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/migrate', label: 'Migration', icon: ArrowRightLeft },
  { href: '/execute', label: 'Execute', icon: Send },
  { href: '/attest', label: 'Attestor Sign', icon: PenTool },
  { href: '/recover', label: 'Recovery', icon: LifeBuoy },
  { href: '/slash', label: 'Slashing', icon: ShieldAlert },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-16 md:w-60 shrink-0 border-r border-border bg-bg-card flex flex-col">
      <div className="h-14 flex items-center gap-2 px-3 md:px-5 border-b border-border">
        <ShieldCheck className="w-6 h-6 text-accent shrink-0" />
        <span className="hidden md:inline font-bold text-sm tracking-tight">
          Guardian
        </span>
      </div>
      <nav className="flex-1 py-3 px-2 md:px-3 space-y-1">
        {NAV.map((item) => {
          const active = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-2.5 py-2 rounded-lg text-sm font-medium transition-colors',
                active
                  ? 'bg-accent/15 text-accent'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-bg-hover'
              )}
            >
              <Icon className="w-5 h-5 shrink-0" />
              <span className="hidden md:inline">{item.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="p-3 border-t border-border">
        <span className="hidden md:inline text-xs text-muted">
          TESTNET ONLY — AUDIT REQUIRED
        </span>
      </div>
    </aside>
  );
}
