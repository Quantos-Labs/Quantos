import type { Metadata } from 'next';
import './globals.css';
import { Sidebar } from '@/components/Sidebar';
import { Header } from '@/components/Header';
import { ConfigProvider } from '@/components/ConfigProvider';
import { WalletProvider } from '@/lib/wallet';

export const metadata: Metadata = {
  title: 'Guardian — Post-Quantum Smart Account Dashboard',
  description: 'Guardian secures digital assets across 10+ blockchains with post-quantum cryptography (SLH-DSA), WOTS attestations, and M-of-N quorum verification. Multi-VM support for EVM, Sui, Aptos, Solana, NEAR, Stellar, Bitcoin/Stacks, Canton, and ICP.',
  keywords: [
    'Guardian',
    'post-quantum cryptography',
    'SLH-DSA',
    'WOTS',
    'Winternitz signature',
    'quantum-resistant',
    'smart account',
    'multi-chain',
    'multi-VM',
    'blockchain security',
    'attestation',
    'M-of-N quorum',
    'EVM',
    'Sui',
    'Aptos',
    'Solana',
    'NEAR',
    'Stellar',
    'Canton',
    'ICP',
    'Bitcoin Stacks',
    'Tron',
    'quantum-safe wallet',
    'PQC migration',
  ],
  authors: [{ name: 'Quantos Labs SAS' }],
  openGraph: {
    title: 'Guardian — Post-Quantum Smart Account Dashboard',
    description: 'Quantum-resistant smart accounts with multi-chain attestation verification. Secure your assets across EVM, Sui, Aptos, Solana, NEAR, Stellar, and more.',
    type: 'website',
    siteName: 'Guardian',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Guardian — Post-Quantum Smart Account Dashboard',
    description: 'Quantum-resistant smart accounts with multi-chain attestation verification.',
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <ConfigProvider>
          <WalletProvider>
            <div className="flex min-h-screen">
              <Sidebar />
              <div className="flex-1 flex flex-col min-w-0">
                <Header />
                <main className="flex-1 p-4 md:p-6 lg:p-8 max-w-7xl mx-auto w-full">
                  {children}
                </main>
              </div>
            </div>
          </WalletProvider>
        </ConfigProvider>
      </body>
    </html>
  );
}
