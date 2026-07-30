import type { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  const routes = ['', '/migrate', '/execute', '/attest', '/recover', '/slash'];
  const base = 'https://guardian.quantos.xyz';
  return routes.map((r) => ({
    url: `${base}${r}`,
    lastModified: new Date(),
    changeFrequency: 'weekly' as const,
    priority: r === '' ? 1.0 : 0.8,
  }));
}
