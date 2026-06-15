// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Quantos Whitepaper',
  tagline: 'Post-Quantum Layer 1 Blockchain — Complete Technical Specification',
  favicon: 'img/logo.png',

  future: { v4: true },

  url: 'https://whitepaper.quantos.tech',
  baseUrl: '/',

  organizationName: 'Wayleyy',
  projectName: 'quantos-audit',

  onBrokenLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  plugins: [
    './plugins/remove-docusaurus-meta',
  ],

  presets: [
    [
      'classic',
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  headTags: [
    {
      tagName: 'meta',
      attributes: {
        name: 'generator',
        content: 'Quantos Whitepaper',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:site_name',
        content: 'Quantos Whitepaper',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:description',
        content: 'Quantos Technical Whitepaper — Post-Quantum Layer 1 Blockchain with Zero-Gas Execution, Dynamic Sharding, and Cryptographic Cross-Chain Finality.',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:image',
        content: 'https://whitepaper.quantos.tech/img/quantos-social-card.png',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'twitter:card',
        content: 'summary_large_image',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'twitter:title',
        content: 'Quantos Whitepaper',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'twitter:description',
        content: 'Quantos Technical Whitepaper — Post-Quantum Layer 1 Blockchain with Zero-Gas Execution, Dynamic Sharding, and Cryptographic Cross-Chain Finality.',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'twitter:image',
        content: 'https://whitepaper.quantos.tech/img/quantos-social-card.png',
      },
    },
  ],

  themeConfig:
    ({
      image: 'img/quantos-social-card.png',
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'Quantos Whitepaper',
        logo: {
          alt: 'Quantos Logo',
          src: 'img/logo.png',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Whitepaper',
          },
          {
            href: 'https://github.com/Wayleyy/quantos-audit',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://docs.quantos.tech',
            label: 'Docs',
            position: 'right',
          },
          {
            href: 'https://lightpaper.quantos.tech',
            label: 'Lightpaper',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Resources',
            items: [
              { label: 'Documentation', href: 'https://docs.quantos.tech' },
              { label: 'Lightpaper', href: 'https://lightpaper.quantos.tech' },
              { label: 'GitHub', href: 'https://github.com/Wayleyy/quantos-audit' },
            ],
          },
          {
            title: 'Ecosystem',
            items: [
              { label: 'Quantos', href: 'https://quantos.tech' },
              { label: 'Vybss', href: 'https://vybss.com' },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Quantos Labs.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
      },
    }),
};

export default config;
