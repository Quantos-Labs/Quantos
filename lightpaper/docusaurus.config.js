// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Quantos Lightpaper',
  tagline: 'Post-Quantum Layer 1 Blockchain — Technical Whitepaper',
  favicon: 'img/logo.png',

  future: {
    v4: true,
  },

  url: 'https://lightpaper.quantos.tech',
  baseUrl: '/',

  organizationName: 'Wayleyy',
  projectName: 'quantos-audit',

  onBrokenLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

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

  themeConfig:
    ({
      image: 'img/docusaurus-social-card.jpg',
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'Quantos Lightpaper',
        logo: {
          alt: 'Quantos Logo',
          src: 'img/logo.png',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Lightpaper',
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
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Resources',
            items: [
              {
                label: 'Documentation',
                href: 'https://docs.quantos.tech',
              },
              {
                label: 'GitHub',
                href: 'https://github.com/Wayleyy/quantos-audit',
              },
            ],
          },
          {
            title: 'Ecosystem',
            items: [
              {
                label: 'Quantos',
                href: 'https://quantos.tech',
              },
              {
                label: 'Vybss',
                href: 'https://vybss.com',
              },
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
