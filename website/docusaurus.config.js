// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
const {themes} = require('prism-react-renderer');
const lightCodeTheme = themes.github;
const darkCodeTheme = themes.dracula;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'acl-skills',
  tagline: '为 AI Agent 而生的 Go ACL 库 — SSRF 防护、域名/IP 访问控制、HTTP 中间件',
  favicon: 'img/favicon.ico',

  url: 'https://cyberspacesec.github.io',
  baseUrl: '/acl-skills/',

  organizationName: 'cyberspacesec',
  projectName: 'acl-skills',

  onBrokenLinks: 'warn',

  i18n: {
    defaultLocale: 'zh-CN',
    locales: ['zh-CN'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/cyberspacesec/acl-skills/edit/main/website/',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/logo.png',
      navbar: {
        title: 'acl-skills',
        logo: {
          alt: 'acl-skills Logo',
          src: 'img/logo.svg',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docsSidebar',
            position: 'left',
            label: '文档',
          },
          {
            href: 'https://github.com/cyberspacesec/acl-skills',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: '文档',
            items: [
              {
                label: '快速开始',
                to: '/docs/intro',
              },
              {
                label: '核心架构',
                to: '/docs/architecture',
              },
            ],
          },
          {
            title: '更多',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/cyberspacesec/acl-skills',
              },
              {
                label: 'CHANGELOG',
                href: 'https://github.com/cyberspacesec/acl-skills/blob/main/CHANGELOG.md',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} cyberspacesec. MIT License.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
      mermaid: {
        theme: {light: 'neutral', dark: 'dark'},
      },
    }),

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themes: ['@docusaurus/theme-mermaid'],
};

module.exports = config;
