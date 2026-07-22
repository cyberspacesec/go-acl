/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    'intro',
    'architecture',
    {
      type: 'category',
      label: '快速开始',
      items: ['quickstart/installation', 'quickstart/domain-acl', 'quickstart/ip-acl', 'quickstart/middleware'],
    },
    {
      type: 'category',
      label: '领域指南',
      items: ['guides/domain-matching', 'guides/ip-matching', 'guides/predefined-sets', 'guides/json-policy'],
    },
    {
      type: 'category',
      label: 'API 参考',
      items: ['api/types', 'api/manager', 'api/domain', 'api/ip', 'api/config'],
    },
    'faq',
  ],
};

module.exports = sidebars;