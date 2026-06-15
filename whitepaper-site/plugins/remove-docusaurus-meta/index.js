module.exports = function removeDocusaurusMeta(context, options) {
  return {
    name: 'remove-docusaurus-meta',
    postBuild({siteConfig, routesPaths, outDir}) {
      const fs = require('fs');
      const path = require('path');

      function walk(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(fullPath);
          } else if (entry.isFile() && entry.name.endsWith('.html')) {
            let html = fs.readFileSync(fullPath, 'utf-8');
            html = html.replace(/<meta name="?generator"? content="Docusaurus[^"]*"\s*\/?>\s*/gi, '');
            fs.writeFileSync(fullPath, html, 'utf-8');
          }
        }
      }

      walk(outDir);
    },
  };
};
