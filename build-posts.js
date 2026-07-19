// Genera blog/<id>.html por cada post en data.js
// No requiere dependencias externas; usa marked vía CDN en tiempo de carga del navegador.
const fs = require('fs');
const path = require('path');

const dataJs = fs.readFileSync(path.join(__dirname, 'data.js'), 'utf-8');
// Extraer el array POSTS evaluándolo en un contexto aislado simple
const match = dataJs.match(/const POSTS = (\[[\s\S]*\]);/);
if (!match) {
  console.error('No se pudo encontrar POSTS en data.js');
  process.exit(1);
}
const POSTS = JSON.parse(match[1].replace(/\\\n/g, '\\n'));

const outDir = path.join(__dirname, 'blog-pages');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function template(post, index) {
  const idx = String(index + 1).padStart(2, '0');
  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(post.titleEs)} — Thomas Campos</title>
  <meta name="description" content="${escapeHtml(post.excerptEs)}" />
  <link rel="icon" type="image/png" href="../Media/avatar.png" />

  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400..800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />

  <link rel="stylesheet" href="../style.css" />
  <link rel="stylesheet" href="post.css" />
</head>
<body class="post-body">

  <header class="post-header">
    <div class="nav-inner">
      <a href="../index.html#ctfs" class="post-back">
        <svg viewBox="0 0 24 24" fill="none"><path d="M15 18l-6-6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span data-i18n="post.back">Volver a Write-ups</span>
      </a>
      <div class="lang-toggle">
        <button class="lang-btn active" data-lang="es">ES</button>
        <button class="lang-btn" data-lang="en">EN</button>
      </div>
    </div>
  </header>

  <main class="post-main">
    <div class="post-meta-row">
      <span class="post-category">${escapeHtml(post.category)}</span>
      <span class="post-date">${escapeHtml(post.date)}</span>
    </div>
    <h1 class="post-title" id="postTitle">${escapeHtml(post.titleEs)}</h1>
    <div class="post-content" id="postContent"></div>

    <div class="post-footer-nav">
      <a href="../index.html#ctfs" class="post-back">
        <svg viewBox="0 0 24 24" fill="none"><path d="M15 18l-6-6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span data-i18n="post.back">Volver a Write-ups</span>
      </a>
    </div>
  </main>

  <footer>
    <p data-i18n="footer.copy">© 2026 Thomas Campos.</p>
  </footer>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/9.1.6/marked.min.js"></script>
  <script src="../data.js"></script>
  <script src="post.js"></script>
  <script>renderPost('${post.id}');</script>
</body>
</html>
`;
}

POSTS.forEach((post, i) => {
  const html = template(post, i);
  fs.writeFileSync(path.join(outDir, `${post.id}.html`), html, 'utf-8');
  console.log('Generado:', `blog-pages/${post.id}.html`);
});
