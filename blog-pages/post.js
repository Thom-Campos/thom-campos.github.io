/* =========================================================
   POST PAGE — i18n mínimo + render de markdown
   Comparte estructura de traducciones con script.js del sitio principal
========================================================= */
const postTranslations = {
  es: {
    'post.back':   'Volver a Write-ups',
    'footer.copy': '© 2026 Thomas Campos.',
  },
  en: {
    'post.back':   'Back to Write-ups',
    'footer.copy': '© 2026 Thomas Campos.',
  }
};

let currentPostLang = 'es';
let currentPost = null;

function setPostLanguage(lang) {
  currentPostLang = lang;

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (postTranslations[lang][key] !== undefined) {
      el.textContent = postTranslations[lang][key];
    }
  });

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
  });

  document.documentElement.setAttribute('lang', lang);

  if (currentPost) renderPostContent(currentPost);
}

function renderPostContent(post) {
  const title = currentPostLang === 'es' ? post.titleEs : post.titleEn;
  const md    = currentPostLang === 'es' ? post.mdEs    : post.mdEn;

  document.getElementById('postTitle').textContent = title;
  document.title = `${title} — Thomas Campos`;

  const html = (typeof marked !== 'undefined')
    ? marked.parse(md)
    : `<pre>${md}</pre>`;
  document.getElementById('postContent').innerHTML = html;
}

function renderPost(id) {
  const post = (typeof POSTS !== 'undefined') ? POSTS.find(p => p.id === id) : null;
  if (!post) {
    document.getElementById('postContent').innerHTML = '<p>Write-up no encontrado.</p>';
    return;
  }
  currentPost = post;
  renderPostContent(post);
}

document.querySelectorAll('.lang-btn').forEach(btn => {
  btn.addEventListener('click', () => setPostLanguage(btn.getAttribute('data-lang')));
});
