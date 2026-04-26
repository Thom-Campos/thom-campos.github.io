/* =========================================================
   1. INTERNATIONALISATION (i18n)
========================================================= */
const translations = {
  es: {
    // Nav
    'nav.about':              'Sobre mí',
    'nav.skills':             'Habilidades',
    'nav.blog':               'Blog',
    'nav.contact':            'Contacto',
    // Hero
    'hero.greeting':          'Hola, soy',
    'hero.name':              'Thomas Campos',
    'hero.title':             'Ciberseguridad',
    'hero.subtitle':          'Estudiante de Ingeniería en Conectividad y Redes orientado a Blue Team y análisis de eventos de seguridad. Certificado por Google, Cisco y CertiProf. Competidor CTF activo.',
    'hero.badge1':            'Blue Team',
    'hero.badge2':            'SOC Nivel 1',
    'hero.cta.contact':       'Contactar',
    'hero.cta.blog':          'Ver Write-ups',
    'hero.scroll':            'scroll',
    // About
    'about.label':            'Trayectoria',
    'about.title':            'Sobre mí',
    'about.p1':               'Estudiante de Ingeniería en Conectividad y Redes en Duoc UC, con foco en ciberseguridad defensiva y análisis de seguridad. Busco iniciar mi carrera en un SOC de Nivel 1, monitoreando y respondiendo a eventos de seguridad.',
    'about.p2':               'Participé como contribuyente técnico principal en el CTF FIDAE Llaitun 2026, quedando en el top 36 de 233 participantes, resolviendo la totalidad de los desafíos de infraestructura del equipo. Experiencia práctica analizando vulnerabilidades SSL legacy, bypass SSH y escalamiento de privilegios.',
    'about.p3':               'Mi objetivo es integrar mis certificaciones, habilidades técnicas y experiencia en liderazgo estudiantil para aportar valor en equipos de seguridad, mientras continúo creciendo en el área.',
    'about.stat1':            'Certificaciones',
    'about.stat2':            'FIDAE CTF 2026',
    'about.stat3':            'Pts aportados al equipo',
    // Timeline
    'timeline.label':         'Historial',
    'timeline.title':         'Formación & Experiencia',
    'timeline.present':       'Presente',
    'timeline.job1.role':     'Alumno Ayudante',
    'timeline.job1.desc':     'Apoyo administrativo y operativo en tareas institucionales: atención al público, orientación a estudiantes, colaboración en eventos institucionales y coordinación logística.',
    'timeline.job2.role':     'Docente Voluntario · IA & Ciberseguridad',
    'timeline.job2.desc':     'Diseñé e impartí talleres prácticos de Ciberseguridad e Inteligencia Artificial en el Centro de Innovación y Transferencia Tecnológica. Planifiqué clases con enfoque 100% aplicado.',
    'timeline.edu1.uni':      'Duoc UC',
    'timeline.edu1.degree':   'Ingeniería en Conectividad y Redes',
    'timeline.edu1.desc':     'Enfoque en gestión de redes, administración de sistemas y ciberseguridad. Actividades: Docente Voluntario (CITT) y Alumno Ayudante.',
    'timeline.type.work':     'Trabajo',
    'timeline.type.edu':      'Educación',
    // Skills
    'skills.label':           'Arsenal',
    'skills.title':           'Habilidades & Herramientas',
    'skills.desc':            'Herramientas y tecnologías que utilizo para monitorear, analizar y responder a eventos de seguridad, con foco en operaciones defensivas (Blue Team / SOC).',
    'skills.cat1.title':      'Blue Team & SOC',
    'skills.cat2.title':      'Redes & Infraestructura',
    'skills.cat3.title':      'Scripting & Dev',
    // Certs
    'certs.label':            'Credenciales',
    'certs.title':            'Certificaciones',
    // Blog
    'blog.label':             'Publicaciones',
    'blog.title':             'Blog & Write-ups',
    'blog.filter.all':        'Todos',
    'blog.filter.articles':   'Artículos',
    'blog.read':              'Leer',
    // Contact
    'contact.label':          'Contacto',
    'contact.title':          'Hablemos',
    'contact.desc':           'Abierto a oportunidades en equipos de seguridad, colaboraciones técnicas y proyectos de Blue Team. Respondo a la brevedad.',
    'contact.form.name':      'Nombre',
    'contact.form.email':     'Correo electrónico',
    'contact.form.subject':   'Asunto',
    'contact.form.message':   'Mensaje',
    'contact.form.send':      'Enviar mensaje',
    // Footer
    'footer.copy':            '© 2026 Thomas Campos. Todos los derechos reservados.',
  },

  en: {
    // Nav
    'nav.about':              'About',
    'nav.skills':             'Skills',
    'nav.blog':               'Blog',
    'nav.contact':            'Contact',
    // Hero
    'hero.greeting':          "Hi, I'm",
    'hero.name':              'Thomas Campos',
    'hero.title':             'Cybersecurity',
    'hero.subtitle':          'Network & Connectivity Engineering student focused on Blue Team and security event analysis. Certified by Google, Cisco and CertiProf. Active CTF competitor.',
    'hero.badge1':            'Blue Team',
    'hero.badge2':            'SOC Level 1',
    'hero.cta.contact':       'Get in Touch',
    'hero.cta.blog':          'Read Write-ups',
    'hero.scroll':            'scroll',
    // About
    'about.label':            'Background',
    'about.title':            'About Me',
    'about.p1':               'Network & Connectivity Engineering student at Duoc UC, focused on defensive cybersecurity and security analysis. Looking to start my career in a Level 1 SOC, monitoring and responding to security events.',
    'about.p2':               'I was the main technical contributor at FIDAE Llaitun CTF 2026, ranking Top 36 out of 233 participants, solving all of my team\'s Infrastructure challenges. Hands-on experience analyzing legacy SSL vulnerabilities, SSH bypass and privilege escalation.',
    'about.p3':               'My goal is to combine my certifications, technical skills and student leadership experience to add value in security teams, while continuing to grow in the field.',
    'about.stat1':            'Certifications',
    'about.stat2':            'FIDAE CTF 2026',
    'about.stat3':            'Points contributed',
    // Timeline
    'timeline.label':         'History',
    'timeline.title':         'Education & Experience',
    'timeline.present':       'Present',
    'timeline.job1.role':     'Student Assistant',
    'timeline.job1.desc':     'Administrative and operational support: public assistance, student orientation, event collaboration and logistics coordination.',
    'timeline.job2.role':     'Volunteer Instructor · AI & Cybersecurity',
    'timeline.job2.desc':     'Designed and delivered practical workshops on Cybersecurity and Artificial Intelligence at the Center for Innovation and Technology Transfer. 100% applied approach.',
    'timeline.edu1.uni':      'Duoc UC',
    'timeline.edu1.degree':   'Network & Connectivity Engineering',
    'timeline.edu1.desc':     'Focus on network management, system administration and cybersecurity. Activities: Volunteer Instructor (CITT) and Teaching Assistant.',
    'timeline.type.work':     'Work',
    'timeline.type.edu':      'Education',
    // Skills
    'skills.label':           'Arsenal',
    'skills.title':           'Skills & Tools',
    'skills.desc':            'Tools and technologies I use to monitor, analyze and respond to security events, with a focus on defensive operations (Blue Team / SOC).',
    'skills.cat1.title':      'Blue Team & SOC',
    'skills.cat2.title':      'Networks & Infrastructure',
    'skills.cat3.title':      'Scripting & Dev',
    // Certs
    'certs.label':            'Credentials',
    'certs.title':            'Certifications',
    // Blog
    'blog.label':             'Publications',
    'blog.title':             'Blog & Write-ups',
    'blog.filter.all':        'All',
    'blog.filter.articles':   'Articles',
    'blog.read':              'Read',
    // Contact
    'contact.label':          'Contact',
    'contact.title':          "Let's Talk",
    'contact.desc':           'Open to opportunities in security teams, technical collaborations and Blue Team projects. I will respond promptly.',
    'contact.form.name':      'Name',
    'contact.form.email':     'Email address',
    'contact.form.subject':   'Subject',
    'contact.form.message':   'Message',
    'contact.form.send':      'Send message',
    // Footer
    'footer.copy':            '© 2026 Thomas Campos. All rights reserved.',
  }
};

let currentLang = 'es';

function setLanguage(lang) {
  currentLang = lang;
  localStorage.setItem('lang', lang);

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (translations[lang][key] !== undefined) {
      el.textContent = translations[lang][key];
    }
  });

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
  });

  document.documentElement.setAttribute('lang', lang);

  const placeholders = {
    es: { fName: 'Juan Pérez', fEmail: 'juan@empresa.com', fSubject: 'Oportunidad SOC Nivel 1', fMessage: 'Cuéntame sobre la oportunidad o proyecto...' },
    en: { fName: 'John Doe', fEmail: 'john@company.com', fSubject: 'SOC Level 1 Opportunity', fMessage: 'Tell me about the opportunity or project...' }
  };
  const ph = placeholders[lang];
  const fName    = document.getElementById('fName');
  const fEmail   = document.getElementById('fEmail');
  const fSubject = document.getElementById('fSubject');
  const fMessage = document.getElementById('fMessage');
  if (fName)    fName.placeholder    = ph.fName;
  if (fEmail)   fEmail.placeholder   = ph.fEmail;
  if (fSubject) fSubject.placeholder = ph.fSubject;
  if (fMessage) fMessage.placeholder = ph.fMessage;

  // Re-render blog cards in the current language
  renderBlogGrid();
}

/* =========================================================
   2. DARK MODE
========================================================= */
function toggleTheme() {
  const html   = document.documentElement;
  const isDark = html.getAttribute('data-theme') === 'dark';
  const next   = isDark ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  document.getElementById('themeIcon').textContent = next === 'dark' ? 'dark_mode' : 'light_mode';
}

/* =========================================================
   3. STICKY HEADER
========================================================= */
const header = document.getElementById('header');
window.addEventListener('scroll', () => {
  header.classList.toggle('scrolled', window.scrollY > 30);
}, { passive: true });

/* =========================================================
   4. BLOG FILTER
========================================================= */
function filterBlog(filter, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeFilter = filter;
  visibleCount = POSTS_PER_PAGE;
  renderBlogGrid();
}

function loadMorePosts() {
  visibleCount += POSTS_PER_PAGE;
  renderBlogGrid();
}

/* =========================================================
   5. CONTACT FORM — Formspree
   
   Para activar el formulario:
   1. Regístrate gratis en https://formspree.io
   2. Crea un nuevo formulario (apunta a thomas.campos.carvacho@gmail.com)
   3. Copia tu Form ID y reemplaza 'TU_FORM_ID' abajo
   ─────────────────────────────────────────────────────── */
const FORMSPREE_ID = 'xnjllrla'; // ← reemplazar, ej: 'xpwzgkjb'

async function handleFormSubmit(e) {
  e.preventDefault();

  const btn  = e.currentTarget;
  const icon = btn.querySelector('.material-symbols-outlined');
  const span = btn.querySelector('span[data-i18n]');

  // — Leer valores —
  const name    = document.getElementById('fName').value.trim();
  const email   = document.getElementById('fEmail').value.trim();
  const subject = document.getElementById('fSubject').value.trim();
  const message = document.getElementById('fMessage').value.trim();

  // — Validación básica —
  const es = currentLang === 'es';
  if (!name || !email || !message) {
    showFormFeedback(
      es ? 'Por favor completa los campos obligatorios.' : 'Please fill in all required fields.',
      'error'
    );
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    showFormFeedback(
      es ? 'Ingresa un correo electrónico válido.' : 'Please enter a valid email address.',
      'error'
    );
    return;
  }

  // — Estado: enviando —
  btn.disabled      = true;
  icon.textContent  = 'hourglass_top';
  span.textContent  = es ? 'Enviando…' : 'Sending…';
  btn.style.opacity = '0.75';

  try {
    const res = await fetch(`https://formspree.io/f/${FORMSPREE_ID}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ name, email, subject, message }),
    });

    if (res.ok) {
      // — Éxito —
      icon.textContent     = 'check_circle';
      span.textContent     = es ? 'Mensaje enviado ✓' : 'Message sent ✓';
      btn.style.background = 'var(--color-success, #10B981)';
      btn.style.boxShadow  = '0 4px 20px rgba(16,185,129,0.4)';
      btn.style.opacity    = '1';
      showFormFeedback(
        es ? '¡Mensaje enviado! Te responderé a la brevedad.' : 'Message sent! I\'ll get back to you soon.',
        'success'
      );
      // Limpiar campos
      ['fName','fEmail','fSubject','fMessage'].forEach(id => {
        document.getElementById(id).value = '';
      });
      setTimeout(resetFormBtn, 4000);
    } else {
      const data = await res.json().catch(() => ({}));
      const errMsg = data?.errors?.map(e => e.message).join(', ')
        || (es ? 'Error al enviar. Intenta de nuevo.' : 'Send error. Please try again.');
      showFormFeedback(errMsg, 'error');
      resetFormBtn();
    }
  } catch {
    showFormFeedback(
      es ? 'Sin conexión. Verifica tu internet e intenta de nuevo.' : 'No connection. Check your internet and try again.',
      'error'
    );
    resetFormBtn();
  }

  function resetFormBtn() {
    btn.disabled      = false;
    btn.style.opacity = '1';
    btn.style.background = '';
    btn.style.boxShadow  = '';
    icon.textContent  = 'send';
    span.textContent  = currentLang === 'es' ? 'Enviar mensaje' : 'Send message';
  }
}

function showFormFeedback(msg, type) {
  let fb = document.getElementById('formFeedback');
  if (!fb) {
    fb = document.createElement('p');
    fb.id = 'formFeedback';
    fb.style.cssText = 'margin-top:12px;font-size:0.875rem;border-radius:8px;padding:10px 14px;transition:opacity 0.3s;';
    document.querySelector('.form-submit').insertAdjacentElement('afterend', fb);
  }
  fb.textContent = msg;
  fb.style.opacity = '1';
  if (type === 'success') {
    fb.style.background = 'rgba(16,185,129,0.12)';
    fb.style.color      = '#10B981';
    fb.style.border     = '1px solid rgba(16,185,129,0.3)';
  } else {
    fb.style.background = 'rgba(239,68,68,0.1)';
    fb.style.color      = '#EF4444';
    fb.style.border     = '1px solid rgba(239,68,68,0.25)';
  }
  clearTimeout(fb._timer);
  fb._timer = setTimeout(() => { fb.style.opacity = '0'; }, 6000);
}

/* =========================================================
   6. MOBILE NAV
========================================================= */
function openMobileNav()  { document.getElementById('mobileNav').classList.add('open'); }
function closeMobileNav() { document.getElementById('mobileNav').classList.remove('open'); }

/* =========================================================
   7. BLOG DATA — cargado dinámicamente desde Blog/index.json
   =====================================================================
   CÓMO AÑADIR UNA ENTRADA AL BLOG:
   
   1. Crea un archivo  Blog/mi-nuevo-post.md  con tu contenido en Markdown.
   2. Abre  Blog/index.json  y agrega un nuevo objeto al array:
      {
        "id":          "mi-nuevo-post",      ← debe coincidir con el nombre del .md
        "cat":         "ctf",                ← "ctf" | "event" (artículos de largo formato)
        "dateDisplay": "May 2026",
        "icon":        "emoji_events",       ← nombre de Material Symbol
        "titleEs":     "Título en español",
        "titleEn":     "Title in English",
        "excerptEs":   "Resumen corto (es)",
        "excerptEn":   "Short summary (en)",
        "cardTags":    [{"text":"CTF","cls":"tag-osint"}],
        "articleDate": "Mayo 2026",
        "articleTags": [{"text":"CTF","cls":"tag-osint"}],
        "placeholder": false
      }
   3. ¡Listo! La tarjeta aparecerá automáticamente en el blog.
   
   Clases de color para tags:
     tag-web   → azul   tag-osint  → verde
     tag-misc  → gris   tag-tuto   → naranja
   ===================================================================== */

let POSTS = [];

async function loadPosts() {
  try {
    const res = await fetch('Blog/index.json');
    if (!res.ok) throw new Error('No se pudo cargar Blog/index.json');
    POSTS = await res.json();
  } catch (e) {
    console.warn('Blog/index.json no encontrado. ¿Estás usando un servidor local?', e);
    POSTS = [];
  }
  renderBlogGrid();
}

/* ─── Pagination state ───────────────────────────────────────────────── */
const POSTS_PER_PAGE = 6;
let visibleCount = POSTS_PER_PAGE;
let activeFilter = 'all';

/* ─── Render blog grid from POSTS array ─────────────────────────────── */
function renderBlogGrid() {
  const grid = document.getElementById('blogGrid');
  if (!grid) return;

  const lang = currentLang;

  if (POSTS.length === 0) {
    grid.innerHTML = `<p style="opacity:0.5;font-size:0.9rem;">No hay publicaciones aún.</p>`;
    return;
  }

  // Filter posts by active category
  const filtered = activeFilter === 'all'
    ? POSTS
    : POSTS.filter(p => p.cat === activeFilter);

  // Slice to current visible count
  const visible = filtered.slice(0, visibleCount);

  grid.innerHTML = visible.map(post => {
    const title   = lang === 'es' ? post.titleEs   : post.titleEn;
    const excerpt = lang === 'es' ? post.excerptEs : post.excerptEn;
    const readLbl = translations[lang]['blog.read'] || 'Leer';

    const tagsHtml = post.cardTags.map(t =>
      `<span class="blog-tag ${t.cls}">${t.text}</span>`
    ).join('');

    const placeholderBadge = post.placeholder
      ? `<div style="position:absolute;top:12px;right:12px;font-family:'IBM Plex Mono',monospace;font-size:0.6rem;font-weight:600;background:rgba(239,68,68,0.15);color:#EF4444;border:1px solid rgba(239,68,68,0.3);padding:3px 8px;border-radius:5px;letter-spacing:0.05em;">PLACEHOLDER</div>`
      : '';

    return `
      <article class="blog-card" data-cat="${post.cat}" onclick="openArticle('${post.id}')" style="position:relative;">
        ${placeholderBadge}
        <div class="blog-card-meta">
          <span class="blog-date">${post.dateDisplay}</span>
          <div class="blog-category-icon">
            <span class="material-symbols-outlined">${post.icon}</span>
          </div>
        </div>
        <h3 class="blog-title">${title}</h3>
        <p class="blog-excerpt">${excerpt}</p>
        <div class="blog-footer">
          <div class="blog-tags">${tagsHtml}</div>
          <span class="blog-read-more">
            <span>${readLbl}</span>
            <span class="material-symbols-outlined">arrow_forward</span>
          </span>
        </div>
      </article>
    `;
  }).join('');

  // Re-apply scroll observer to newly rendered cards
  applyScrollObserver(grid.querySelectorAll('.blog-card'));

  // "Show more" button
  const remaining = filtered.length - visibleCount;
  let loadMoreBtn = document.getElementById('blogLoadMore');
  if (!loadMoreBtn) {
    loadMoreBtn = document.createElement('div');
    loadMoreBtn.id = 'blogLoadMore';
    loadMoreBtn.style.cssText = 'grid-column:1/-1;display:flex;justify-content:center;margin-top:8px;';
    grid.parentElement.insertBefore(loadMoreBtn, grid.nextSibling);
  }

  if (remaining > 0) {
    const es = currentLang === 'es';
    loadMoreBtn.innerHTML = `
      <button onclick="loadMorePosts()" style="
        display:flex;align-items:center;gap:8px;
        padding:12px 28px;border-radius:10px;border:1px solid var(--border);
        background:var(--card-bg);color:var(--text-primary);
        font-family:inherit;font-size:0.9rem;font-weight:500;cursor:pointer;
        transition:border-color 0.2s,background 0.2s;">
        <span class="material-symbols-outlined" style="font-size:18px;">expand_more</span>
        ${es ? `Ver ${remaining} más` : `Load ${remaining} more`}
      </button>`;
  } else {
    loadMoreBtn.innerHTML = '';
  }
}

/* =========================================================
   8. ARTICLE MODAL — carga el .md desde Blog/{id}.md
========================================================= */
async function openArticle(id) {
  const post = POSTS.find(p => p.id === id);
  if (!post) return;

  const lang  = currentLang;
  const title = lang === 'es' ? post.titleEs : post.titleEn;

  document.getElementById('modalDate').textContent = post.articleDate;

  const tagsEl = document.getElementById('modalTags');
  tagsEl.innerHTML = post.articleTags
    .map(t => `<span class="blog-tag ${t.cls}">${t.text}</span>`)
    .join('');

  document.getElementById('modalTitle').textContent = title;

  // Show loading state while fetching markdown
  document.getElementById('modalContent').innerHTML =
    `<p style="opacity:0.5;">Cargando…</p>`;

  const modal = document.getElementById('articleModal');
  modal.classList.add('open');
  document.body.style.overflow = 'hidden';
  history.pushState({ articleId: id, lang }, '', `#article/${id}/${lang}`);

  // Fetch and render the markdown file.
  // Convention:
  //   Blog/{id}.md    → versión en español (obligatoria)
  //   Blog/{id}.en.md → versión en inglés  (opcional; si no existe, usa la ES)
  async function fetchMd(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error('not found');
    return res.text();
  }

  try {
    let mdText;
    if (lang === 'en') {
      try {
        mdText = await fetchMd(`Blog/${id}.en.md`);
      } catch {
        // No English version found — fall back to Spanish
        mdText = await fetchMd(`Blog/${id}.md`);
      }
    } else {
      mdText = await fetchMd(`Blog/${id}.md`);
    }

    const html = (typeof marked !== 'undefined')
      ? marked.parse(mdText)
      : `<pre>${mdText}</pre>`;
    document.getElementById('modalContent').innerHTML = html;
  } catch {
    const missing = lang === 'en'
      ? `<code>Blog/${id}.en.md</code> (o <code>Blog/${id}.md</code>)`
      : `<code>Blog/${id}.md</code>`;
    document.getElementById('modalContent').innerHTML =
      `<div class="coming-soon">
        <span class="material-symbols-outlined">construction</span>
        <strong>Artículo en proceso</strong>
        <p>El archivo ${missing} no existe aún.</p>
       </div>`;
  }
}

function closeArticle() {
  document.getElementById('articleModal').classList.remove('open');
  document.body.style.overflow = '';
  // Remove hash from URL when closing
  history.pushState(null, '', window.location.pathname + window.location.search);
}

function handleModalClick(e) {
  if (e.target === document.getElementById('articleModal')) {
    closeArticle();
  }
}

// Close on ESC
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeArticle();
});

// Parse #article/{id}/{lang} — lang is optional
function parseArticleHash(hash) {
  // e.g. "#article/fidae2026/en"  → { id: 'fidae2026', lang: 'en' }
  //      "#article/fidae2026"     → { id: 'fidae2026', lang: null }
  const parts = hash.replace('#article/', '').split('/');
  const id    = parts[0];
  const lang  = ['es', 'en'].includes(parts[1]) ? parts[1] : null;
  return { id, lang };
}

// Handle browser back/forward button
window.addEventListener('popstate', () => {
  const hash = location.hash;
  if (hash.startsWith('#article/')) {
    const { id, lang } = parseArticleHash(hash);
    if (lang && lang !== currentLang) setLanguage(lang);
    openArticle(id);
  } else {
    document.getElementById('articleModal').classList.remove('open');
    document.body.style.overflow = '';
  }
});

/* =========================================================
   9. SCROLL ANIMATION OBSERVER
========================================================= */
let scrollObserver;

function applyScrollObserver(elements) {
  if (!scrollObserver) return;
  elements.forEach(el => {
    el.style.opacity    = '0';
    el.style.transform  = 'translateY(24px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    scrollObserver.observe(el);
  });
}

/* =========================================================
   10. INIT
========================================================= */
(function init() {
  // Theme — default dark
  const savedTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  document.getElementById('themeIcon').textContent =
    savedTheme === 'dark' ? 'dark_mode' : 'light_mode';

  // Language
  const savedLang = localStorage.getItem('lang') || 'es';
  currentLang = savedLang;

  // Set up scroll observer
  scrollObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, { threshold: 0.15 });

  // Render blog grid — loads from Blog/index.json
  loadPosts();

  // Apply i18n (also re-renders blog grid)
  setLanguage(savedLang);

  // Observe static animated elements
  applyScrollObserver(document.querySelectorAll(
    '.timeline-item, .skill-category, .cert-card, .stat-card'
  ));

  // Check URL hash on load — open article if present
  const hash = location.hash;
  if (hash.startsWith('#article/')) {
    const { id, lang } = parseArticleHash(hash);
    if (lang && lang !== currentLang) setLanguage(lang);
    // Small delay to let the page render first
    setTimeout(() => openArticle(id), 100);
  }
})();

