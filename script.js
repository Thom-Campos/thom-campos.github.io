/* =========================================================
   I18N
========================================================= */
const translations = {
  es: {
    'hero.line1':    'Bienvenido, soy',
    'hero.line2':    'Thomas Campos',
    'hero.role':     'CIBERSEGURIDAD · BLUE TEAM · CTF PLAYER',
    'hero.desc':     'Técnico en Redes egresado, actualmente cursando Ingeniería en Conectividad y Redes, orientado a Blue Team y análisis de eventos de seguridad. Certificado por Google, Cisco y CertiProf. Competidor CTF activo.',
    'hero.cta1':     'Ver Write-ups',
    'hero.cta2':     'Contactar',

    'ctfs.label':    'Write-ups',
    'ctfs.title':    'CTFs & Write-ups',
    'ctfs.desc':     'Retos resueltos compitiendo en distintas competencias de ciberseguridad. Cada write-up documenta el proceso completo: reconocimiento, análisis y exploit.',
    'ctfs.stat1':    'Write-ups',
    'ctfs.stat2tag': 'Nacional',
    'ctfs.stat2':    'FIDAE Llaitun CTF (#36/233)',
    'ctfs.stat3tag': 'Internacional',
    'ctfs.stat3':    'UMDCTF 2026 (#74/617)',
    'ctfs.stat4':    'Categorías',
    'ctfs.search':   'Buscar por título, categoría o técnica...',
    'ctfs.empty':    'No hay write-ups aún.',
    'ctfs.noResults':'No se encontraron write-ups para tu búsqueda.',

    'contact.label':      'Contacto',
    'contact.title':      'Hablemos',
    'contact.desc':       'Abierto a oportunidades en equipos de seguridad y colaboraciones técnicas.',
    'contact.emailLabel': 'Correo',
    'contact.form.name':    'Nombre',
    'contact.form.email':   'Correo electrónico',
    'contact.form.subject': 'Asunto',
    'contact.form.message': 'Mensaje',
    'contact.form.send':    'Enviar mensaje',
    'contact.form.sending': 'Enviando…',
    'contact.form.sent':    'Mensaje enviado ✓',
    'contact.form.errorRequired': 'Por favor completa los campos obligatorios.',
    'contact.form.errorEmail':    'Ingresa un correo electrónico válido.',
    'contact.form.errorGeneric':  'Algo salió mal. Intenta de nuevo o escríbeme directo por correo.',
    'contact.form.success':       '¡Mensaje enviado! Te responderé a la brevedad.',

    'footer.copy':   '© 2026 Thomas Campos.',
  },
  en: {
    'hero.line1':    'Welcome, I\'m',
    'hero.line2':    'Thomas Campos',
    'hero.role':     'CYBERSECURITY · BLUE TEAM · CTF PLAYER',
    'hero.desc':     'Network Technician graduate, currently pursuing a degree in Networking & Connectivity Engineering, focused on Blue Team work and security event analysis. Certified by Google, Cisco and CertiProf. Active CTF competitor.',
    'hero.cta1':     'Read Write-ups',
    'hero.cta2':     'Get in Touch',

    'ctfs.label':    'Write-ups',
    'ctfs.title':    'CTFs & Write-ups',
    'ctfs.desc':     'Challenges solved competing in various cybersecurity competitions. Every write-up documents the full process: recon, analysis and exploit.',
    'ctfs.stat1':    'Write-ups',
    'ctfs.stat2tag': 'National',
    'ctfs.stat2':    'FIDAE Llaitun CTF (#36/233)',
    'ctfs.stat3tag': 'International',
    'ctfs.stat3':    'UMDCTF 2026 (#74/617)',
    'ctfs.stat4':    'Categories',
    'ctfs.search':   'Search by title, category or technique...',
    'ctfs.empty':    'No write-ups yet.',
    'ctfs.noResults':'No write-ups matched your search.',

    'contact.label':      'Contact',
    'contact.title':      "Let's talk",
    'contact.desc':       'Open to opportunities in security teams and technical collaborations.',
    'contact.emailLabel': 'Email',
    'contact.form.name':    'Name',
    'contact.form.email':   'Email address',
    'contact.form.subject': 'Subject',
    'contact.form.message': 'Message',
    'contact.form.send':    'Send message',
    'contact.form.sending': 'Sending…',
    'contact.form.sent':    'Message sent ✓',
    'contact.form.errorRequired': 'Please fill in all required fields.',
    'contact.form.errorEmail':    'Please enter a valid email address.',
    'contact.form.errorGeneric':  'Something went wrong. Try again or email me directly.',
    'contact.form.success':       "Message sent! I'll get back to you soon.",

    'footer.copy':   '© 2026 Thomas Campos.',
  }
};

let currentLang = 'es';
let ctfSearchQuery = '';

function setLanguage(lang) {
  currentLang = lang;

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (translations[lang][key] !== undefined) {
      el.textContent = translations[lang][key];
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (translations[lang][key] !== undefined) {
      el.setAttribute('placeholder', translations[lang][key]);
    }
  });

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
  });

  document.documentElement.setAttribute('lang', lang);
  renderCtfList();
}

/* =========================================================
   HEADER SCROLL STATE
========================================================= */
window.addEventListener('scroll', () => {
  const header = document.getElementById('header');
  if (window.scrollY > 40) header.classList.add('scrolled');
  else header.classList.remove('scrolled');
});

/* =========================================================
   CTF LIST — usa POSTS embebido en data.js, sin fetch.
   Incluye búsqueda en vivo por título / categoría / excerpt.
========================================================= */
function renderCtfList() {
  const list = document.getElementById('ctfList');
  if (!list) return;

  if (typeof POSTS === 'undefined' || POSTS.length === 0) {
    list.innerHTML = `<p class="ctf-empty">${translations[currentLang]['ctfs.empty']}</p>`;
    return;
  }

  const q = ctfSearchQuery.trim().toLowerCase();

  const filtered = POSTS.filter((post) => {
    if (!q) return true;
    const title   = (currentLang === 'es' ? post.titleEs   : post.titleEn).toLowerCase();
    const excerpt = (currentLang === 'es' ? post.excerptEs : post.excerptEn).toLowerCase();
    const cat     = post.category.toLowerCase();
    return title.includes(q) || excerpt.includes(q) || cat.includes(q);
  });

  if (filtered.length === 0) {
    list.innerHTML = `<p class="ctf-empty">${translations[currentLang]['ctfs.noResults']}</p>`;
    return;
  }

  list.innerHTML = filtered.map((post) => {
    const title   = currentLang === 'es' ? post.titleEs   : post.titleEn;
    const excerpt = currentLang === 'es' ? post.excerptEs : post.excerptEn;
    const index   = String(POSTS.indexOf(post) + 1).padStart(2, '0');

    return `
      <a class="ctf-entry" href="blog-pages/${post.id}.html" target="_blank" rel="noopener">
        <span class="ctf-entry-index">${index}</span>
        <span class="ctf-entry-main">
          <span class="ctf-entry-path">${post.category} — UMDCTF</span>
          <span class="ctf-entry-title">${title}</span>
          <span class="ctf-entry-desc">${excerpt}</span>
        </span>
        <span class="ctf-entry-arrow">&rarr;</span>
      </a>
    `;
  }).join('');
}

document.getElementById('ctfSearch')?.addEventListener('input', (e) => {
  ctfSearchQuery = e.target.value;
  renderCtfList();
});

/* =========================================================
   CONTACT FORM — envía vía Formspree
========================================================= */
const FORMSPREE_ID = 'xnjllrla';

function showFormFeedback(message, type) {
  const el = document.getElementById('formFeedback');
  if (!el) return;
  el.textContent = message;
  el.className = `form-feedback ${type}`;
}

document.getElementById('contactForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();

  const btn  = document.getElementById('formSubmitBtn');
  const span = btn.querySelector('span[data-i18n]');

  const name    = document.getElementById('fName').value.trim();
  const email   = document.getElementById('fEmail').value.trim();
  const subject = document.getElementById('fSubject').value.trim();
  const message = document.getElementById('fMessage').value.trim();

  const t = translations[currentLang];

  if (!name || !email || !message) {
    showFormFeedback(t['contact.form.errorRequired'], 'error');
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    showFormFeedback(t['contact.form.errorEmail'], 'error');
    return;
  }

  btn.disabled = true;
  const originalText = span.textContent;
  span.textContent = t['contact.form.sending'];
  showFormFeedback('', '');

  try {
    const res = await fetch(`https://formspree.io/f/${FORMSPREE_ID}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ name, email, subject, message }),
    });

    if (res.ok) {
      span.textContent = t['contact.form.sent'];
      showFormFeedback(t['contact.form.success'], 'success');
      ['fName', 'fEmail', 'fSubject', 'fMessage'].forEach(id => {
        document.getElementById(id).value = '';
      });
      setTimeout(() => {
        span.textContent = originalText;
        btn.disabled = false;
      }, 4000);
    } else {
      throw new Error('Formspree error');
    }
  } catch {
    span.textContent = originalText;
    btn.disabled = false;
    showFormFeedback(t['contact.form.errorGeneric'], 'error');
  }
});

/* =========================================================
   NAV LANG BUTTONS
========================================================= */
document.querySelectorAll('.lang-btn').forEach(btn => {
  btn.addEventListener('click', () => setLanguage(btn.getAttribute('data-lang')));
});

/* =========================================================
   INIT
========================================================= */
setLanguage('es');
