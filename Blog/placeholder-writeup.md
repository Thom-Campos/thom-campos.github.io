# [PLACEHOLDER] Próximo CTF Writeup

> ⚠️ **Este es un archivo de ejemplo.** Reemplaza este contenido con tu writeup real y actualiza los metadatos en `Blog/index.json`.

***

## Sistema de blog bilingüe

Cada entrada del blog puede tener **dos archivos Markdown**:

| Archivo | Idioma | ¿Obligatorio? |
| ------- | ------ | ------------- |
| `Blog/{id}.md` | Español | ✅ Sí |
| `Blog/{id}.en.md` | Inglés | ⬜ Opcional |

Si el visitante tiene el idioma en **inglés** y existe `Blog/{id}.en.md`, se cargará ese. Si no existe, se carga el `.md` base en español como fallback automático.

### Cómo añadir una entrada nueva

**1.** Crea `Blog/mi-nuevo-post.md` con el contenido en español.

**2.** (Opcional) Crea `Blog/mi-nuevo-post.en.md` con la versión en inglés.

**3.** Añade el objeto al array en `Blog/index.json`:

```json
{
  "id":          "mi-nuevo-post",
  "cat":         "ctf",
  "dateDisplay": "May 2026",
  "icon":        "emoji_events",
  "titleEs":     "Título en español",
  "titleEn":     "Title in English",
  "excerptEs":   "Resumen corto (español).",
  "excerptEn":   "Short summary (English).",
  "cardTags":    [{ "text": "CTF", "cls": "tag-osint" }],
  "articleDate": "Mayo 2026",
  "articleTags": [{ "text": "CTF", "cls": "tag-osint" }],
  "placeholder": false
}
```

**4.** ¡Listo! La tarjeta aparece automáticamente.

***

## Ejemplo de estructura de writeup

## Contexto

Descripción breve del CTF o evento.

## Desafío: Nombre del reto

Descripción del problema planteado.

### Solución

```bash
$ nmap -sV -p 22,80,443 10.0.0.1
```

### Flag obtenida

```
FLAG{ejemplo_de_flag}
```

## Aprendizajes

* Punto clave 1
* Punto clave 2