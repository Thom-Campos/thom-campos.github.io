# Páginas de write-ups

Cada write-up vive en su propia página HTML dentro de esta carpeta
(`blog-pages/<id>.html`), generada a partir de los datos en `../data.js`.

Esto permite que cada entrada del blog se abra en una pestaña nueva
del navegador con su propia URL, en vez de un modal dentro de la
página principal.

## Cómo regenerar las páginas

Si agregas, editas o quitas un post en `data.js`, vuelve a correr
desde la raíz del proyecto:

```
node build-posts.js
```

Esto regenera todos los archivos `blog-pages/<id>.html` a partir del
contenido actual de `data.js`. No hace falta tocarlos a mano.

Archivos relevantes:
- `../build-posts.js` — script generador (Node, sin dependencias externas)
- `post.css` — estilos de la página de artículo (reutiliza los tokens de `../style.css`)
- `post.js` — lógica de idioma (ES/EN) y render del markdown con `marked.js`

**Importante:** no borres esta carpeta con `rm -rf` antes de regenerar,
ya que `post.css`, `post.js` y este README no se recrean automáticamente
(solo los `.html` de cada post). Si necesitas limpiar, borra solo los
archivos `.html` dentro de `blog-pages/`.
