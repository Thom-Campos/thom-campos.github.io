**Flag:** `UMDCTF{REC-9305174}`

**Categoría:** OSINT

**Autor del reto:** greyroad__
***

Este reto fue básicamente trabajo de detective puro y duro. Fue el último que hice, más que nada porque, la verdad, los desafíos de OSINT me intimidaban bastante.

## El caso: Hades Group

Nos pasaron un dump de Telegram (`hades_export.json`) de un grupo llamado "Hades Group". Básicamente, era un mercado clandestino donde la gente apostaba si iban a doxear o swattear a distintas personas reales.

El admin era súper cuidadoso y nunca posteaba con su cuenta personal. Todos sus mensajes salían como anónimos del canal (con un `from_id` tipo `"channel..."`).

Nuestra misión era desenmascarar al dueño real de toda esta operación y conseguir un **Document Record ID** que entregaba uno de los bots al final de la investigación.

### Nuestras herramientas (Bots de Telegram)

Teníamos acceso a un montón de bots para ir armando el puzzle:

| Bot | Función |
| --- | ------- |
| `@QuickOSINTSearch_XGBXL_389YBot` | Leak DB A — busca por username, UID o teléfono |
| `@EyeOfTheGod_ZF231_389YBot` | Leak DB B — busca por username, UID o teléfono |
| `@SherlockTweaked_9VEZB_389YBot` | Caché web e historial de usernames |
| `@TGObserver_H6J3S_389YBot` | Perfiles cacheados, ideal para sacar teléfonos a partir de usernames |
| `@StickerSleuth_VZBHY_389YBot` | Inteligencia de stickers — te da el UID del creador del pack |
| `@RussiaSearch_D4S38_389YBot` | DB de documentos rusos |
| `@ChinaSearch_44U32_389YBot` | DB de documentos chinos |
| `@USDocs_6C582_389YBot` | DB de documentos gringos |
| `@CountrySearch_U6B8V_389YBot` | DB mundial genérica — le pasas país + nombre y cruza los dedos |

***

## Análisis inicial: Buscando una aguja en el JSON

Empecé filtrando el dump buscando al administrador (`from_id: "channel28740651"`). De sus 30 mensajes, casi todo era ruido o moderación genérica del grupo.

Tuve que cabecear harto un rato tirando comandos con `jq` hasta que pillé un metadato interesante:

```bash
jq '.messages[] | select(.from_id=="channel28740651" and has("file"))' hades_export.json
```

Y saltó esto:

```json
{
  "type": "message",
  "date": "2025-12-29T10:23:00Z",
  "from": "Hades Group",
  "from_id": "channel28740651",
  "media_type": "sticker",
  "sticker_set_name": "styx_reaction_pack",
  "file": "stickers/styx_reaction_pack_001.webp",
  "id": 56
}
```

El compadre mandó un sticker custom. En Telegram, los packs de stickers quedan amarrados internamente al UID de la cuenta que los creó.

***

## La cacería paso a paso

### Paso 1: Tirando del hilo del sticker

Le pasé el nombre del pack al bot `@StickerSleuth_VZBHY_389YBot` para ver de quién era.

```
Attributed!
Set: styx_reaction_pack
Creator UID: 7816442093
```

Bingo. Ya teníamos el UID real del creador detrás de la cuenta de administrador.

### Paso 2: El laberinto de los alias (Rabbit holes)

Metí ese UID en `QuickOSINT` y `EyeOfTheGod`. Me escupieron una locura de datos: como 28 alias distintos y 4 números de teléfono de México, Japón, Brasil y UK.

Traté de buscar esos números en las DBs de documentos por un buen rato y nada. Me dieron varios dolores de cabeza hasta que caché que eran puros rabbit holes. Los sembró a propósito para hacernos perder el tiempo.

### Paso 3: El historial que no perdona

Como los teléfonos eran señuelos, agarré uno de los alias basura de la lista (`@zeus_archive`) y lo pasé por el bot `@SherlockTweaked_9VEZB_389YBot`.

```
Subject: @zeus_archive
Presence report:
  GitHub — renamed
  Instagram — not found
  Reddit — not found

Last looked up at: 2025-12-14
Username at lookup: @thanatos_signal
```

Aquí estuvo la magia. El loco se había cambiado el nombre, pero el bot tenía cacheado el handle en el momento de su último escaneo: `@thanatos_signal`. Este alias oculto no salía en los leaks anteriores.

### Paso 4: Cazando el número real

Le pasé este nuevo alias recién descubierto al bot `@TGObserver_H6J3S_389YBot`.

```
Subject: @thanatos_signal
Username history:
  1. @erebos_lane
  2. @thanatos_signal
  3. @kerberos_spine

Phone: +49 160 5550 7318
```

¡Pum! Un número alemán real (+49). Y Alemania sí era una de las jurisdicciones válidas que aceptaba nuestro bot global de documentos. Íbamos por buen camino.

### Paso 5: Poniéndole nombre y apellido

Volví a consultar `QuickOSINT`, pero esta vez directamente con el número de teléfono alemán.

```
phone: +49 160 5550 7318
name: Niklas Hofmann
linked id: 7816442093
linked usernames: @kerberos_spine
```

Match perfecto. El nombre real era Niklas Hofmann y, si se fijan, el UID cierra el círculo: es el mismísimo `7816442093` que sacamos del sticker en el paso 1.

### Paso 6: Sacando la flag

Ya con el nombre completo y el país confirmados, fui directo al `@CountrySearch_U6B8V_389YBot`.

```
Matched
Country: Germany
Query: Niklas Hofmann
Record: REC-9305174
Atlas ref AYJMVU5K
```

Misión cumplida. Nos soltó el récord exacto que pedía el desafío.

***

## Perfil del admin cacheado

| Campo | Datazo |
| ----- | ------ |
| Nombre real | Niklas Hofmann |
| País | Alemania |
| Teléfono | +49 160 5550 7318 |
| UID Telegram | 7816442093 |
| Alias principal activo | @kerberos\_spine |
| Alias descartable | @zeus\_archive |
| Record ID | REC-9305174 |

***

## Resumen de la jugada

Dejo el arbolito de cómo fue la cadena de ataque por si alguien se perdió en algún paso:

```
hades_export.json
  └─ msg id 56: sticker del pack "styx_reaction_pack"
       └─ StickerSleuth → Creator UID: 7816442093
            └─ QuickOSINT + EyeOfTheGod → 28 alias, 4 teléfonos basura (señuelos)
                 └─ SherlockTweaked(@zeus_archive) → alias oculto: @thanatos_signal
                      └─ TGObserver(@thanatos_signal) → +49 160 5550 7318
                           └─ QuickOSINT(+49...) → Niklas Hofmann
                                └─ CountrySearch(Germany, Niklas Hofmann) → REC-9305174
```

***

## Aprendizajes

* Costó harto no marearse dando pelea con tantos bots y rabbit holes. Queda clarísimo que en CTFs (y en la vida real), las bases de datos pueden estar llenas de basura puesta a propósito para despistar.
* El OpSec perfecto es un mito. Todo el esquema de anonimato que armó el compadre se fue al piso por un detalle súper tonto: usar un sticker de su propio pack.
* Las cachés son la salvación en OSINT. Aunque borres o cambies tu username, los bots guardan registros de estados pasados y te pueden triangular igual. Nada desaparece de internet.