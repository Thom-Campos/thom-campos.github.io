**Flag:** `UMDCTF{REC-9305174}`

**Category:** OSINT

**Challenge author:** greyroad__

***

## The case: Hades Group

This challenge was basically pure detective work. It was the last one I tackled, mostly because OSINT challenges honestly intimidated me quite a bit.

We were given a Telegram dump (`hades_export.json`) from a shady group called "Hades Group". It was essentially an underground marketplace where people placed bets on whether specific real individuals would be doxxed or swatted.

The admin was extremely careful and never posted from a personal account. All their messages appeared anonymously from the channel (with a `from_id` like `"channel..."`).

Our mission was to unmask the real owner of the entire operation and obtain a **Document Record ID** that one of the bots would hand over at the end of the investigation.

### Our tools (Telegram Bots)

We had access to a bunch of bots to piece the puzzle together:

| Bot | Function |
| --- | -------- |
| `@QuickOSINTSearch_XGBXL_389YBot` | Leak DB A — search by username, UID, or phone |
| `@EyeOfTheGod_ZF231_389YBot` | Leak DB B — search by username, UID, or phone |
| `@SherlockTweaked_9VEZB_389YBot` | Web cache and username history |
| `@TGObserver_H6J3S_389YBot` | Cached profiles, great for pulling phone numbers from usernames |
| `@StickerSleuth_VZBHY_389YBot` | Sticker intelligence — returns the UID of the pack creator |
| `@RussiaSearch_D4S38_389YBot` | Russian document DB |
| `@ChinaSearch_44U32_389YBot` | Chinese document DB |
| `@USDocs_6C582_389YBot` | US document DB |
| `@CountrySearch_U6B8V_389YBot` | Global generic DB — pass a country and name and hope for the best |

***

## Initial analysis: Finding a needle in the JSON

I started by filtering the dump to find the admin (`from_id: "channel28740651"`). Out of their 30 messages, almost everything was noise or generic group moderation.

I had to bang my head against it for a while running `jq` commands until I spotted an interesting piece of metadata:

```bash
jq '.messages[] | select(.from_id=="channel28740651" and has("file"))' hades_export.json
```

And this popped up:

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

The guy sent a custom sticker. In Telegram, sticker packs are internally tied to the UID of the account that created them.

***

## The hunt, step by step

### Step 1: Pulling the sticker thread

I passed the pack name to the `@StickerSleuth_VZBHY_389YBot` bot to see who it belonged to.

```
Attributed!
Set: styx_reaction_pack
Creator UID: 7816442093
```

Bingo. We now had the real UID of the creator hiding behind the admin account.

### Step 2: The alias maze (Rabbit holes)

I plugged that UID into `QuickOSINT` and `EyeOfTheGod`. They spat out a mess of data: around 28 different aliases and 4 phone numbers from Mexico, Japan, Brazil, and the UK.

I spent a good while trying to search those numbers in the document DBs and got nowhere. They gave me quite a few headaches before I realized they were all rabbit holes. He planted them on purpose to waste our time.

### Step 3: The history that never forgets

Since the phone numbers were decoys, I grabbed one of the throwaway aliases from the list (`@zeus_archive`) and ran it through the `@SherlockTweaked_9VEZB_389YBot` bot.

```
Subject: @zeus_archive
Presence report:
  GitHub — renamed
  Instagram — not found
  Reddit — not found

Last looked up at: 2025-12-14
Username at lookup: @thanatos_signal
```

This was where the magic happened. The guy had changed his name, but the bot had cached the handle at the time of its last scan: `@thanatos_signal`. This hidden alias did not appear in the earlier leaks.

### Step 4: Hunting down the real number

I passed this newly discovered alias to the `@TGObserver_H6J3S_389YBot` bot.

```
Subject: @thanatos_signal
Username history:
  1. @erebos_lane
  2. @thanatos_signal
  3. @kerberos_spine

Phone: +49 160 5550 7318
```

A real German number (+49). And Germany was one of the valid jurisdictions accepted by our global document bot. We were on the right track.

### Step 5: Putting a name to the face

I queried `QuickOSINT` again, but this time directly with the German phone number.

```
phone: +49 160 5550 7318
name: Niklas Hofmann
linked id: 7816442093
linked usernames: @kerberos_spine
```

Perfect match. The real name was Niklas Hofmann and, if you look closely, the UID closes the loop: it is the very same `7816442093` we pulled from the sticker back in step 1.

### Step 6: Grabbing the flag

With the full name and confirmed country in hand, I went straight to `@CountrySearch_U6B8V_389YBot`.

```
Matched
Country: Germany
Query: Niklas Hofmann
Record: REC-9305174
Atlas ref AYJMVU5K
```

Mission accomplished. It returned the exact record the challenge was asking for.

***

## Cached admin profile

| Field | Data |
| ----- | ---- |
| Real name | Niklas Hofmann |
| Country | Germany |
| Phone | +49 160 5550 7318 |
| Telegram UID | 7816442093 |
| Active main alias | @kerberos\_spine |
| Throwaway alias | @zeus\_archive |
| Record ID | REC-9305174 |

***

## Attack chain summary

Here is the attack chain tree in case anyone got lost along the way:

```
hades_export.json
  └─ msg id 56: sticker from pack "styx_reaction_pack"
       └─ StickerSleuth → Creator UID: 7816442093
            └─ QuickOSINT + EyeOfTheGod → 28 aliases, 4 fake phones (decoys)
                 └─ SherlockTweaked(@zeus_archive) → hidden alias: @thanatos_signal
                      └─ TGObserver(@thanatos_signal) → +49 160 5550 7318
                           └─ QuickOSINT(+49...) → Niklas Hofmann
                                └─ CountrySearch(Germany, Niklas Hofmann) → REC-9305174
```

***

## Lessons learned

* It was hard not to get dizzy juggling so many bots and rabbit holes. It makes it crystal clear that in CTFs (and in real life), databases can be full of garbage planted on purpose to throw you off.
* Perfect OpSec is a myth. The whole anonymity scheme the guy built collapsed because of one tiny detail: using a sticker from his own pack.
* Caches are a lifesaver in OSINT. Even if you delete or change your username, bots keep records of past states and can triangulate you anyway. Nothing disappears from the internet.