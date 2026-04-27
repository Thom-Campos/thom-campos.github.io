**Flag:** `UMDCTF{one_might_argue_that_gambling_is_the_best_vice_but_they_would_be_wrong}`

**Category:** Rev

**Challenge author:** segal

***

## Context

This challenge was really fun to take apart and forced me out of my comfort zone, spending a good while wrestling with the game logic.

On the surface, it was an online betting site where you had to win 25 times in a row across two games: a minefield and a road-crossing game. Impossible by pure luck, so we had to dig deeper.

## Challenge: rainbet

> *"sponsored by rainbet (for legal reasons this is not true). their rng backend was leaked (for legal reasons this is also not true)! can you get enough max wins?"*

The interface gave us access to an online casino (`rainbet.challs.umdctf.io`). To help us along, we were given two backend files: a Python script (`rainbet.py`) and a compiled WebAssembly binary (`rainbet_gen.wasm`).

The goal was simple: reach a streak of 25 consecutive wins without losing.

### What exactly does the system do?

The server used the WASM file to generate the game boards. After digging into the code, I understood that the random number generator (RNG) was not truly random but deterministic.

It was seeded with our session ID and the current round number. It is like a dealer who always uses the same deck in the same order: if we know which table we are at and which hand is being played, we can predict exactly which cards will come up.

This meant we could call the WASM locally and see where the mines or cars were before the server ever sent us the official board.

### Architecture and Strategy: Putting the puzzle together

When I tried to automate this, I hit a wall. The server did not use normal HTTP requests but WebSockets (`wss://`). On top of that, every move we sent had to be cryptographically signed with a `sig` parameter.

I spent a good while digging through the frontend JavaScript. It turned out the signature was a simple HMAC-SHA256. The server gave us a `secret` each round, and the frontend generated a hash by combining that secret with the move we wanted to make.

Since the signing logic was exposed on the client side and we received the secret, we could generate valid signatures from our own script and bypass the server's validation entirely.

### Solution

It took me a while to set up the virtual environment on my Kali so that `wasmtime` and `websocket-client` would work properly together, but it was essential for running the exploit locally.

I built a Python script that automated the entire flow: it generated the board locally, calculated the safe moves, signed the payload, and sent it over the WebSocket.

```python
# Summary of the main exploit logic
def play_round(ws, secret, sid, streak):
    # Generate the game locally using the leaked WASM
    game_info = rainbet.generate_game(sid, streak)
    
    if game_info["type"] == "mines":
        return play_mines(ws, secret, streak, game_info)
    elif game_info["type"] == "chicken":
        return play_chicken(ws, secret, streak, game_info)

# Main loop to win all 25 times
while streak < 25:
    result = play_round(ws, secret, sid, streak)
    
    # The server rotates the secret, so we update it for the next signature
    if "secret" in result: 
        secret = result["secret"]
    if "session_id" in result: 
        sid = result["session_id"]
```

### Execution and flag obtained

I let the script run in my terminal. Since we already knew the outcome of every board, the bot started playing perfectly, dodging mines and cars automatically.

Upon reaching win number 25, the server gave up and sent us the flag through the socket.

```
[+] Connected. Starting exploit!
[*] Streak 0/25 — Playing: CHICKEN
[*] Streak 1/25 — Playing: MINES
...
[*] Streak 24/25 — Playing: MINES
[!!!] FLAG: UMDCTF{one_might_argue_that_gambling_is_the_best_vice_but_they_would_be_wrong}
```

***

## Technical vulnerability summary

| Component | Weakness | Impact |
|---|---|---|
| `rainbet_gen.wasm` | Deterministic RNG (seeded with `session_id + round_idx`) | Full board prediction before playing. |
| `sig` signature | HMAC signing logic exposed in the frontend. | Allows forging and signing valid payloads. |
| WebSocket protocol | No additional per-round authentication. | Unrestricted programmatic access. |

## Lessons learned

* Hiding your RNG inside a WASM binary is completely useless if you feed it predictable inputs. Security through obscurity is never a good idea in infrastructure or development.
* Leaving data-signing logic on the client side (frontend) is a gift to any attacker. They handed us a blueprint for mimicking browser behavior on a silver platter.
* Wrestling with WebSockets was rough at first, but it taught me a lot about how to manipulate non-conventional traffic in web CTF challenges.