<div align="center">

<img src="assets/Icarus_logo.png" alt="Icarus" width="120" />

# Icarus Un-follower

**Remove inactive followers in Umamusume — headless, straight through the game server.**

<sub>Companion to the Icarus bots · Windows · Python 3.9+</sub>

[![Join our Discord](https://img.shields.io/badge/Discord-Join%20the%20server-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/wpbd3hTBDc)

</div>

---

Icarus Un-follower reads your **follower list directly from the Cygames game
server**, works out who's been inactive, and removes them — using the game's own
`friend/un_follower` API, exactly as if you tapped **"Remove Follower"** in-game.

It talks to the server the **same way the Icarus career bot does**: it captures
your account auth off the running game once (via Frida), then everything is
headless — **the game can stay closed** while it scans and removes.

> ⚠️ **Use responsibly.** This automates removals on *your own* account and is
> **permanent**. It's rate-paced with human-like delays and has a Stop button,
> but you use it at your own risk.

---

## ✨ Features

- 🌐 **Headless** — talks to the server directly (msgpack + AES, rolling `sid`).
  Game needed only once, to grab auth.
- 🖥️ **Clean dashboard UI** — dark, minimalist, live stat cards + activity log.
- 😴 **Inactivity filtering** — dropdown: **12 hours · 1 · 2 · 3 · 7 · 14 · 21
  days · 1 month**. "1 month" means *1 month or older* (includes 2-, 3-, 4-month
  idlers).
- 🤝 **Mutual-safe** — never removes someone you follow back (toggle off to include).
- 🕰️ **Human-like pacing** — randomized min→max delay between removals; a Stop
  button halts instantly; the client auto-backs-off if the server throttles.
- 🧹 **Batch or cap** — Max = `all` clears everyone inactive in one run, or set a
  number to cap it.

---

## 🚀 Quick start

| you have… | do this |
|---|---|
| **the exe** | double-click **`IcarusUnfollower.exe`** — no Python needed |
| **Python, dislike cmd** | double-click **`Start Icarus Unfollower.vbs`** — auto-installs deps, opens the app |
| **a dev setup** | `pip install -r requirements.txt` then `python unfollower_bot.py` |

Then:

1. **Have Umamusume open at the home menu** (needed once for auth).
2. Click **Scan followers**. First time it captures your auth (tap around in-game
   so it sends a request); after that it's instant and **needs no game**. The
   **INACTIVE** card fills in.
3. Pick an **inactivity period**, set your **delay** range and **Max** (`all` =
   everyone).
4. Turn **Arm removals** ON → **Remove inactive** → confirm. It removes them
   through the server, one every few seconds. **Scan again** to confirm the count.

---

## 🧠 Video Showcase

https://www.youtube.com/watch?v=wRGMfyAJXas

## 🧠 How it works

```
┌─ auth_capture.py ─┐   Frida hooks the game's TLS write + CompressRequest and
│  (game running)   │   lifts viewer_id / auth_key / udid / app_ver / res_ver +
└─────────┬─────────┘   steam ticket + device info  ->  follower_data/account.json
          │
┌─────────▼─────────┐   msgpack -> AES-CBC -> HEAD/sid/udid framing -> base64,
│   uma_client.py   │   rolling sid, retries/back-off. login() = start_session +
│  (headless, no    │   load/index. Then:
│   game needed)    │     friend/index        -> your follower list
└─────────┬─────────┘     friend/un_follower  -> remove one follower
          │
┌─────────▼─────────┐   auto-detect the follower list + last-login times, flag
│ unfollower_bot.py │   mutuals, classify inactive by your period, and drive the
│  (UI + logic)     │   removals paced by your delays.
└───────────────────┘
```

The protocol (crypto, `sid` rotation, error handling) is the same one the Icarus
career bot proved against the live server, so removals actually take effect
server-side — unlike client-side injection tricks.

---

## ⌨️ Command line (optional)

```bash
python unfollower_bot.py                          # dashboard UI (default)
python unfollower_bot.py analyze --days 30        # login + report inactive (no removals)
python unfollower_bot.py analyze --days 0.5       # fractions ok: 0.5 = 12 hours
python unfollower_bot.py run --days 30 --max 0    # dry run (add --arm --yes to remove all)
```

`analyze` writes `follower_data/`:

| file | what |
|---|---|
| `account.json` | your captured auth — **REAL secrets, git-ignored, never share** |
| `followers.json` | detected list + who's inactive/active/mutual |
| `followers_report.md` | human-readable table of removal candidates |

---

## 🔧 Build a standalone exe

```bash
python make_icon.py       # optional: assets/Icarus_logo.png -> assets/icarus.ico
build_exe.bat             # produces dist/IcarusUnfollower.exe (PyInstaller)
```

---

## 📁 Project layout

| file | role |
|---|---|
| `unfollower_bot.py` | dashboard UI + inactivity logic + CLI |
| `uma_client.py` | headless game-server client (crypto, login, friend endpoints) |
| `auth_capture.py` | one-time Frida auth grab off the running game |
| `launcher.py`, `Start Icarus Unfollower.vbs`/`.bat` | plug-and-play launch |
| `build_exe.bat`, `make_icon.py` | build the exe / icon |
| `assets/` | Icarus logo (+ generated icon) |
| `requirements.txt` | frida, msgpack, curl_cffi, pycryptodome |

---

## 🩺 Troubleshooting

- **Scan says "capturing auth" but never finishes** → have the game at the **home
  menu** and tap around so it sends a request; make sure nothing else is attached
  to the game (close other Frida tools).
- **`API error 214`/`217` on login** → the game updated and the captured
  `app_ver`/`res_ver` are stale. Update the game fully, reach home, delete
  `follower_data/account.json`, and Scan again to re-capture.
- **Login fails after a while** → the cached auth expired; delete
  `account.json` and re-capture with the game running.
- **A removal fails mid-batch** → the client stops on the first hard error; re-scan
  and try again (transient `208 server busy` is auto-retried with back-off).

---

## 💬 Community

Questions, feedback, or want the latest builds? **[Join our Discord →](https://discord.gg/wpbd3hTBDc)**
(there's also a **Discord** button in the app's title bar).

---

<div align="center">
<sub>Part of the <b>Icarus</b> toolset · sibling project: <b>Icarus Scenario Recorder</b></sub>
</div>
