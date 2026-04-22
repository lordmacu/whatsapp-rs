# whatsapp-rs

A Rust WhatsApp Web client library with a CLI. Connects via the Noise
protocol, pairs by QR, and speaks the full Signal protocol (X3DH + Double
Ratchet) end-to-end — interoperates with the real WhatsApp servers and
official mobile apps.

## Quick start (one command)

```bash
cargo build --release
./target/release/whatsapp-rs setup       # pair via QR + install autostart
./target/release/whatsapp-rs send 573144347358@s.whatsapp.net "hello"
```

`setup` walks you through QR pairing if you aren't paired yet, then
installs the background daemon for your OS (systemd / launchd / Task
Scheduler). From that point every CLI command proxies through the
daemon and round-trips in ~10 ms.

## Daemon mode (fast sends)

Fresh connects eat 2–3 s because WhatsApp drains queued offline messages
before processing our `iq`s. A long-lived daemon keeps one session open
and lets CLI commands round-trip in ~10 ms.

Run the daemon:
```bash
./target/release/whatsapp-rs daemon      # foreground
```

Once it's running, `send`/`status`/etc. proxy through it automatically.

Stop it:
```bash
./target/release/whatsapp-rs daemon-stop
```

> **Pair first.** The daemon has no terminal to show the QR, so it will
> refuse to start until credentials exist. Run `whatsapp-rs listen` once,
> scan the QR, press Ctrl+C; after that the daemon is free to start.

### Auto-start on login — one command, any OS

```bash
./target/release/whatsapp-rs install     # Linux/macOS/Windows auto-detected
```

Under the hood this writes the right init file for your platform
(systemd user unit / launchd plist / Scheduled Task) pointing at the
currently-running binary and loads it. The daemon starts at every login
and is restarted if it crashes.

To remove:
```bash
./target/release/whatsapp-rs uninstall
```

Per-platform tails (if you want raw logs):

| Platform | Tail command |
| --- | --- |
| Linux | `journalctl --user -u whatsapp-rs -f` |
| macOS | `tail -f /tmp/whatsapp-rs.log` |
| Windows | Event Viewer → Task Scheduler Operational log |

Reference unit files are also shipped under `contrib/` for manual setup.

## Commands

| Command | Description |
| --- | --- |
| `listen` | Connect and print incoming messages (blocks). |
| `send <jid> <text>` | Send a text message. |
| `send-group <jid> <text>` | Send to a group JID. |
| `reply <jid> <msg-id> <text>` | Reply to a specific message. |
| `react <jid> <msg-id> <emoji>` | Add a reaction. |
| `revoke <jid> <msg-id>` | Delete a sent message. |
| `edit <jid> <msg-id> <new-text>` | Edit a sent message. |
| `status` | Print our JID. |
| `contacts` / `history <jid> [n]` | Local cache lookups. |
| `daemon` / `daemon-stop` | Start/stop the background daemon. |

Full list: `./target/release/whatsapp-rs --help`.

## State

Credentials, sessions and caches live under:
```
$XDG_DATA_HOME/.whatsapp-rs/    (typically ~/.local/share/.whatsapp-rs/)
├── creds.json
├── sessions.json
├── pre-keys/
└── messages/
```

Delete `creds.json` to force a fresh QR pairing.
