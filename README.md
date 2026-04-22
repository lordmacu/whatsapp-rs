# whatsapp-rs

A Rust WhatsApp Web client library with a CLI. Connects via the Noise
protocol, pairs by QR, and speaks the full Signal protocol (X3DH + Double
Ratchet) end-to-end — interoperates with the real WhatsApp servers and
official mobile apps.

## Quick start

Build:
```bash
cargo build --release
```

Pair your phone (scan QR):
```bash
./target/release/whatsapp-rs listen
```

Send a message:
```bash
./target/release/whatsapp-rs send 573144347358@s.whatsapp.net "hello"
```

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

### Auto-start on login

#### Linux (systemd)

```bash
mkdir -p ~/.config/systemd/user
cp contrib/whatsapp-rs.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now whatsapp-rs.service
loginctl enable-linger "$USER"   # start at boot, not just at interactive login
journalctl --user -u whatsapp-rs -f
```

#### macOS (launchd)

```bash
cp contrib/com.whatsapp-rs.plist ~/Library/LaunchAgents/
# edit the <string> path inside to point at your binary, then:
launchctl load -w ~/Library/LaunchAgents/com.whatsapp-rs.plist
tail -f /tmp/whatsapp-rs.log
```

#### Windows (Task Scheduler)

Edit `contrib\whatsapp-rs-task.xml` so `<Command>` points at your
compiled `whatsapp-rs.exe`, then:

```powershell
schtasks /Create /TN "whatsapp-rs" /XML contrib\whatsapp-rs-task.xml
```

The task fires on every user login and auto-restarts on crash.

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
