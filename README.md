# webshell

A mobile-first web terminal that connects to your server via the browser. Powered by tmux — sessions persist across disconnects.

## Why I built this

I wanted a personal replacement for Claw and other terminal cloud tools — something I fully own, running on my own server, accessible from any device via a URL.

**Why not just SSH + tmux?** I use that too. But having a URL I can open from my phone, a borrowed laptop, or a tablet — without an SSH client — is genuinely useful. And the project/session organization is something tmux alone doesn't give you without a wrapper.

**Why not Claw / Wetty / code-server?** Claw is closed-source and someone else's server. Wetty is SSH-over-HTTP which adds a layer I don't need on my own box. code-server is great but heavy — I just want terminals, not an IDE.

This is ~300 lines of server code. No build step, no framework. One script to set up on a fresh Ubuntu box.

## Features

- **Project organization** — group terminal sessions into projects; delete a project to terminate all its sessions
- **Persistent sessions** — powered by tmux; close the browser, come back later, pick up where you left off
- **First-visit setup** — no config files needed; set your password on first visit
- **Quick session switching** — slide-out sidebar lets you jump between any session across all projects
- **Change password** — update your password anytime from the sidebar settings
- **Mobile-optimized** — full-screen terminal with touch support, virtual keyboard handling
- **Secure** — HTTPS via Let's Encrypt, bcrypt-hashed password, no unnecessary open ports
- **Autosuggestions** — zsh + oh-my-zsh + zsh-autosuggestions out of the box

## Stack

- **Backend:** Node.js + Express + WebSocket + node-pty
- **Frontend:** xterm.js, marked and highlight.js vendored in `public/vendor/` (no CDN, no build step), vanilla JS SPA
- **Storage:** SQLite (better-sqlite3) for projects, sessions, and settings
- **Terminal:** tmux sessions with zsh
- **Proxy:** nginx + Let's Encrypt SSL

## Setup

### Prerequisites

- Ubuntu server (tested on 24.04)
- A domain pointing to your server's IP
- Ports 80 and 443 open in your firewall/security group

### Install

```bash
git clone git@github.com:parag/webshell.git
cd webshell
chmod +x setup.sh
```

Edit `setup.sh` and set your domain on the `DOMAIN=` line, then run:

```bash
./setup.sh
```

This installs everything (Node.js 22, nginx, certbot, zsh, oh-my-zsh, autosuggestions), configures the reverse proxy, and starts the app as a systemd service.

After setup, run certbot for HTTPS:

```bash
sudo certbot --nginx -d YOUR_DOMAIN
```

Then visit your domain — you'll see a **"Set your password"** screen on first visit.

### Manual setup (without setup.sh)

Create a `.env` file in the project root:

```bash
PORT=3000
```

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 3000) |
| `WEBSHELL_PASSWORD_FILE` | No | Read the password from this file instead of the first-visit setup (see below) |

Then install dependencies and start:

```bash
npm install
node server.js
```

Visit `http://localhost:3000` — the first-visit setup screen will prompt you to choose a password. The password is bcrypt-hashed and stored in `data/webshell.db`.

## macOS + Tailscale (no public exposure)

This runs webshell on a Mac (e.g. a Mac mini at home) and reaches it only from
devices on your Tailscale tailnet. The server listens on `127.0.0.1` only;
`tailscale serve` terminates HTTPS on the tailnet name and proxies to it.
Nothing is exposed to the internet. Do not enable Funnel.

### Install

Needs Node 20+ (tested with 24), tmux (`brew install tmux`) and the Tailscale app.

```bash
git clone https://github.com/parag/webshell.git ~/Services/webshell
cd ~/Services/webshell
npm ci
```

`npm ci` runs a postinstall step that makes node-pty's `prebuilds/*/spawn-helper`
executable. node-pty 1.1.0 ships it without the executable bit, which makes every
terminal fail on macOS with `posix_spawnp failed`.

### Password file

```bash
mkdir -m 700 -p ~/.config/webshell
printf 'CHANGE-ME-dummy-password\n' > ~/.config/webshell/password
chmod 600 ~/.config/webshell/password
```

With `WEBSHELL_PASSWORD_FILE` set:

- the first-visit "set password" screen and the in-app password change are off;
- every login reads the file fresh and compares its trimmed contents with what you typed;
- while the file is missing, empty or still `CHANGE-ME-dummy-password`, every login is
  refused with "set a password in <path>";
- editing the file signs out every existing session, including open terminals
  (within about 15 seconds).

Edit the file to set or change the password. No restart needed.

### tmux

A `~/.tmux.conf` that works well with xterm.js:

```
set -sg escape-time 10
set -g extended-keys on
set -as terminal-features 'xterm*:extkeys'
set -g mouse on
set -g set-clipboard on
set -g history-limit 50000
set -g default-terminal "tmux-256color"
```

### LaunchAgent

`~/Library/LaunchAgents/com.parag.webshell.plist` (adjust the user name and Node path):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.parag.webshell</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.nvm/versions/node/v24.2.0/bin/node</string>
    <string>/Users/YOU/Services/webshell/server.js</string>
  </array>
  <key>WorkingDirectory</key><string>/Users/YOU/Services/webshell</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/Users/YOU/.local/bin:/Users/YOU/.nvm/versions/node/v24.2.0/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>PORT</key><string>3000</string>
    <key>LANG</key><string>en_US.UTF-8</string>
    <key>LC_ALL</key><string>en_US.UTF-8</string>
    <key>WEBSHELL_PASSWORD_FILE</key><string>/Users/YOU/.config/webshell/password</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>AbandonProcessGroup</key><true/>
  <key>StandardOutPath</key><string>/Users/YOU/Library/Logs/webshell.log</string>
  <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/webshell.err.log</string>
</dict>
</plist>
```

`AbandonProcessGroup` keeps the tmux server (and your sessions) alive when launchd
restarts webshell.

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.parag.webshell.plist
launchctl kickstart -k gui/$(id -u)/com.parag.webshell   # restart after a git pull
launchctl bootout gui/$(id -u)/com.parag.webshell        # stop and unload
lsof -nP -iTCP:3000 -sTCP:LISTEN                         # should show 127.0.0.1:3000 only
```

A LaunchAgent runs in your login session, so the Mac has to be logged in
(with FileVault on, someone must log in after a reboot).

### Tailscale Serve

HTTPS certificates must be enabled for the tailnet (admin console, DNS page).
Then:

```bash
tailscale serve --bg 3000
tailscale serve status
```

Open `https://<machine>.<tailnet>.ts.net/` from any device on the tailnet.

### Notes

- `/api/notify` accepts unauthenticated requests only when they come straight from
  the same machine (`curl http://127.0.0.1:3000/api/notify ...`). Requests relayed
  by `tailscale serve` or nginx need a token.
- Logins are limited to 5 failures per minute per client, then locked out for a minute,
  doubling on each repeat up to 15 minutes. Behind `tailscale serve` every request
  arrives from 127.0.0.1, so for loopback peers the client is the
  `Tailscale-User-Login` header, then the first `X-Forwarded-For` hop; one person's
  typos do not lock out the rest of the tailnet. These headers are ignored from any
  other peer. Lockouts are logged as `login lockout: ts:<login> for 60s`. Such a
  request still does not count as local for `/api/notify`. Test: `node --test test/*.test.js`.
- Tokens expire after 30 days.
- The WebSocket still carries the token as a query parameter (browsers cannot set
  headers on a WebSocket). File downloads and image previews send it as a header.
- On touch devices a small key bar under the terminal adds Esc, Tab, Shift-Tab,
  Ctrl-C, Ctrl-D, arrows and Enter.

## Usage

1. Visit `https://YOUR_DOMAIN`
2. **First visit:** choose a password. **Returning:** sign in.
3. Create a **project** to organize your sessions
4. Open a project, tap **+ New** to create a terminal session
5. Tap any session to resume it
6. Tap **←** to detach (session stays alive)
7. Tap the **hamburger menu** (top-left) to open the sidebar — switch between any session across all projects without navigating back
8. Tap **Settings** in the sidebar to change your password

## Architecture

```
Browser → nginx (HTTPS) → Node.js (:3000) → node-pty → tmux sessions
                                ↓
                          SQLite (data/webshell.db)
```

## Security

- HTTPS via Let's Encrypt (auto-renewing)
- Password hashed with bcrypt (cost factor 12)
- First-visit setup — no default password, no password in config files
- Token-based session auth on all API + WebSocket endpoints; tokens expire after 30 days
- Password change invalidates all other sessions
- Login rate limit: 5 failures per minute per client (Tailscale login behind Serve), then an escalating lockout
- tmux is always run with an argument list, never through a shell
- No third-party CDN: frontend libraries are served from `public/vendor/`
- nginx reverse proxy — only ports 80/443 exposed
- Session name sanitization to prevent command injection

## License

MIT
