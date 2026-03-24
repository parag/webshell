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
- **Frontend:** xterm.js (CDN, no build step), vanilla JS SPA
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

Then install dependencies and start:

```bash
npm install
node server.js
```

Visit `http://localhost:3000` — the first-visit setup screen will prompt you to choose a password. The password is bcrypt-hashed and stored in `data/webshell.db`.

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
- Token-based session auth on all API + WebSocket endpoints
- Password change invalidates all other sessions
- nginx reverse proxy — only ports 80/443 exposed
- Session name sanitization to prevent command injection

## License

MIT
