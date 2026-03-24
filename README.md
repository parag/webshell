# webshell

A mobile-first web terminal that connects to your server via the browser. Powered by tmux — sessions persist across disconnects.

## Features

- **Session management** — create, resume, and delete terminal sessions from a clean UI
- **Persistent sessions** — powered by tmux; close the browser, come back later, pick up where you left off
- **Mobile-optimized** — full-screen terminal with touch support, virtual keyboard handling
- **Secure** — HTTPS via Let's Encrypt, password auth, no unnecessary open ports
- **Autosuggestions** — zsh + oh-my-zsh + zsh-autosuggestions out of the box

## Stack

- **Backend:** Node.js + Express + WebSocket + node-pty
- **Frontend:** xterm.js (CDN, no build step), vanilla JS SPA
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

The script generates a random password and saves it to `.env`. It prints the password at the end — save it somewhere safe.

### Manual setup (without setup.sh)

Create a `.env` file in the project root:

```bash
TERM_PASSWORD=your-secure-password-here
PORT=3000
```

| Variable | Required | Description |
|----------|----------|-------------|
| `TERM_PASSWORD` | Yes | Password for the web login |
| `PORT` | No | Server port (default: 3000) |

Then install dependencies and start:

```bash
npm install
source .env && node server.js
```

## Usage

1. Visit `https://YOUR_DOMAIN`
2. Enter your password
3. Tap **+ New** to create a terminal session
4. Tap any session to resume it
5. Tap **←** to detach (session stays alive)

## Architecture

```
Browser → nginx (HTTPS) → Node.js (:3000) → node-pty → tmux sessions
```

## Security

- HTTPS via Let's Encrypt (auto-renewing)
- App-level password authentication with token-based sessions
- nginx reverse proxy — only ports 80/443 exposed
- Session name sanitization to prevent command injection
- Timing-safe password comparison

## License

MIT
