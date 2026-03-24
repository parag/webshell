#!/bin/bash
set -euo pipefail

DOMAIN="remote.paragarora.com"
APP_DIR="/home/ubuntu/Workspace/remote/terminal-server"
APP_PORT=3000

echo "=== Terminal Server Setup ==="
echo ""

# --- Node.js 22 LTS ---
if ! command -v node &>/dev/null || [[ "$(node -v)" != v22* ]]; then
  echo "[1/6] Installing Node.js 22 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y nodejs
else
  echo "[1/6] Node.js 22 already installed."
fi

# --- Build tools + nginx + certbot ---
echo "[2/6] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y build-essential nginx certbot python3-certbot-nginx zsh

# --- zsh + oh-my-zsh + autosuggestions ---
echo "[3/6] Setting up zsh with autosuggestions..."
if [ ! -d "$HOME/.oh-my-zsh" ]; then
  RUNZSH=no CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
fi

ZSH_AUTOSUGGEST_DIR="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-autosuggestions"
if [ ! -d "$ZSH_AUTOSUGGEST_DIR" ]; then
  git clone https://github.com/zsh-users/zsh-autosuggestions "$ZSH_AUTOSUGGEST_DIR"
fi

# Enable the plugin in .zshrc
if ! grep -q "zsh-autosuggestions" "$HOME/.zshrc" 2>/dev/null; then
  sed -i 's/plugins=(git)/plugins=(git zsh-autosuggestions)/' "$HOME/.zshrc"
fi

# Set zsh as default shell
if [ "$SHELL" != "$(which zsh)" ]; then
  sudo chsh -s "$(which zsh)" "$USER"
fi

# Configure tmux to use zsh
if ! grep -q "default-shell" "$HOME/.tmux.conf" 2>/dev/null; then
  echo "set-option -g default-shell $(which zsh)" >> "$HOME/.tmux.conf"
fi

# --- npm install ---
echo "[4/6] Installing Node.js dependencies..."
cd "$APP_DIR"
npm install

# --- Generate password ---
TERM_PASSWORD=$(openssl rand -base64 24)
cat > "$APP_DIR/.env" <<EOF
TERM_PASSWORD=$TERM_PASSWORD
PORT=$APP_PORT
EOF
chmod 600 "$APP_DIR/.env"

# --- nginx config ---
echo "[5/6] Configuring nginx..."
sudo tee /etc/nginx/sites-available/terminal-server > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/terminal-server /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx

# --- systemd service ---
echo "[6/6] Creating systemd service..."
sudo tee /etc/systemd/system/terminal-server.service > /dev/null <<EOF
[Unit]
Description=Web Terminal Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$(which node) server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable terminal-server
sudo systemctl start terminal-server

echo ""
echo "=== Setup Complete ==="
echo ""
echo "App running at: http://$DOMAIN"
echo ""
echo "Now run certbot for HTTPS:"
echo "  sudo certbot --nginx -d $DOMAIN"
echo ""
echo "Your password is:"
echo "  $TERM_PASSWORD"
echo ""
echo "Save this password! It's stored in $APP_DIR/.env"
echo ""
