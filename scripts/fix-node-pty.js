// node-pty 1.1.0 ships prebuilds/*/spawn-helper without the executable bit.
// On macOS that makes every pty.spawn fail with "posix_spawnp failed".
// Runs as npm postinstall; harmless where node-pty or its prebuilds are absent.
const fs = require('fs');
const path = require('path');

let ptyDir;
try {
  ptyDir = path.dirname(require.resolve('node-pty/package.json'));
} catch {
  process.exit(0);
}

const prebuilds = path.join(ptyDir, 'prebuilds');
if (!fs.existsSync(prebuilds)) process.exit(0);

for (const platform of fs.readdirSync(prebuilds)) {
  const helper = path.join(prebuilds, platform, 'spawn-helper');
  if (!fs.existsSync(helper)) continue;
  const mode = fs.statSync(helper).mode;
  if ((mode & 0o111) !== 0o111) {
    fs.chmodSync(helper, mode | 0o755);
    console.log(`webshell postinstall: made ${path.relative(process.cwd(), helper)} executable`);
  }
}
