/**
 * @fileoverview systemd service install/uninstall for the wpn-agent itself.
 *
 * `install()` copies the agent tree to `/opt/wpn-agent`, writes the systemd
 * unit, and starts (or restarts) the service so upgrades take effect
 * immediately.
 *
 * `uninstall()` stops + disables the service and removes `/opt/wpn-agent`.
 * Identity material in `/etc/wpn-agent` is preserved so a reinstall reuses
 * the same token and TLS cert.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const { run, log } = require("./util");

const DEST = "/opt/wpn-agent";
const UNIT = "/etc/systemd/system/wpn-agent.service";

/**
 * Deploy the agent to `/opt/wpn-agent` and register it as a systemd service.
 * Safe to call on an already-installed agent — it will overwrite the files and
 * restart the service, effectively performing an in-place upgrade.
 *
 * @param {number} agentPort - Control-API TCP port baked into the unit file.
 */
function install(agentPort) {
  fs.mkdirSync(DEST, { recursive: true });

  for (const item of ["src", "bin", "package.json"]) {
    const src = path.join(__dirname, "..", item);
    const dst = path.join(DEST, item);
    if (src === dst) continue; // already running from /opt — skip self-copy
    fs.rmSync(dst, { recursive: true, force: true });
    fs.cpSync(src, dst, { recursive: true });
  }

  fs.writeFileSync(
    UNIT,
    [
      "[Unit]",
      "Description=Wpn WireGuard node agent",
      "After=network-online.target",
      "Wants=network-online.target",
      "",
      "[Service]",
      `Environment=WPN_AGENT_PORT=${agentPort}`,
      `ExecStart=${process.execPath} ${DEST}/bin/wpn-agent`,
      "Restart=always",
      "RestartSec=3",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "",
    ].join("\n")
  );

  run("systemctl daemon-reload");
  run("systemctl enable wpn-agent");
  // Use `restart` (not `start`) so an upgrade swaps the running code.
  run("systemctl restart wpn-agent");

  log.ok("installed + started as systemd service 'wpn-agent'");
  log.info("logs:  journalctl -u wpn-agent -f");
}

/**
 * Stop, disable, and remove the systemd service and the `/opt/wpn-agent`
 * directory.  The identity directory (`/etc/wpn-agent`) is intentionally
 * preserved — the node can be reinstated without generating new credentials.
 */
function uninstall() {
  try {
    run("systemctl disable --now wpn-agent");
  } catch {}
  fs.rmSync(UNIT, { force: true });
  try {
    run("systemctl daemon-reload");
  } catch {}
  fs.rmSync(DEST, { recursive: true, force: true });
  log.ok("service removed (identity kept in /etc/wpn-agent)");
}

module.exports = { install, uninstall };
