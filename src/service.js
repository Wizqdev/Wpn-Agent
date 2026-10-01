/**
 * @fileoverview systemd service install/uninstall for the wpn-agent itself.
 *
 * `install()` copies the agent tree to `/opt/wpn-agent` (preserving `.git`
 * when present so `POST /update` can fast-forward later), writes the systemd
 * unit, and starts (or restarts) the service so upgrades take effect
 * immediately.
 *
 * `uninstall()` performs a full teardown: stops the agent AND the data plane
 * it manages — `wg0`, the stealth relay, the sysctl forwarding drop-in, and
 * the dedicated nftables table.  Identity material in `/etc/wpn-agent` and
 * the WireGuard server key are preserved so a reinstall reuses the same
 * credentials.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const { runBin, tryRunBin, log } = require("./util");

const DEST       = "/opt/wpn-agent";
const UNIT       = "/etc/systemd/system/wpn-agent.service";
const STEALTH    = "/etc/systemd/system/wpn-stealth.service";
const SYSCTL     = "/etc/sysctl.d/99-wpn.conf";
const WG_IFACE   = process.env.WPN_WG_IFACE || "wg0";
const WG_CONF    = `/etc/wireguard/${WG_IFACE}.conf`;
const ENV_FILE   = `${process.env.WPN_AGENT_DIR || "/etc/wpn-agent"}/agent.env`;

/**
 * Render the wpn-agent systemd unit.  Single source of truth: used by
 * {@link install} and by {@link referenceUnit} (the checked-in
 * `systemd/wpn-agent.service`), so the two can never drift apart.
 *
 * @param {{ agentPort: number, execStart?: string, envFile?: string }} opts
 * @returns {string}
 */
function renderUnit({
  agentPort,
  execStart = `${process.execPath} ${DEST}/bin/wpn-agent`,
  envFile   = ENV_FILE,
}) {
  return [
    "[Unit]",
    "Description=Wpn WireGuard node agent",
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Service]",
    `Environment=WPN_AGENT_PORT=${agentPort}`,
    // Optional operator overrides — see .env.example for the full list.
    `EnvironmentFile=-${envFile}`,
    `ExecStart=${execStart}`,
    "Restart=always",
    "RestartSec=3",
    // Light sandboxing that does not impede net-admin duties.
    "ProtectHome=true",
    "PrivateTmp=true",
    "NoNewPrivileges=true",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

/**
 * Exact contents of the checked-in `systemd/wpn-agent.service`.  Regenerate
 * with `npm run gen:unit`; a test fails if the file drifts from the template.
 *
 * @returns {string}
 */
const referenceUnit = () =>
  "# Reference unit — `wpn-agent --install` writes this itself.\n" +
  renderUnit({
    agentPort: 44664,
    execStart: "/usr/bin/node /opt/wpn-agent/bin/wpn-agent",
    envFile:   "/etc/wpn-agent/agent.env",
  });

/**
 * Deploy the agent to `/opt/wpn-agent` and register it as a systemd service.
 * Safe to call on an already-installed agent — it will overwrite the files and
 * restart the service, effectively performing an in-place upgrade.
 *
 * @param {number} agentPort - Control-API TCP port baked into the unit file.
 * @returns {Promise<void>}
 */
async function install(agentPort) {
  fs.mkdirSync(DEST, { recursive: true });

  // Copy the whole tree (dotfiles included — `.git` comes along so the
  // `/update` endpoint can fast-forward this checkout later).
  const srcRoot = path.join(__dirname, "..");
  if (srcRoot !== DEST) {
    fs.rmSync(DEST, { recursive: true, force: true });
    fs.mkdirSync(DEST, { recursive: true });
    fs.cpSync(srcRoot, DEST, { recursive: true });
    fs.chmodSync(path.join(DEST, "bin", "wpn-agent"), 0o755);
  }

  fs.writeFileSync(UNIT, renderUnit({ agentPort }));

  await runBin("systemctl", ["daemon-reload"]);
  await runBin("systemctl", ["enable", "wpn-agent"]);
  // Use `restart` (not `start`) so an upgrade swaps the running code.
  await runBin("systemctl", ["restart", "wpn-agent"]);

  log.ok("installed + started as systemd service 'wpn-agent'");
  log.info("logs:  journalctl -u wpn-agent -f");
}

/**
 * Stop, disable, and remove the systemd services, the `/opt/wpn-agent`
 * directory, and the data-plane state the agent created:
 *   - `wg0` is taken down (PostDown removes its NAT/forward/clamp rules)
 *   - `wg-quick@wg0` is disabled so it does not come back on boot
 *   - the `inet wpn` nftables table is flushed (defensive; PostDown usually did it)
 *   - `/etc/sysctl.d/99-wpn.conf` is removed and sysctls reloaded
 *
 * Identity material (`/etc/wpn-agent`, `/etc/wireguard/server.key`) is
 * intentionally preserved — the node can be reinstated without generating
 * new credentials.
 *
 * @returns {Promise<void>}
 */
async function uninstall() {
  // Control plane + stealth relay.
  await tryRunBin("systemctl", ["disable", "--now", "wpn-agent"]);
  await tryRunBin("systemctl", ["disable", "--now", "wpn-stealth"]);
  fs.rmSync(UNIT,    { force: true });
  fs.rmSync(STEALTH, { force: true });

  // Data plane: bring wg0 down (runs PostDown → removes NAT rules), then stop
  // it from ever coming back automatically.
  if (fs.existsSync(WG_CONF)) await tryRunBin("wg-quick", ["down", WG_CONF]);
  await tryRunBin("systemctl", ["disable", `wg-quick@${WG_IFACE}`]);
  await tryRunBin("nft", ["delete", "table", "inet", "wpn"]); // no-op if absent / iptables backend

  // Forwarding drop-in we installed.
  if (fs.existsSync(SYSCTL)) {
    fs.rmSync(SYSCTL, { force: true });
    await tryRunBin("sysctl", ["--system", "-q"]);
  }

  await tryRunBin("systemctl", ["daemon-reload"]);
  fs.rmSync(DEST, { recursive: true, force: true });
  log.ok("service removed + data plane torn down (identity kept in /etc/wpn-agent)");
}

module.exports = { install, uninstall, renderUnit, referenceUnit };
