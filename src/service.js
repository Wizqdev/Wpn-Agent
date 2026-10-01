
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
    `EnvironmentFile=-${envFile}`,
    `ExecStart=${execStart}`,
    "Restart=always",
    "RestartSec=3",

    "ProtectHome=true",
    "PrivateTmp=true",
    "NoNewPrivileges=true",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

const referenceUnit = () =>
  renderUnit({
    agentPort: 44664,
    execStart: "/usr/bin/node /opt/wpn-agent/bin/wpn-agent",
    envFile:   "/etc/wpn-agent/agent.env",
  });

async function install(agentPort) {
  fs.mkdirSync(DEST, { recursive: true });

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

  await runBin("systemctl", ["restart", "wpn-agent"]);

  log.ok("installed + started as systemd service 'wpn-agent'");
  log.info("logs:  journalctl -u wpn-agent -f");
}

async function uninstall() {

  await tryRunBin("systemctl", ["disable", "--now", "wpn-agent"]);
  await tryRunBin("systemctl", ["disable", "--now", "wpn-stealth"]);
  fs.rmSync(UNIT,    { force: true });
  fs.rmSync(STEALTH, { force: true });

  if (fs.existsSync(WG_CONF)) await tryRunBin("wg-quick", ["down", WG_CONF]);
  await tryRunBin("systemctl", ["disable", `wg-quick@${WG_IFACE}`]);
  await tryRunBin("nft", ["delete", "table", "inet", "wpn"]);

  if (fs.existsSync(SYSCTL)) {
    fs.rmSync(SYSCTL, { force: true });
    await tryRunBin("sysctl", ["--system", "-q"]);
  }

  await tryRunBin("systemctl", ["daemon-reload"]);
  fs.rmSync(DEST, { recursive: true, force: true });
  log.ok("service removed + data plane torn down (identity kept in /etc/wpn-agent)");
}

module.exports = { install, uninstall, renderUnit, referenceUnit };
