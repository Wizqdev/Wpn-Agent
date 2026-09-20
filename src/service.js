// systemd install/uninstall for the agent itself.

const fs = require("fs");
const path = require("path");
const { run, log } = require("./util");

const DEST = "/opt/wpn-agent";
const UNIT = "/etc/systemd/system/wpn-agent.service";

function install(agentPort) {
  fs.mkdirSync(DEST, { recursive: true });
  for (const item of ["src", "bin", "package.json"]) {
    const src = path.join(__dirname, "..", item);
    const dst = path.join(DEST, item);
    if (src === dst) continue; // already running from /opt — don't self-copy
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
  // restart (not just start) so upgrades actually swap the running code
  run("systemctl restart wpn-agent");
  log.ok("installed + started as systemd service 'wpn-agent'");
  log.info("logs:  journalctl -u wpn-agent -f");
}

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
