
"use strict";

const fs     = require("fs");
const os     = require("os");
const path   = require("path");
const crypto = require("crypto");
const net    = require("net");
const { runBin, tryRunBin, log } = require("./util");

const WST_VERSION = "10.6.2";

const ASSETS = {
  "linux-x64": {
    file:   `wstunnel_${WST_VERSION}_linux_amd64.tar.gz`,
    sha256: "db6064cca0515b67f8652e201cff8e27553b8cbb7216b2e19241311e34868e6e",
  },
  "linux-arm64": {
    file:   `wstunnel_${WST_VERSION}_linux_arm64.tar.gz`,
    sha256: "26bb36b856948255bec7cd71a39df5f8912acdd7a47a9ccd4044a9b80ced108d",
  },
  "darwin-arm64": {
    file:   `wstunnel_${WST_VERSION}_darwin_arm64.tar.gz`,
    sha256: "c3fb062254947d3aeb70b3813fc6e1e2cf954f60fb9397ae0bb6debc263f1237",
  },
  "darwin-x64": {
    file:   `wstunnel_${WST_VERSION}_darwin_amd64.tar.gz`,
    sha256: "adf570ec5f158af7cef6ff4b0c4a7c2685b8c39dca34b531db549a5110ad3944",
  },
};

const BASE_URL = `https://github.com/erebe/wstunnel/releases/download/v${WST_VERSION}`;
const BIN      = "/opt/wpn-agent/bin/wstunnel";
const KEY_FILE = "stealth.key";
const UNIT     = "/etc/systemd/system/wpn-stealth.service";

const platformKey = () =>
  `${process.platform}-${process.arch === "arm64" ? "arm64" : "x64"}`;

const sha256 = (file) =>
  crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

async function install() {
  const asset = ASSETS[platformKey()];
  if (!asset) {
    throw new Error(`no wstunnel build for ${process.platform}/${process.arch}`);
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wstunnel-"));
  const tmp = path.join(dir, asset.file);
  try {
    const url = `${BASE_URL}/${asset.file}`;
    try {
      await runBin("curl", ["-fsSL", "-o", tmp, url]);
    } catch {
      await runBin("wget", ["-qO", tmp, url]).catch(() => {});
    }
    if (!fs.existsSync(tmp)) throw new Error("download failed");

    const got = sha256(tmp);
    if (got !== asset.sha256) {
      throw new Error(`sha256 mismatch: ${got.slice(0, 12)}… ≠ pinned`);
    }

    const sumsUrl = `${BASE_URL}/checksums.txt`;
    const sums =
      (await tryRunBin("curl", ["-fsSL", sumsUrl])) ||
      (await tryRunBin("wget", ["-qO-", sumsUrl]));
    if (sums && !sums.includes(`${asset.sha256}  ${asset.file}`)) {
      throw new Error("release checksums.txt disagrees with pinned hash");
    }

    fs.mkdirSync(path.dirname(BIN), { recursive: true });
    await runBin("tar", ["-xzf", tmp, "-C", path.dirname(BIN), "wstunnel"]);
    fs.chmodSync(BIN, 0o755);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function stealthKey(dir) {
  const p = path.join(dir, KEY_FILE);
  if (!fs.existsSync(p)) {
    fs.writeFileSync(
      p,
      crypto.randomBytes(32).toString("base64url") + "\n",
      { mode: 0o600 }
    );
  }
  return fs.readFileSync(p, "utf8").trim();
}

function canBind(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.once("listening", () => probe.close(() => resolve(true)));
    probe.listen(port, "0.0.0.0");
  });
}

function renderUnit({ bin, port, key, wgPort }) {
  const execArgs =
    `server wss://0.0.0.0:${port}` +
    ` --restrict-to 127.0.0.1:${wgPort}` +
    ` --restrict-http-upgrade-path-prefix ${key}`;
  return [
    "[Unit]",
    "Description=Wpn stealth transport (wstunnel)",
    "After=network-online.target wpn-agent.service",
    "Wants=network-online.target",
    "",
    "[Service]",
    `ExecStart=${bin} ${execArgs}`,
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

function readUnitPort(unitPath) {
  try {
    const m = fs.readFileSync(unitPath, "utf8").match(/server wss:\/\/0\.0\.0\.0:(\d+)/);
    return m ? parseInt(m[1], 10) : null;
  } catch {
    return null;
  }
}

const tcpConnect = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ port, host: "127.0.0.1" });
    const done = (ok) => { s.destroy(); resolve(ok); };
    s.setTimeout(1_000, () => done(false));
    s.once("connect", () => done(true));
    s.once("error",   () => done(false));
  });

async function probe(port, tries = 6) {
  for (let i = 0; i < tries; i++) {
    if (await tcpConnect(port)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

async function pickPort(candidates = [443, 8443]) {
  if (process.env.WPN_STEALTH_PORT) {
    return parseInt(process.env.WPN_STEALTH_PORT, 10);
  }
  for (const p of candidates) {
    if (await canBind(p)) return p;
  }
  return candidates[candidates.length - 1];
}

async function ensure(dir, { wgPort }, deps = {}) {
  if (process.env.WPN_STEALTH === "0") return { enabled: false };
  const platform = deps.platform || process.platform;
  const unitPath = deps.unit || UNIT;
  const bin      = deps.bin  || BIN;
  try {
    if (!fs.existsSync(bin)) {
      log.info("stealth: installing wstunnel…");
      await install();
    }

    const key   = stealthKey(dir);
    const linux = platform === "linux";
    const isActive = async () =>
      (await tryRunBin("systemctl", ["is-active", "wpn-stealth"])) === "active";

    const existingPort = linux ? readUnitPort(unitPath) : null;
    const wasActive    = existingPort !== null && (await isActive());
    const port =
      wasActive && !process.env.WPN_STEALTH_PORT
        ? existingPort
        : await pickPort(deps.candidates);

    if (linux) {
      const unit = renderUnit({ bin, port, key, wgPort });
      const prev = fs.existsSync(unitPath) ? fs.readFileSync(unitPath, "utf8") : null;
      const changed = prev !== unit;
      if (changed) {

        fs.writeFileSync(unitPath, unit, { mode: 0o600 });
        fs.chmodSync(unitPath, 0o600);
        await tryRunBin("systemctl", ["daemon-reload"]);
      }
      await tryRunBin("systemctl", ["enable", "--now", "wpn-stealth"]);

      if (changed && wasActive) await tryRunBin("systemctl", ["restart", "wpn-stealth"]);

      await new Promise((r) => setTimeout(r, deps.settleMs ?? 800));
      const active = await tryRunBin("systemctl", ["is-active", "wpn-stealth"]);
      if (active !== "active") {
        return {
          enabled: false,
          error: `wpn-stealth unit is ${active || "unknown"} (check journalctl -u wpn-stealth)`,
        };
      }
      if (!(await (deps.probe || probe)(port))) {
        return {
          enabled: false,
          error: `wpn-stealth is active but nothing is listening on tcp/${port} (check journalctl -u wpn-stealth)`,
        };
      }
    }

    return { enabled: true, port, key };
  } catch (e) {
    return { enabled: false, error: e.message };
  }
}

module.exports = { ensure, pickPort, canBind, readUnitPort };
