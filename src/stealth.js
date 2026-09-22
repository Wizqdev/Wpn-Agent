// Stealth transport — wstunnel wraps WireGuard UDP in WebSocket-over-TLS on
// tcp/443 (looks like HTTPS). WireGuard still does the crypto; wstunnel is
// camouflage. The per-node stealthKey path prefix is what stops strangers
// relaying through the listener.
//
//   ensure(dir, { wgPort })  → { enabled, port, key, error? } — installs the
//                              pinned binary, writes the systemd unit, starts it
//   status()                 → same shape, cheap re-check for /capabilities

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { run, tryRun, log } = require("./util");

// Pinned wstunnel release — bump deliberately, never float.
const WST_VERSION = "10.6.2";
const ASSETS = {
  "linux-x64": { file: `wstunnel_${WST_VERSION}_linux_amd64.tar.gz`, sha256: "db6064cca0515b67f8652e201cff8e27553b8cbb7216b2e19241311e34868e6e" },
  "linux-arm64": { file: `wstunnel_${WST_VERSION}_linux_arm64.tar.gz`, sha256: "26bb36b856948255bec7cd71a39df5f8912acdd7a47a9ccd4044a9b80ced108d" },
  "darwin-arm64": { file: `wstunnel_${WST_VERSION}_darwin_arm64.tar.gz`, sha256: "c3fb062254947d3aeb70b3813fc6e1e2cf954f60fb9397ae0bb6debc263f1237" },
  "darwin-x64": { file: `wstunnel_${WST_VERSION}_darwin_amd64.tar.gz`, sha256: "adf570ec5f158af7cef6ff4b0c4a7c2685b8c39dca34b531db549a5110ad3944" },
};
const BASE_URL = `https://github.com/erebe/wstunnel/releases/download/v${WST_VERSION}`;
const BIN = "/opt/wpn-agent/bin/wstunnel";
const KEY_FILE = "stealth.key";
const UNIT = "/etc/systemd/system/wpn-stealth.service";

const keyOf = (dir) => `${process.platform}-${process.arch === "arm64" ? "arm64" : "x64"}`;

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

// Download the pinned tarball, verify sha256 twice — against the hash pinned
// in code AND the release's own checksums.txt — then extract the binary.
async function install() {
  const asset = ASSETS[keyOf()];
  if (!asset) throw new Error(`no wstunnel build for ${process.platform}/${process.arch}`);
  const tmp = `/tmp/wstunnel-${WST_VERSION}.tar.gz`;
  tryRun(`curl -fsSL -o ${tmp} ${BASE_URL}/${asset.file}`);
  if (!fs.existsSync(tmp)) throw new Error("download failed");
  const got = sha256(tmp);
  if (got !== asset.sha256) {
    fs.unlinkSync(tmp);
    throw new Error(`sha256 mismatch: ${got.slice(0, 12)}… ≠ pinned`);
  }
  const sums = tryRun(`curl -fsSL ${BASE_URL}/checksums.txt`);
  if (sums && !sums.includes(`${asset.sha256}  ${asset.file}`)) {
    fs.unlinkSync(tmp);
    throw new Error("release checksums.txt disagrees with pinned hash");
  }
  fs.mkdirSync(path.dirname(BIN), { recursive: true });
  run(`tar -xzf ${tmp} -C ${path.dirname(BIN)} wstunnel`);
  fs.chmodSync(BIN, 0o755);
  fs.unlinkSync(tmp);
}

function stealthKey(dir) {
  const p = path.join(dir, KEY_FILE);
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, crypto.randomBytes(32).toString("base64url") + "\n", { mode: 0o600 });
  }
  return fs.readFileSync(p, "utf8").trim();
}

function pickPort() {
  if (process.env.WPN_STEALTH_PORT) return parseInt(process.env.WPN_STEALTH_PORT, 10);
  // 443 if free, else 8443 — cheap bind probe
  for (const p of [443, 8443]) {
    const probe = require("net").createServer();
    try {
      probe.listen(p, "0.0.0.0");
      probe.close();
      return p;
    } catch {}
  }
  return 8443;
}

// Starts (or confirms) the wstunnel relay. Never throws — stealth is optional;
// failures are reported so /capabilities can advertise honestly.
async function ensure(dir, { wgPort }) {
  if (process.env.WPN_STEALTH === "0") return { enabled: false };
  try {
    if (!fs.existsSync(BIN)) {
      log.info("stealth: installing wstunnel…");
      await install();
    }
    const key = stealthKey(dir);
    const port = pickPort();
    if (process.platform === "linux") {
      fs.writeFileSync(
        UNIT,
        `[Unit]\nDescription=Wpn stealth transport (wstunnel)\nAfter=network.target wpn-agent.service\n\n` +
          `[Service]\nExecStart=${BIN} server wss://0.0.0.0:${port} --restrict-to 127.0.0.1:${wgPort} --restrict-http-upgrade-path-prefix ${key}\n` +
          `Restart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n`
      );
      tryRun("systemctl daemon-reload");
      tryRun("systemctl enable --now wpn-stealth");
    }
    // dev path (darwin smoke): no systemd — just report configured
    return { enabled: true, port, key };
  } catch (e) {
    return { enabled: false, error: e.message };
  }
}

module.exports = { ensure, BIN, WST_VERSION };
