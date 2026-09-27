/**
 * @fileoverview Stealth transport — wraps WireGuard UDP in WebSocket-over-TLS
 * on tcp/443 using the pinned `wstunnel` binary.  From the outside the traffic
 * looks like HTTPS; WireGuard handles all the actual crypto.
 *
 * The per-node `stealthKey` path prefix acts as a pre-shared secret so random
 * clients on the internet cannot relay through the listener.
 *
 * `ensure(dir, { wgPort })` is the only public entry point.  It never throws —
 * stealth is an optional enhancement; failures degrade gracefully so
 * `/capabilities` can advertise `stealth: false` with an explanation.
 */

"use strict";

const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");
const net    = require("net");
const { run, tryRun, log } = require("./util");

// ---------------------------------------------------------------------------
// Pinned release — bump deliberately, never float.
// ---------------------------------------------------------------------------

const WST_VERSION = "10.6.2";

/** @type {Record<string, {file: string, sha256: string}>} */
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Derive the asset key for the current platform/arch combination.
 *
 * @returns {string} e.g. `"linux-x64"`
 */
const platformKey = () =>
  `${process.platform}-${process.arch === "arm64" ? "arm64" : "x64"}`;

/**
 * Compute the SHA-256 hex digest of a file.
 *
 * @param {string} file - Absolute path.
 * @returns {string} Hex digest.
 */
const sha256 = (file) =>
  crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

/**
 * Download the pinned `wstunnel` tarball, verify its SHA-256 against the
 * pinned hash AND the upstream `checksums.txt`, then extract the binary.
 *
 * @returns {Promise<void>}
 */
async function install() {
  const asset = ASSETS[platformKey()];
  if (!asset) {
    throw new Error(`no wstunnel build for ${process.platform}/${process.arch}`);
  }

  const tmp = `/tmp/wstunnel-${WST_VERSION}.tar.gz`;
  tryRun(`curl -fsSL -o ${tmp} ${BASE_URL}/${asset.file}`);
  if (!fs.existsSync(tmp)) throw new Error("download failed");

  const got = sha256(tmp);
  if (got !== asset.sha256) {
    fs.unlinkSync(tmp);
    throw new Error(`sha256 mismatch: ${got.slice(0, 12)}… ≠ pinned`);
  }

  // Secondary verification against upstream checksums.txt.
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

/**
 * Return the per-node stealth key, creating it if absent.
 *
 * @param {string} dir - Agent identity directory.
 * @returns {string} Base64url-encoded 256-bit key.
 */
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

/**
 * Select the stealth port — 443 if a bind probe succeeds, 8443 as fallback.
 * `WPN_STEALTH_PORT` overrides both.
 *
 * @returns {number}
 */
function pickPort() {
  if (process.env.WPN_STEALTH_PORT) {
    return parseInt(process.env.WPN_STEALTH_PORT, 10);
  }
  for (const p of [443, 8443]) {
    const probe = net.createServer();
    try {
      probe.listen(p, "0.0.0.0");
      probe.close();
      return p;
    } catch {
      // port in use — try next
    }
  }
  return 8443;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * @typedef {{ enabled: true,  port: number, key: string } |
 *            { enabled: false, error?: string }} StealthState
 */

/**
 * Install and start the `wstunnel` stealth relay.  Never throws; failures
 * are returned as `{ enabled: false, error }`.
 *
 * @param {string} dir - Agent identity directory.
 * @param {{ wgPort: number }} opts
 * @returns {Promise<StealthState>}
 */
async function ensure(dir, { wgPort }) {
  if (process.env.WPN_STEALTH === "0") return { enabled: false };
  try {
    if (!fs.existsSync(BIN)) {
      log.info("stealth: installing wstunnel…");
      await install();
    }

    const key  = stealthKey(dir);
    const port = pickPort();

    if (process.platform === "linux") {
      const execArgs =
        `server wss://0.0.0.0:${port}` +
        ` --restrict-to 127.0.0.1:${wgPort}` +
        ` --restrict-http-upgrade-path-prefix ${key}`;
      fs.writeFileSync(
        UNIT,
        [
          "[Unit]",
          "Description=Wpn stealth transport (wstunnel)",
          "After=network.target wpn-agent.service",
          "",
          "[Service]",
          `ExecStart=${BIN} ${execArgs}`,
          "Restart=always",
          "RestartSec=3",
          "",
          "[Install]",
          "WantedBy=multi-user.target",
          "",
        ].join("\n")
      );
      tryRun("systemctl daemon-reload");
      tryRun("systemctl enable --now wpn-stealth");
    }

    // On non-Linux (macOS dev smoke): no systemd — just report configured.
    return { enabled: true, port, key };
  } catch (e) {
    return { enabled: false, error: e.message };
  }
}

module.exports = { ensure, BIN, WST_VERSION };
