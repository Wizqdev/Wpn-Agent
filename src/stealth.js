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
const os     = require("os");
const path   = require("path");
const crypto = require("crypto");
const net    = require("net");
const { runBin, tryRunBin, log } = require("./util");

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

  // Private (0700) temp dir — a predictable /tmp path is a symlink-race target
  // for a root process.
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

    // Secondary verification against upstream checksums.txt.
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
 * Probe whether a TCP port can be bound.  `net.Server.listen()` reports
 * EADDRINUSE asynchronously via the `'error'` event — a sync try/catch can
 * never see it — so the bind is properly awaited.
 *
 * @param {number} port
 * @returns {Promise<boolean>} `true` if the port was bindable.
 */
function canBind(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.once("listening", () => probe.close(() => resolve(true)));
    probe.listen(port, "0.0.0.0");
  });
}

/**
 * Render the `wpn-stealth` systemd unit.
 *
 * @param {{ bin: string, port: number, key: string, wgPort: number }} o
 * @returns {string}
 */
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

/**
 * Port the existing unit file is configured to listen on, if any.
 *
 * @param {string} unitPath
 * @returns {number|null}
 */
function readUnitPort(unitPath) {
  try {
    const m = fs.readFileSync(unitPath, "utf8").match(/server wss:\/\/0\.0\.0\.0:(\d+)/);
    return m ? parseInt(m[1], 10) : null;
  } catch {
    return null;
  }
}

/** @param {number} port @returns {Promise<boolean>} true if something accepts TCP on 127.0.0.1:port. */
const tcpConnect = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ port, host: "127.0.0.1" });
    const done = (ok) => { s.destroy(); resolve(ok); };
    s.setTimeout(1_000, () => done(false));
    s.once("connect", () => done(true));
    s.once("error",   () => done(false));
  });

/**
 * Wait for the relay to accept connections (it may take a moment to bind
 * after systemd reports `active`).
 *
 * @param {number} port
 * @param {number} [tries]
 * @returns {Promise<boolean>}
 */
async function probe(port, tries = 6) {
  for (let i = 0; i < tries; i++) {
    if (await tcpConnect(port)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

/**
 * Select the stealth port — try each candidate in order until a real bind
 * succeeds.  `WPN_STEALTH_PORT` overrides both.
 *
 * NOTE: probe-then-close is inherently racy — another process can grab the
 * port before wstunnel binds it.  `ensure()` therefore verifies the unit is
 * active AND listening after start rather than trusting this pick.
 *
 * @param {number[]} [candidates] - Defaults to [443, 8443].  Injectable for
 *   tests (privileged ports need root).
 * @returns {Promise<number>}
 */
async function pickPort(candidates = [443, 8443]) {
  if (process.env.WPN_STEALTH_PORT) {
    return parseInt(process.env.WPN_STEALTH_PORT, 10);
  }
  for (const p of candidates) {
    if (await canBind(p)) return p;
  }
  return candidates[candidates.length - 1]; // last resort — wstunnel will log its own error
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
 * Restart-safe: when the unit is already running, its configured port is
 * reused (re-probing would find the port busy — held by wstunnel itself —
 * and wrongly fall back to 8443 while the relay stays on 443).  A changed
 * unit file triggers an explicit `restart`.  On Linux the relay must be
 * `active` AND accepting TCP on the advertised port before `enabled: true`
 * is reported.
 *
 * @param {string} dir - Agent identity directory.
 * @param {{ wgPort: number }} opts
 * @param {{ platform?: string, unit?: string, bin?: string, candidates?: number[],
 *           settleMs?: number, probe?: (port: number) => Promise<boolean> }} [deps]
 *   Test hooks; production callers omit this.
 * @returns {Promise<StealthState>}
 */
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
        // The unit embeds the path-prefix secret — keep it root-only.
        fs.writeFileSync(unitPath, unit, { mode: 0o600 });
        fs.chmodSync(unitPath, 0o600);
        await tryRunBin("systemctl", ["daemon-reload"]);
      }
      await tryRunBin("systemctl", ["enable", "--now", "wpn-stealth"]);
      // `enable --now` does not restart a running unit — do it explicitly so
      // a changed port/key actually takes effect.
      if (changed && wasActive) await tryRunBin("systemctl", ["restart", "wpn-stealth"]);

      // Verify the relay actually started — bind failure/crash shouldn't be
      // advertised as "enabled" to the control plane.
      await new Promise((r) => setTimeout(r, deps.settleMs ?? 800)); // let it bind/crash
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

    // On non-Linux (macOS dev smoke): no systemd — just report configured.
    return { enabled: true, port, key };
  } catch (e) {
    return { enabled: false, error: e.message };
  }
}

module.exports = { ensure, pickPort, canBind, readUnitPort };
