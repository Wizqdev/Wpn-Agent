/**
 * @fileoverview Agent identity — bearer token + self-signed TLS cert for the
 * control channel.  All identity material is stored once under {@link DIR}
 * (default `/etc/wpn-agent`) and persisted across restarts.
 *
 * Files created:
 *  - `token`      — 192-bit random bearer token (0600)
 *  - `cert.pem`   — self-signed X.509 certificate (0644)
 *  - `key.pem`    — matching RSA-2048 private key  (0600)
 *  - `server.pub` — WireGuard server public key    (0644)
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { run } = require("./util");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOKEN_FILE = "token";
const CERT_FILE  = "cert.pem";
const KEY_FILE   = "key.pem";
const PUB_FILE   = "server.pub";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Ensure all identity material exists under `dir`.  Creates the directory and
 * any missing files on first call; idempotent on subsequent calls.
 *
 * @param {string} dir - Path to the identity directory (e.g. `/etc/wpn-agent`).
 * @returns {{ tls: boolean }} `tls: true` when cert+key were created or already
 *   exist; `tls: false` when `openssl` is unavailable and TLS cannot be offered.
 */
function ensure(dir) {
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });

  // Bearer token — generated once, never rotated automatically.
  const tokenPath = path.join(dir, TOKEN_FILE);
  if (!fs.existsSync(tokenPath)) {
    fs.writeFileSync(
      tokenPath,
      crypto.randomBytes(24).toString("base64url") + "\n",
      { mode: 0o600 }
    );
  }

  // Self-signed TLS cert — 10-year validity, RSA-2048.
  const certPath = path.join(dir, CERT_FILE);
  const keyPath  = path.join(dir, KEY_FILE);
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    try {
      run(
        `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 ` +
          `-keyout ${keyPath} -out ${certPath} -subj "/CN=wpn-agent" 2>/dev/null`
      );
      fs.chmodSync(keyPath, 0o600);
    } catch {
      return { tls: false };
    }
  }

  return { tls: true };
}

/**
 * Read the bearer token for `dir`.
 *
 * @param {string} dir
 * @returns {string}
 */
const token = (dir) =>
  fs.readFileSync(path.join(dir, TOKEN_FILE), "utf8").trim();

/**
 * Read the TLS certificate for `dir`.
 *
 * @param {string} dir
 * @returns {Buffer}
 */
const cert = (dir) => fs.readFileSync(path.join(dir, CERT_FILE));

/**
 * Read the TLS private key for `dir`.
 *
 * @param {string} dir
 * @returns {Buffer}
 */
const key = (dir) => fs.readFileSync(path.join(dir, KEY_FILE));

/**
 * Absolute path to the WireGuard server public-key cache file.
 *
 * @param {string} dir
 * @returns {string}
 */
const pubFile = (dir) => path.join(dir, PUB_FILE);

module.exports = { ensure, token, cert, key, pubFile, PUB_FILE };
