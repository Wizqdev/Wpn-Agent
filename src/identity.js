/**
 * @fileoverview Agent identity — bearer token + self-signed TLS cert for the
 * control channel.  All identity material is stored once under `dir`
 * (default `/etc/wpn-agent`) and persisted across restarts.
 *
 * Files created:
 *  - `token`      — 192-bit random bearer token (0600)
 *  - `cert.pem`   — self-signed X.509 certificate (0644)
 *  - `key.pem`    — matching RSA-2048 private key  (0600)
 *  - `server.pub` — WireGuard server public key    (0644)
 *
 * The cert is self-signed, so the Wpn API should pin {@link fingerprint}
 * (SHA-256 of the DER/PEM bytes) rather than rely on CA verification —
 * that is what actually authenticates the channel against MITM.
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
 * @returns {Promise<{ tls: boolean }>} `tls: true` when cert+key were created
 *   or already exist; `tls: false` when `openssl` is unavailable and TLS
 *   cannot be offered.
 */
async function ensure(dir) {
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });

  // Bearer token — generated once, rotated by deleting the file + restarting.
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
      await run(
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
 * SHA-256 fingerprint of the TLS certificate — the value the Wpn API should
 * pin when connecting, since the cert is self-signed.
 *
 * @param {string} dir
 * @returns {string|null} Hex fingerprint, or null when no cert exists.
 */
function fingerprint(dir) {
  try {
    return crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(dir, CERT_FILE)))
      .digest("hex");
  } catch {
    return null;
  }
}

/**
 * Absolute path to the WireGuard server public-key cache file.
 *
 * @param {string} dir
 * @returns {string}
 */
const pubFile = (dir) => path.join(dir, PUB_FILE);

module.exports = { ensure, token, cert, key, fingerprint, pubFile, PUB_FILE };
