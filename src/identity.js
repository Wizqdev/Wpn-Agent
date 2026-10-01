
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { runBin } = require("./util");

const TOKEN_FILE = "token";
const CERT_FILE  = "cert.pem";
const KEY_FILE   = "key.pem";
const PUB_FILE   = "server.pub";

async function ensure(dir) {
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });

  const tokenPath = path.join(dir, TOKEN_FILE);
  if (!fs.existsSync(tokenPath)) {
    fs.writeFileSync(
      tokenPath,
      crypto.randomBytes(24).toString("base64url") + "\n",
      { mode: 0o600 }
    );
  }

  const certPath = path.join(dir, CERT_FILE);
  const keyPath  = path.join(dir, KEY_FILE);
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    try {
      await runBin("openssl", [
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
        "-keyout", keyPath, "-out", certPath, "-subj", "/CN=wpn-agent",
      ]);
      fs.chmodSync(keyPath, 0o600);
    } catch {
      return { tls: false };
    }
  }

  return { tls: true };
}

const token = (dir) =>
  fs.readFileSync(path.join(dir, TOKEN_FILE), "utf8").trim();

const cert = (dir) => fs.readFileSync(path.join(dir, CERT_FILE));

const key = (dir) => fs.readFileSync(path.join(dir, KEY_FILE));

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

const pubFile = (dir) => path.join(dir, PUB_FILE);

module.exports = { ensure, token, cert, key, fingerprint, pubFile };
