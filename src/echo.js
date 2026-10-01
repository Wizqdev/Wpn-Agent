
"use strict";

const dgram = require("dgram");

const PORT = parseInt(process.env.WPN_ECHO_PORT || "44665", 10);

const MAX_BYTES = 64;

const PPS = 200;

const BUCKET_SWEEP_AT = 4_096;

let sock = null;

function start() {
  if (sock) return PORT;

  sock = dgram.createSocket("udp4");

    const buckets = new Map();

  sock.on("message", (msg, rinfo) => {
    if (msg.length > MAX_BYTES) return;

    const now = Date.now();
    const b = buckets.get(rinfo.address);

    if (!b || now > b.reset) {
      buckets.set(rinfo.address, { count: 1, reset: now + 1_000 });
    } else if (++b.count > PPS) {
      return;
    }

    if (buckets.size > BUCKET_SWEEP_AT) {
      for (const [addr, entry] of buckets) {
        if (now > entry.reset) buckets.delete(addr);
      }
    }

    sock.send(msg, rinfo.port, rinfo.address, () => {});
  });

  sock.on("error", () => {});

  sock.bind(PORT);
  return PORT;
}

function stop() {
  if (!sock) return;
  try {
    sock.close();
  } catch {}
  sock = null;
}

const port = () => PORT;

module.exports = { start, stop, port };
