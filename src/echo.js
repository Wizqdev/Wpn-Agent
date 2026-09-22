// UDP echo — tiny datagram reflector for the client's gaming-mode
// loss/jitter probe. Echoes any datagram ≤64 bytes; rate-limits to
// 200 packets/sec per source IP so it can't become an amplifier.

const dgram = require("dgram");
const crypto = require("crypto");

const PORT = parseInt(process.env.WPN_ECHO_PORT || "44665", 10);
const MAX_BYTES = 64;
const PPS = 200;

let sock = null;

function start() {
  if (sock) return PORT;
  sock = dgram.createSocket("udp4");
  const buckets = new Map(); // ip -> {count, reset}
  sock.on("message", (msg, rinfo) => {
    if (msg.length > MAX_BYTES) return;
    const now = Date.now();
    const b = buckets.get(rinfo.address);
    if (!b || now > b.reset) buckets.set(rinfo.address, { count: 1, reset: now + 1000 });
    else if (++b.count > PPS) return;
    sock.send(msg, rinfo.port, rinfo.address, () => {});
  });
  sock.on("error", () => {});
  sock.bind(PORT);
  return PORT;
}

function port() {
  return PORT;
}

module.exports = { start, port };
