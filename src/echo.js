/**
 * @fileoverview UDP echo reflector for the client's loss/jitter probe.
 *
 * Any datagram ≤ {@link MAX_BYTES} bytes is reflected back verbatim.  A simple
 * token-bucket rate-limiter (200 pps per source IP) prevents use as a UDP
 * amplifier.  The bucket map is swept when it exceeds {@link BUCKET_SWEEP_AT}
 * entries so the process does not accumulate stale state on busy nodes.
 */

"use strict";

const dgram = require("dgram");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** UDP port for the echo service. */
const PORT = parseInt(process.env.WPN_ECHO_PORT || "44665", 10);

/** Maximum datagram size we will echo; larger packets are silently dropped. */
const MAX_BYTES = 64;

/** Maximum packets per second per source IP before packets are dropped. */
const PPS = 200;

/** Sweep the bucket map when it exceeds this many entries. */
const BUCKET_SWEEP_AT = 4_096;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** @type {import("dgram").Socket|null} */
let sock = null;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start the UDP echo socket.  Safe to call multiple times — subsequent calls
 * are no-ops and return the port immediately.
 *
 * @returns {number} The UDP port the socket is (or will be) bound to.
 */
function start() {
  if (sock) return PORT;

  sock = dgram.createSocket("udp4");

  /** @type {Map<string, {count: number, reset: number}>} */
  const buckets = new Map();

  sock.on("message", (msg, rinfo) => {
    if (msg.length > MAX_BYTES) return;

    const now = Date.now();
    const b = buckets.get(rinfo.address);

    if (!b || now > b.reset) {
      buckets.set(rinfo.address, { count: 1, reset: now + 1_000 });
    } else if (++b.count > PPS) {
      return; // rate-limited — drop silently
    }

    // Lazy sweep: purge expired entries when the map grows large.
    if (buckets.size > BUCKET_SWEEP_AT) {
      for (const [addr, entry] of buckets) {
        if (now > entry.reset) buckets.delete(addr);
      }
    }

    sock.send(msg, rinfo.port, rinfo.address, () => {});
  });

  // Swallow socket errors — echo loss is acceptable; a throw here would crash
  // the entire agent process.
  sock.on("error", () => {});

  sock.bind(PORT);
  return PORT;
}

/**
 * Return the configured echo port regardless of whether the socket is bound.
 *
 * @returns {number}
 */
const port = () => PORT;

module.exports = { start, port };
