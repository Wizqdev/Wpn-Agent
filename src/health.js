/**
 * @fileoverview `wg0` health monitor — polls the WireGuard interface every
 * {@link POLL_MS} milliseconds and performs a self-healing restart if it is
 * found to be down.
 *
 * Two failure modes are healed:
 *  1. **Interface down** → `wg-quick up <wgConf>` (bounded retries).
 *  2. **NAT/forward rules flushed** (docker restart, manual `iptables -F`)
 *     while the interface stays up → rules are re-asserted every poll via
 *     {@link firewall.ensureLiveNat}, which is a no-op when nothing is missing.
 *
 * The monitor runs on an `unref()`-ed timer so it never prevents the process
 * from exiting cleanly.  Health status is exposed via {@link status} and
 * surfaced in the `/health` API endpoint so load balancers and dashboards get
 * an accurate signal instead of a false "green".
 */

"use strict";

const { tryRun, log } = require("./util");
const firewall = require("./firewall");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** How often to poll the WireGuard interface (ms). */
const POLL_MS = 30_000;

/** Maximum consecutive self-heal failures before giving up and logging loudly. */
const MAX_HEAL_ATTEMPTS = 5;

const WG_IFACE = process.env.WPN_WG_IFACE || "wg0";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/**
 * @typedef {{ up: boolean, lastCheck: number, healAttempts: number, lastError: string|null }} HealthState
 */

/** @type {HealthState} */
const _state = {
  up:           true,
  lastCheck:    Date.now(),
  healAttempts: 0,
  lastError:    null,
};

/** @type {NodeJS.Timeout|null} */
let _timer = null;

/** Re-entrancy guard — a slow heal must not overlap the next tick. */
let _busy = false;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Check whether the WG interface appears in the live interface list.
 *
 * @returns {Promise<boolean>}
 */
async function isWgUp() {
  return (await tryRun("wg show interfaces") || "")
    .split(/\s+/)
    .includes(WG_IFACE);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start the background health monitor.  Safe to call multiple times — only
 * one timer is ever active.
 *
 * @param {{ wgConf: string, wanIf: string }} opts
 *   `wgConf` — path to the conf used to bring the interface up on self-heal.
 *   `wanIf`  — WAN interface; used to re-assert NAT rules that may have been
 *              flushed by other tooling while wg0 stayed up.
 * @returns {() => void} Stop function — call it during graceful shutdown.
 */
function start({ wgConf, wanIf }) {
  if (_timer) return () => clearInterval(_timer);

  _timer = setInterval(async () => {
    if (_busy) return; // previous heal still running — skip this tick
    _busy = true;
    _state.lastCheck = Date.now();

    try {
      const up = await isWgUp();

      if (up) {
        if (!_state.up) log.ok(`${WG_IFACE} is back up`);
        _state.up           = true;
        _state.healAttempts = 0;
        _state.lastError    = null;

        // Re-assert NAT/clamp rules — heals iptables flushes that leave the
        // interface up.  Idempotent: a no-op when nothing is missing.
        try {
          const added = await firewall.ensureLiveNat(wanIf, WG_IFACE);
          if (added) log.warn("nat/forward rules were missing — re-asserted");
        } catch {}
        return;
      }

      _state.up = false;
      _state.healAttempts++;

      if (_state.healAttempts > MAX_HEAL_ATTEMPTS) {
        log.err(`${WG_IFACE} is DOWN — ${_state.healAttempts} heal attempts failed; manual intervention required`);
        return;
      }

      log.warn(`${WG_IFACE} is DOWN — self-heal attempt ${_state.healAttempts}/${MAX_HEAL_ATTEMPTS}`);
      await tryRun(`wg-quick up ${wgConf}`);

      if (await isWgUp()) {
        _state.up        = true;
        _state.lastError = null;
        log.ok(`${WG_IFACE} self-healed (attempt ${_state.healAttempts})`);
      } else {
        _state.lastError = `wg-quick up failed at ${new Date().toISOString()}`;
        log.err(`${WG_IFACE} self-heal attempt ${_state.healAttempts} failed`);
      }
    } finally {
      _busy = false;
    }
  }, POLL_MS);

  // Don't prevent process from exiting cleanly during tests or --skip-wg mode.
  _timer.unref();

  return () => {
    clearInterval(_timer);
    _timer = null;
  };
}

/**
 * Return a snapshot of the current health state.
 * Used by the `/health` endpoint to give load balancers an accurate signal.
 *
 * @returns {HealthState}
 */
const status = () => ({ ..._state });

module.exports = { start, status, isWgUp };
