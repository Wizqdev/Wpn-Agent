/**
 * @fileoverview `wg0` health monitor — polls the WireGuard interface every
 * {@link POLL_MS} milliseconds and performs a self-healing restart if it is
 * found to be down.
 *
 * The monitor runs on an `unref()`-ed timer so it never prevents the process
 * from exiting cleanly.  Health status is exposed via {@link status} and
 * surfaced in the `/health` API endpoint so load balancers and dashboards get
 * an accurate signal instead of a false "green".
 */

"use strict";

const { tryRun, log } = require("./util");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** How often to poll wg0 (ms). */
const POLL_MS = 30_000;

/** Maximum consecutive self-heal failures before giving up and logging loudly. */
const MAX_HEAL_ATTEMPTS = 5;

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Check whether `wg0` appears in the live WireGuard interface list.
 *
 * @returns {boolean}
 */
function isWgUp() {
  return (tryRun("wg show interfaces") || "").split(/\s+/).includes("wg0");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start the background health monitor.  Safe to call multiple times — only
 * one timer is ever active.
 *
 * @param {string} wgConf - Path to `wg0.conf` (used to bring the interface up
 *   on self-heal: `wg-quick up <wgConf>`).
 * @returns {() => void} Stop function — call it during graceful shutdown.
 */
function start(wgConf) {
  if (_timer) return () => clearInterval(_timer);

  _timer = setInterval(() => {
    _state.lastCheck = Date.now();

    if (isWgUp()) {
      if (!_state.up) log.ok("wg0 is back up");
      _state.up           = true;
      _state.healAttempts = 0;
      _state.lastError    = null;
      return;
    }

    _state.up = false;
    _state.healAttempts++;

    if (_state.healAttempts > MAX_HEAL_ATTEMPTS) {
      log.err(`wg0 is DOWN — ${_state.healAttempts} heal attempts failed; manual intervention required`);
      return;
    }

    log.warn(`wg0 is DOWN — self-heal attempt ${_state.healAttempts}/${MAX_HEAL_ATTEMPTS}`);
    tryRun(`wg-quick up ${wgConf}`);

    if (isWgUp()) {
      _state.up        = true;
      _state.lastError = null;
      log.ok(`wg0 self-healed (attempt ${_state.healAttempts})`);
    } else {
      _state.lastError = `wg-quick up failed at ${new Date().toISOString()}`;
      log.err(`wg0 self-heal attempt ${_state.healAttempts} failed`);
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
