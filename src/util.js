/**
 * @fileoverview Shared utilities — shell execution helpers and structured logger.
 *
 * All shell helpers use `execFileSync`-style semantics under the hood: stdout is
 * captured, stderr is silently discarded unless the call throws.  The 2-minute
 * hard timeout is intentionally generous — WireGuard package installation can
 * be slow on constrained VMs.
 */

"use strict";

const { execSync } = require("child_process");

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/**
 * Run a shell command and return trimmed stdout.
 *
 * @param {string} cmd - Shell command string (passed to `/bin/sh -c`).
 * @param {import("child_process").ExecSyncOptions} [opts] - Extra options merged
 *   into the `execSync` call.  Callers may override `timeout`.
 * @returns {string} Trimmed stdout.
 * @throws {Error} If the command exits non-zero.
 */
const run = (cmd, opts = {}) =>
  execSync(cmd, {
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
    ...opts,
  })
    .toString()
    .trim();

/**
 * Like {@link run} but returns `null` instead of throwing on any error.
 * Useful for probing optional system features.
 *
 * @param {string} cmd - Shell command string.
 * @returns {string|null} Trimmed stdout, or `null` on any failure.
 */
const tryRun = (cmd) => {
  try {
    return run(cmd);
  } catch {
    return null;
  }
};

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/**
 * Returns `true` when the process is running as UID 0 (root).
 * Always returns `false` on platforms without `process.getuid` (Windows).
 *
 * @returns {boolean}
 */
const isRoot = () => (process.getuid ? process.getuid() === 0 : false);

// ---------------------------------------------------------------------------
// Structured logger
// ---------------------------------------------------------------------------

/**
 * Minimal structured logger.  Info/ok/warn write to **stdout**; err writes to
 * **stderr** so operators can separate noise from fatal signals.
 *
 * @namespace log
 */
const log = {
  /** @param {string} m - Informational message. */
  info: (m) => process.stdout.write(`[*] ${m}\n`),

  /** @param {string} m - Success / checkpoint message. */
  ok: (m) => process.stdout.write(`[✓] ${m}\n`),

  /** @param {string} m - Non-fatal warning. */
  warn: (m) => process.stdout.write(`[!] ${m}\n`),

  /** @param {string} m - Fatal error (written to stderr). */
  err: (m) => process.stderr.write(`[✗] ${m}\n`),
};

module.exports = { run, tryRun, isRoot, log };
