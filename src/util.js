/**
 * @fileoverview Shared utilities — shell execution helpers and structured logger.
 *
 * Two execution primitives are provided:
 *  - {@link run}    — shell string via `/bin/sh -c` (for compound commands with
 *                     pipes and redirects)
 *  - {@link runBin} — `execFileSync` with an arg array; no shell involved,
 *                     completely immune to injection; preferred for all wg/ip/systemctl calls
 *
 * The logger supports two output modes:
 *  - **Plain** (default): human-readable `[✓] message` lines to stdout/stderr
 *  - **JSON** (`WPN_LOG_JSON=1`): newline-delimited JSON for log aggregators
 *    (Datadog, Loki, CloudWatch, etc.)
 */

"use strict";

const { execSync, execFileSync } = require("child_process");

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/**
 * Run a shell command string via `/bin/sh -c` and return trimmed stdout.
 * Use this only for commands that need shell features (pipes, redirects,
 * process substitution).  For simple binary invocations prefer {@link runBin}.
 *
 * @param {string} cmd - Shell command string.
 * @param {import("child_process").ExecSyncOptions} [opts]
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
 * Run a binary with an explicit argument array (no shell, no injection risk).
 * Preferred over {@link run} for all `wg`, `ip`, `systemctl`, `git` calls.
 *
 * @param {string}   bin  - Binary name or absolute path.
 * @param {string[]} args - Argument array.
 * @param {import("child_process").ExecFileSyncOptions} [opts]
 * @returns {string} Trimmed stdout.
 * @throws {Error} If the command exits non-zero.
 */
const runBin = (bin, args, opts = {}) =>
  execFileSync(bin, args, {
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
    ...opts,
  })
    .toString()
    .trim();

/**
 * Like {@link run} but returns `null` instead of throwing on any error.
 * Use for probing optional system features.
 *
 * @param {string} cmd
 * @returns {string|null}
 */
const tryRun = (cmd) => {
  try {
    return run(cmd);
  } catch {
    return null;
  }
};

/**
 * Like {@link runBin} but returns `null` instead of throwing.
 *
 * @param {string}   bin
 * @param {string[]} args
 * @returns {string|null}
 */
const tryRunBin = (bin, args) => {
  try {
    return runBin(bin, args);
  } catch {
    return null;
  }
};

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/**
 * Returns `true` when the process is running as UID 0 (root).
 * Always `false` on platforms without `process.getuid` (Windows).
 *
 * @returns {boolean}
 */
const isRoot = () => (process.getuid ? process.getuid() === 0 : false);

// ---------------------------------------------------------------------------
// Structured logger
// ---------------------------------------------------------------------------

/** Whether to emit JSON log lines (set `WPN_LOG_JSON=1`). */
const JSON_LOG = process.env.WPN_LOG_JSON === "1";

/**
 * @typedef {"info"|"ok"|"warn"|"error"} LogLevel
 */

/**
 * Emit a single log entry to the appropriate stream.
 *
 * @param {LogLevel} level
 * @param {string}   message
 * @param {object}   [meta] - Additional fields included in JSON mode.
 */
function _emit(level, message, meta) {
  const isErr = level === "error";
  const out   = isErr ? process.stderr : process.stdout;

  if (JSON_LOG) {
    out.write(
      JSON.stringify({
        ts:      new Date().toISOString(),
        level,
        msg:     message,
        pid:     process.pid,
        ...(meta || {}),
      }) + "\n"
    );
  } else {
    const ICON = { info: "[*]", ok: "[✓]", warn: "[!]", error: "[✗]" };
    out.write(`${ICON[level]} ${message}\n`);
  }
}

/**
 * Minimal structured logger.
 * - `info`/`ok`/`warn` → stdout
 * - `err`             → stderr (for operator log separation)
 *
 * @namespace log
 */
const log = {
  /** @param {string} m @param {object} [meta] */
  info:  (m, meta) => _emit("info",  m, meta),
  /** @param {string} m @param {object} [meta] */
  ok:    (m, meta) => _emit("ok",    m, meta),
  /** @param {string} m @param {object} [meta] */
  warn:  (m, meta) => _emit("warn",  m, meta),
  /** @param {string} m @param {object} [meta] */
  err:   (m, meta) => _emit("error", m, meta),
};

module.exports = { run, runBin, tryRun, tryRunBin, isRoot, log };
