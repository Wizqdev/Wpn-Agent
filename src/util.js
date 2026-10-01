/**
 * @fileoverview Shared utilities — async shell execution helpers and
 * structured logger.
 *
 * Two execution primitives are provided (both async — they never block the
 * event loop, so in-flight API requests and health checks stay responsive
 * while system commands run):
 *  - {@link run}    — shell string via `/bin/sh -c` (for compound commands with
 *                     pipes and redirects)
 *  - {@link runBin} — `execFile` with an arg array; no shell involved,
 *                     completely immune to injection; preferred for all
 *                     wg/ip/systemctl calls
 *
 * The logger supports two output modes:
 *  - **Plain** (default): human-readable `[✓] message` lines to stdout/stderr
 *  - **JSON** (`WPN_LOG_JSON=1`): newline-delimited JSON for log aggregators
 *    (Datadog, Loki, CloudWatch, etc.)
 */

"use strict";

const { exec, execFile } = require("child_process");
const { promisify } = require("util");

const execAsync     = promisify(exec);
const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/**
 * Run a shell command string via `/bin/sh -c` and return trimmed stdout.
 * Use this only for commands that need shell features (pipes, redirects,
 * process substitution).  For simple binary invocations prefer {@link runBin}.
 *
 * @param {string} cmd - Shell command string.
 * @param {import("child_process").ExecOptions} [opts]
 * @returns {Promise<string>} Trimmed stdout.
 * @throws {Error} If the command exits non-zero.  `err.stderr` is attached.
 */
async function run(cmd, opts = {}) {
  if (_fake) {
    if (!_fake.run) throw new Error(`fake runner has no run(): ${cmd}`);
    return String(await _fake.run(cmd, opts)).trim();
  }
  const { stdout } = await execAsync(cmd, {
    timeout: 120_000,
    maxBuffer: 16 * 1_024 * 1_024,
    ...opts,
  });
  return stdout.toString().trim();
}

/**
 * Run a binary with an explicit argument array (no shell, no injection risk).
 * Preferred over {@link run} for all `wg`, `ip`, `systemctl`, `git` calls.
 *
 * @param {string}   bin  - Binary name or absolute path.
 * @param {string[]} args - Argument array.
 * @param {import("child_process").ExecFileOptions} [opts]
 * @returns {Promise<string>} Trimmed stdout.
 * @throws {Error} If the command exits non-zero.  `err.stderr` is attached.
 */
async function runBin(bin, args, opts = {}) {
  if (_fake) {
    if (!_fake.runBin) throw new Error(`fake runner has no runBin(): ${bin} ${args.join(" ")}`);
    return String(await _fake.runBin(bin, args, opts)).trim();
  }
  const { stdout } = await execFileAsync(bin, args, {
    timeout: 120_000,
    maxBuffer: 16 * 1_024 * 1_024,
    ...opts,
  });
  return stdout.toString().trim();
}

/**
 * Like {@link run} but resolves to `null` instead of throwing on any error.
 * Use for probing optional system features.
 *
 * @param {string} cmd
 * @returns {Promise<string|null>}
 */
const tryRun = (cmd) => run(cmd).catch(() => null);

/**
 * Like {@link runBin} but resolves to `null` instead of throwing.
 *
 * @param {string}   bin
 * @param {string[]} args
 * @param {import("child_process").ExecFileOptions} [opts]
 * @returns {Promise<string|null>}
 */
const tryRunBin = (bin, args, opts) => runBin(bin, args, opts).catch(() => null);

// ---------------------------------------------------------------------------
// HTTP error helper
// ---------------------------------------------------------------------------

/**
 * Build an `Error` carrying an HTTP status code for the control API.
 *
 * @param {number} status
 * @param {string} message
 * @returns {Error & {status: number}}
 */
const err = (status, message) => Object.assign(new Error(message), { status });

/**
 * Fixed-window rate limiter.  Returns a predicate that yields `true` once a
 * key exceeds `limit` hits inside `windowMs`.  Expired entries are swept
 * lazily when the map grows past `sweepAt` keys.
 *
 * @param {{ limit: number, windowMs?: number, sweepAt?: number }} opts
 * @returns {(key: string) => boolean}
 */
const rateLimiter = ({ limit, windowMs = 60_000, sweepAt = 4_096 }) => {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const e   = hits.get(key);
    if (!e || now > e.reset) {
      hits.set(key, { count: 1, reset: now + windowMs });
      if (hits.size > sweepAt) {
        for (const [k, v] of hits) if (now > v.reset) hits.delete(k);
      }
      return false;
    }
    return ++e.count > limit;
  };
};

// ---------------------------------------------------------------------------
// Test seam
// ---------------------------------------------------------------------------

/**
 * @typedef {object} FakeRunner
 * @property {(cmd: string, opts: object) => Promise<string>|string} [run]
 * @property {(bin: string, args: string[], opts: object) => Promise<string>|string} [runBin]
 */

/** @type {FakeRunner|null} */
let _fake = null;

/**
 * Route every {@link run} / {@link runBin} call to `fake` (tests only), so
 * system-touching logic can be exercised without root or real binaries.
 * @param {FakeRunner} fake
 */
const setRunner = (fake) => { _fake = fake; };

/** Restore real process execution. */
const resetRunner = () => { _fake = null; };

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

module.exports = { run, runBin, tryRun, tryRunBin, err, rateLimiter, isRoot, log, setRunner, resetRunner };
