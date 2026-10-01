
"use strict";

const { exec, execFile } = require("child_process");
const { promisify } = require("util");

const execAsync     = promisify(exec);
const execFileAsync = promisify(execFile);

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

const tryRun = (cmd) => run(cmd).catch(() => null);

const tryRunBin = (bin, args, opts) => runBin(bin, args, opts).catch(() => null);

const err = (status, message) => Object.assign(new Error(message), { status });

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

let _fake = null;

const setRunner = (fake) => { _fake = fake; };

const resetRunner = () => { _fake = null; };

const isRoot = () => (process.getuid ? process.getuid() === 0 : false);

const JSON_LOG = process.env.WPN_LOG_JSON === "1";

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

const log = {
    info:  (m, meta) => _emit("info",  m, meta),
    ok:    (m, meta) => _emit("ok",    m, meta),
    warn:  (m, meta) => _emit("warn",  m, meta),
    err:   (m, meta) => _emit("error", m, meta),
};

module.exports = { run, runBin, tryRun, tryRunBin, err, rateLimiter, isRoot, log, setRunner, resetRunner };
