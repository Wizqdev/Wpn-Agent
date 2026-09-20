const { execSync } = require("child_process");

const run = (cmd, opts = {}) =>
  execSync(cmd, {
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120000,
    ...opts,
  })
    .toString()
    .trim();

const tryRun = (cmd) => {
  try {
    return run(cmd);
  } catch {
    return null;
  }
};

const isRoot = () => (process.getuid ? process.getuid() === 0 : false);

const log = {
  info: (m) => console.log(`[*] ${m}`),
  ok: (m) => console.log(`[✓] ${m}`),
  warn: (m) => console.log(`[!] ${m}`),
  err: (m) => console.log(`[✗] ${m}`),
};

module.exports = { run, tryRun, isRoot, log };
