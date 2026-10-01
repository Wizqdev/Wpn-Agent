
"use strict";

const { tryRunBin, log } = require("./util");
const firewall = require("./firewall");

const POLL_MS = 30_000;

const MAX_HEAL_ATTEMPTS = 5;

const WG_IFACE = process.env.WPN_WG_IFACE || "wg0";

const _state = {
  up:           true,
  lastCheck:    Date.now(),
  healAttempts: 0,
  lastError:    null,
};

let _timer = null;

let _busy = false;

async function isWgUp() {
  return (await tryRunBin("wg", ["show", "interfaces"]) || "")
    .split(/\s+/)
    .includes(WG_IFACE);
}


function start({ wgConf, wanIf }) {
  if (_timer) return () => clearInterval(_timer);

  _timer = setInterval(async () => {
    if (_busy) return;
    _busy = true;
    _state.lastCheck = Date.now();

    try {
      const up = await isWgUp();

      if (up) {
        if (!_state.up) log.ok(`${WG_IFACE} is back up`);
        _state.up           = true;
        _state.healAttempts = 0;
        _state.lastError    = null;

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
      await tryRunBin("wg-quick", ["up", wgConf]);

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

  _timer.unref();

  return () => {
    clearInterval(_timer);
    _timer = null;
  };
}

const status = () => ({ ..._state });

module.exports = { start, status };
