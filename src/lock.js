/**
 * @fileoverview Async mutex — serialises concurrent `wg0.conf` reads/writes so
 * racing API requests (e.g. two simultaneous `POST /peers`) cannot interleave
 * and corrupt the file.
 *
 * Usage:
 * ```js
 * const { confLock } = require('./lock');
 * const release = await confLock.acquire();
 * try { /* read + write wg0.conf *\/ } finally { release(); }
 * ```
 */

"use strict";

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

class Mutex {
  constructor() {
    /** @type {Array<(release: () => void) => void>} */
    this._queue  = [];
    this._locked = false;
  }

  /**
   * Acquire the lock.  Resolves immediately when free; queues otherwise.
   * The caller **must** call the returned release function — preferably in a
   * `finally` block — to avoid deadlock.
   *
   * @returns {Promise<() => void>} Release function.
   */
  acquire() {
    return new Promise((resolve) => {
      if (!this._locked) {
        this._locked = true;
        resolve(this._release.bind(this));
      } else {
        this._queue.push(resolve);
      }
    });
  }

  /** @private */
  _release() {
    if (this._queue.length) {
      // Hand the lock directly to the next waiter — no unlocked window.
      this._queue.shift()(this._release.bind(this));
    } else {
      this._locked = false;
    }
  }

  /** Whether the mutex is currently held. */
  get locked() { return this._locked; }

  /** Number of callers waiting. */
  get queueLength() { return this._queue.length; }
}

// ---------------------------------------------------------------------------
// Shared instance
// ---------------------------------------------------------------------------

/**
 * Process-wide mutex that guards all reads and writes to `wg0.conf`.
 * Import and use this singleton; do not create additional instances.
 *
 * @type {Mutex}
 */
const confLock = new Mutex();

module.exports = { Mutex, confLock };
