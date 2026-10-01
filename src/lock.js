"use strict";

class Mutex {
  constructor() {
    this._queue  = [];
    this._locked = false;
  }

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

  _release() {
    if (this._queue.length) {
      this._queue.shift()(this._release.bind(this));
    } else {
      this._locked = false;
    }
  }

  get locked() { return this._locked; }

  get queueLength() { return this._queue.length; }
}

const confLock = new Mutex();

module.exports = { Mutex, confLock };
