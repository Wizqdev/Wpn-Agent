"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { Mutex } = require("../src/lock");

test("lock - serialises execution", async () => {
  const m = new Mutex();
  let val = 0;

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  const job1 = async () => {
    const release = await m.acquire();
    val = 1;
    await wait(10);
    val = 2;
    release();
  };

  const job2 = async () => {
    const release = await m.acquire();
    assert.strictEqual(val, 2, "Job 1 should have finished completely before Job 2 acquired lock");
    val = 3;
    release();
  };

  await Promise.all([job1(), job2()]);
  assert.strictEqual(val, 3);
});
