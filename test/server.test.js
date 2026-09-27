"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { match, rateLimited } = require("../src/server");

test("server - match route params", () => {
  assert.deepStrictEqual(match("/peers/:key", "/peers/123"), { key: "123" });
  assert.deepStrictEqual(match("/peers/:key", "/peers/AbC%3D"), { key: "AbC=" });
  assert.strictEqual(match("/peers/:key", "/peers/123/extra"), null);
  assert.strictEqual(match("/peers/:key", "/other/123"), null);
});

test("server - rate limiter limits after threshold", () => {
  const ip = "1.2.3.4";
  let limited = false;
  // Threshold is 120
  for (let i = 0; i < 125; i++) {
    limited = rateLimited(ip);
  }
  assert.strictEqual(limited, true);
});
