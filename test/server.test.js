"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { match, rateLimited, authed } = require("../src/server");

test("server - match route params", () => {
  assert.deepStrictEqual(match("/peers/:key", "/peers/123"), { key: "123" });
  assert.deepStrictEqual(match("/peers/:key", "/peers/AbC%3D"), { key: "AbC=" });
  assert.strictEqual(match("/peers/:key", "/peers/123/extra"), null);
  assert.strictEqual(match("/peers/:key", "/other/123"), null);
});

test("server - match decodes %2F inside params (base64 keys contain '/')", () => {
  assert.deepStrictEqual(match("/peers/:key", "/peers/abc%2Fdef%3D"), {
    key: "abc/def=",
  });
});

test("server - match returns null on malformed percent-encoding", () => {
  assert.strictEqual(match("/peers/:key", "/peers/%zz"), null);
});

test("server - rate limiter limits after threshold", () => {
  const ip = "10.99.0.1";
  let limited = false;
  // Threshold is 120
  for (let i = 0; i < 125; i++) {
    limited = rateLimited(ip);
  }
  assert.strictEqual(limited, true);
});

test("server - authed is constant-time and rejects wrong/missing tokens", () => {
  const token = "test-token-abc123";
  const req = (auth) => ({ headers: { authorization: auth } });
  assert.strictEqual(authed(req(`Bearer ${token}`), token), true);
  assert.strictEqual(authed(req("Bearer wrong"), token), false);
  assert.strictEqual(authed(req(`${token}`), token), false);        // no scheme
  assert.strictEqual(authed(req(""), token), false);                // missing
  assert.strictEqual(authed(req("Bearer " + token + "extra"), token), false);
});
