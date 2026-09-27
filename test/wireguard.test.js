"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { _WG_KEY_RE, _IPV4_RE } = require("../src/wireguard");

test("wireguard - validate pubkey regex", () => {
  assert.strictEqual(_WG_KEY_RE.test("yG2q2/rN+Ym0+zE6k5nB7tqWp9M4bQ1sX0dZ+yH4x0="), false); // too short/long
  assert.strictEqual(_WG_KEY_RE.test("yG2q2/rN+Ym0+zE6k5nB7tqWp9M4bQ1sX0dZ+yH4x0o="), true); // valid base64 32-byte (44 chars)
});

test("wireguard - validate ipv4 regex", () => {
  assert.strictEqual(_IPV4_RE.test("10.66.0.2"), true);
  assert.strictEqual(_IPV4_RE.test("10.66.0.2/32"), false);
  assert.strictEqual(_IPV4_RE.test("invalid"), false);
});
