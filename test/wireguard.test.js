"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { _WG_KEY_RE, _IPV4_RE, _IPV6_RE } = require("../src/wireguard");

test("wireguard - validate pubkey regex", () => {
  assert.strictEqual(_WG_KEY_RE.test("yG2q2/rN+Ym0+zE6k5nB7tqWp9M4bQ1sX0dZ+yH4x0="), false); // too short/long
  assert.strictEqual(_WG_KEY_RE.test("yG2q2/rN+Ym0+zE6k5nB7tqWp9M4bQ1sX0dZ+yH4x0o="), true); // valid base64 32-byte (44 chars)
});

test("wireguard - validate ipv4 regex", () => {
  assert.strictEqual(_IPV4_RE.test("10.66.0.2"), true);
  assert.strictEqual(_IPV4_RE.test("10.66.0.2/32"), false);
  assert.strictEqual(_IPV4_RE.test("invalid"), false);
});

test("wireguard - validate ipv6 regex", () => {
  assert.strictEqual(_IPV6_RE.test("fd00:66::2"), true);
  assert.strictEqual(_IPV6_RE.test("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), true);
  assert.strictEqual(_IPV6_RE.test("invalid"), false);
});
