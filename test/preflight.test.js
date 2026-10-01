"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { isPrivateIp } = require("../src/preflight");

test("preflight - isPrivateIp covers all non-public ranges", () => {
  for (const ip of [
    "10.0.0.1", "10.255.255.254",
    "172.16.0.1", "172.31.255.1",
    "192.168.1.1",
    "100.64.0.1", "100.127.9.9",
    "127.0.0.1", "127.53.0.1",
    "169.254.1.1",
    "0.0.0.0", "0.12.3.4",
    "192.0.0.10",
    "198.18.0.1", "198.19.255.1",
    "224.0.0.1", "240.0.0.1", "255.255.255.255",
  ]) {
    assert.strictEqual(isPrivateIp(ip), true, `${ip} should be non-public`);
  }
});

test("preflight - isPrivateIp passes real public addresses", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "203.0.113.9", "100.63.255.1", "198.51.100.2"]) {
    assert.strictEqual(isPrivateIp(ip), false, `${ip} should be public`);
  }
});

test("preflight - isPrivateIp rejects malformed input", () => {
  assert.strictEqual(isPrivateIp("not-an-ip"), false);
  assert.strictEqual(isPrivateIp("999.1.1.1"), false);
  assert.strictEqual(isPrivateIp("1.2.3"), false);
});
