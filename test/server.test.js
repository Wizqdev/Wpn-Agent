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
  assert.strictEqual(authed(req(`${token}`), token), false);
  assert.strictEqual(authed(req(""), token), false);
  assert.strictEqual(authed(req("Bearer " + token + "extra"), token), false);
});

const { EventEmitter } = require("node:events");
const { readBody, MAX_BODY_BYTES } = require("../src/server");

function fakeReq(buf, parts = 3) {
  const req = new EventEmitter();
  req.destroyed = false;
  req.destroy = () => { req.destroyed = true; setImmediate(() => req.emit("close")); };
  setImmediate(() => {
    const step = Math.ceil(buf.length / parts) || 1;
    for (let i = 0; i < buf.length && !req.destroyed; i += step) req.emit("data", buf.subarray(i, i + step));
    if (!req.destroyed) req.emit("end");
  });
  return req;
}

const jsonOfBytes = (bytes) => {

  const n = (bytes - 8) / 2;
  return Buffer.from(`{"a":"${"é".repeat(n)}"}`);
};

test("server - readBody limit counts bytes, not UTF-16 units (multi-byte at the limit)", async () => {
  const atLimit = jsonOfBytes(MAX_BODY_BYTES);
  assert.strictEqual(atLimit.length, MAX_BODY_BYTES);
  const body = await readBody(fakeReq(atLimit));
  assert.strictEqual(body.a.length, (MAX_BODY_BYTES - 8) / 2);
  assert.ok(!body.a.includes("\uFFFD"), "chunk boundaries must not corrupt multi-byte chars");
});

test("server - readBody rejects 413 one multi-byte char over the limit", async () => {
  const over = jsonOfBytes(MAX_BODY_BYTES + 2);

  await assert.rejects(readBody(fakeReq(over)), (e) => e.status === 413);
});

test("server - readBody rejects a plain oversized body and destroys the request", async () => {
  const req = fakeReq(Buffer.alloc(MAX_BODY_BYTES + 1, 0x61));
  await assert.rejects(readBody(req), (e) => e.status === 413);
  assert.strictEqual(req.destroyed, true);
});

test("server - readBody: empty body is {}, bad JSON is 400", async () => {
  assert.deepStrictEqual(await readBody(fakeReq(Buffer.alloc(0))), {});
  await assert.rejects(readBody(fakeReq(Buffer.from("{nope"))), (e) => e.status === 400);
});
