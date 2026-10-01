"use strict";

const test   = require("node:test");
const assert = require("node:assert");
const fs     = require("fs");
const os     = require("os");
const path   = require("path");

const tmp  = fs.mkdtempSync(path.join(os.tmpdir(), "wpn-subnet-"));
const CONF = path.join(tmp, "wg0.conf");
process.env.WPN_WG_CONF = CONF;

const util = require("../src/util");
const wg   = require("../src/wireguard");

const live = new Map();
let liveV4 = null;
let liveV6 = null;

util.setRunner({
  async run(cmd) {
    if (cmd.includes("-4 addr show")) return liveV4 || "";
    if (cmd.includes("-6 addr show")) return liveV6 || "";
    throw new Error(`unexpected run: ${cmd}`);
  },
  async runBin(bin, args) {
    assert.strictEqual(bin, "wg");
    if (args[0] === "show" && args[2] === "dump") {
      const rows = [...live].map(([k, ips]) => `${k}\t(none)\t(none)\t${ips}\t0\t0\t0\t25`);
      return ["priv\tpub\t51820\toff", ...rows].join("\n");
    }
    if (args[0] === "set") {
      const key = args[3];
      if (args[4] === "remove") live.delete(key);
      else live.set(key, args[args.indexOf("allowed-ips") + 1]);
      return "";
    }
    throw new Error(`unexpected wg call: ${args.join(" ")}`);
  },
});

test.after(() => {
  util.resetRunner();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const key = () => wg._genKeyPair().pub;
const writeConf = (address) =>
  fs.writeFileSync(CONF, `[Interface]\nAddress = ${address}\nPrivateKey = X\n\n`, { mode: 0o600 });

test("subnet - legacy wg0.conf on 10.66.66.0/24 accepts its own addresses", async () => {
  writeConf("10.66.66.1/24, fd42:42:42::1/64");
  liveV4 = "10.66.66.1/24";
  liveV6 = "fd42:42:42::1/64";
  await wg.addPeer(key(), "10.66.66.2");
  await wg.addPeer(key(), "fd42:42:42::5");
});

test("subnet - addresses from the agent default subnet are rejected on a legacy interface", async () => {
  await assert.rejects(wg.addPeer(key(), "10.66.0.2"), (e) => e.status === 400 && /10\.66\.66\.1\/24/.test(e.message));
});

test("subnet - the interface's own address is still rejected", async () => {
  await assert.rejects(wg.addPeer(key(), "10.66.66.1"), (e) => e.status === 400 && /collides/.test(e.message));
});

test("subnet - falls back to the conf Address when the interface is not queryable", async () => {
  writeConf("10.77.0.1/24, fd00:77::1/64");
  liveV4 = null;
  liveV6 = null;
  await wg.addPeer(key(), "10.77.0.2");
  await assert.rejects(wg.addPeer(key(), "10.66.0.2"), (e) => e.status === 400);
});

test("subnet - falls back to the built-in default when neither is available", async () => {
  fs.rmSync(CONF, { force: true });
  live.clear();
  await wg.addPeer(key(), "10.66.0.2");
  await assert.rejects(wg.addPeer(key(), "10.66.66.2"), (e) => e.status === 400);
});

test("peers - knownPeers reports conf claims hidden from the live dump", async () => {
  const stale = key();
  const ghost = key();
  fs.writeFileSync(CONF,
    `[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = X\n\n` +
    `[Peer]\nPublicKey = ${stale}\nAllowedIPs = 10.66.66.2/32, fd42:42:42::2/128\n\n` +
    `[Peer]\nPublicKey = ${ghost}\nAllowedIPs = 10.66.66.9/32\n`,
    { mode: 0o600 });
  live.clear();
  live.set(stale, "fd42:42:42::2/128");

  const peers = await wg.knownPeers();
  const merged = peers.find((p) => p.publicKey === stale);
  assert.ok(merged.allowedIps.includes("10.66.66.2/32"));
  assert.ok(merged.allowedIps.includes("fd42:42:42::2/128"));
  assert.strictEqual(merged.confOnly, false);

  const confPeer = peers.find((p) => p.publicKey === ghost);
  assert.strictEqual(confPeer.allowedIps, "10.66.66.9/32");
  assert.strictEqual(confPeer.confOnly, true);
  assert.strictEqual(confPeer.latestHandshake, 0);

  const liveOnly = (await wg.dump()).peers.find((p) => p.publicKey === stale);
  assert.ok(!liveOnly.allowedIps.includes("10.66.66.2"));
});
