"use strict";

const test = require("node:test");
const assert = require("node:assert");
const {
  _WG_KEY_RE,
  _isValidIPv4,
  _expandIPv6,
  _addrInSubnet,
  _normAddr,
  _parseDump,
  _parseConfPeers,
  _removePeerFromConf,
  _upsertPeerConf,
  _genKeyPair,
  _derivePubKey,
} = require("../src/wireguard");

test("wireguard - validate pubkey regex", () => {
  assert.strictEqual(_WG_KEY_RE.test("yG2q2/rN+Ym0+zE6k5nB7tqWp9M4bQ1sX0dZ+yH4x0="), false);
  assert.strictEqual(_WG_KEY_RE.test("yG2q2/rN+Ym0+zE6k5nB7tqWp9M4bQ1sX0dZ+yH4x0o="), true);
});

test("wireguard - ipv4 validation rejects bad octets", () => {
  assert.strictEqual(_isValidIPv4("10.66.0.2"), true);
  assert.strictEqual(_isValidIPv4("999.1.1.1"), false);
  assert.strictEqual(_isValidIPv4("10.66.0.2/32"), false);
  assert.strictEqual(_isValidIPv4("invalid"), false);
});

test("wireguard - ipv6 expansion validates strictly", () => {
  assert.deepStrictEqual(_expandIPv6("fd00:66::2"), [
    "fd00", "0066", "0000", "0000", "0000", "0000", "0000", "0002",
  ]);
  assert.ok(_expandIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  assert.strictEqual(_expandIPv6("invalid"), null);
  assert.strictEqual(_expandIPv6("a:b:::"), null);
  assert.strictEqual(_expandIPv6("1:2:3:4:5:6:7:8::9"), null);
  assert.strictEqual(_expandIPv6("1:2:3:4:5:6:7"), null);
  assert.strictEqual(_expandIPv6("::ffff:1.2.3.4"), null);
});

test("wireguard - addrInSubnet ipv4", () => {
  assert.strictEqual(_addrInSubnet("10.66.0.2", "10.66.0.1/24"), true);
  assert.strictEqual(_addrInSubnet("10.66.0.254", "10.66.0.1/24"), true);
  assert.strictEqual(_addrInSubnet("10.66.1.5", "10.66.0.1/24"), false);
  assert.strictEqual(_addrInSubnet("8.8.8.8", "10.66.0.1/24"), false);
});

test("wireguard - addrInSubnet ipv6", () => {
  assert.strictEqual(_addrInSubnet("fd00:66::2", "fd00:66::1/64"), true);
  assert.strictEqual(_addrInSubnet("fd00:67::2", "fd00:66::1/64"), false);
  assert.strictEqual(_addrInSubnet("fd00:66:0:1::9", "fd00:66::1/64"), false);
});

test("wireguard - normAddr equalises v6 spellings", () => {
  assert.strictEqual(_normAddr("fd00:66::2"), _normAddr("FD00:0066:0:0:0:0:0:2"));
});

const K1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const K2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const K3 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";

test("wireguard - parseDump handles single-interface format (8 fields)", () => {
  const out = [
    "PRIV\tPUB\t51820\toff",
    `${K1}\t(none)\t1.2.3.4:51820\t10.66.0.2/32\t1712345678\t1024\t2048\t25`,
    `${K2}\t(none)\t(none)\t10.66.0.3/32\t0\t0\t0\toff`,
    "",
  ].join("\n");
  const peers = _parseDump(out, "wg0");
  assert.strictEqual(peers.length, 2);
  assert.strictEqual(peers[0].publicKey, K1);
  assert.strictEqual(peers[0].endpoint, "1.2.3.4:51820");
  assert.strictEqual(peers[0].allowedIps, "10.66.0.2/32");
  assert.strictEqual(peers[0].latestHandshake, 1712345678);
  assert.strictEqual(peers[0].rx, 1024);
  assert.strictEqual(peers[0].tx, 2048);
  assert.strictEqual(peers[1].endpoint, null);
});

test("wireguard - parseDump handles `wg show all dump` format (9 fields)", () => {
  const out = [
    "wg0\tPRIV\tPUB\t51820\toff",
    `wg0\t${K1}\t(none)\t1.2.3.4:51820\t10.66.0.2/32\t1712345678\t1024\t2048\t25`,
    `wg1\t${K3}\t(none)\t5.6.7.8:51820\t10.77.0.2/32\t1712345999\t9\t9\toff`,
    "",
  ].join("\n");
  const peers = _parseDump(out, "wg0");
  assert.strictEqual(peers.length, 1);
  assert.strictEqual(peers[0].publicKey, K1);
});

test("wireguard - generated keypair round-trips through derivePubKey", () => {
  const { priv, pub } = _genKeyPair();
  assert.strictEqual(priv.length, 44);
  assert.strictEqual(pub.length, 44);
  assert.ok(_WG_KEY_RE.test(priv));
  assert.ok(_WG_KEY_RE.test(pub));
  assert.strictEqual(_derivePubKey(priv), pub);
});

const CONF = [
  "[Interface]",
  "Address = 10.66.0.1/24, fd00:66::1/64",
  "ListenPort = 51820",
  "PrivateKey = SERVERPRIV",
  "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT",
  "",
  "# wpn-peer 10.66.0.2",
  "[Peer]",
  `PublicKey = ${K1}`,
  "AllowedIPs = 10.66.0.2/32",
  "PersistentKeepalive = 25",
  "",
  "# wpn-peer 10.66.0.3",
  "[Peer]",
  `PublicKey = ${K2}`,
  "AllowedIPs = 10.66.0.3/32",
  "PersistentKeepalive = 25",
  "",
].join("\n");

test("wireguard - removePeerFromConf removes only the target block", () => {
  const out = _removePeerFromConf(CONF, K1);
  assert.ok(!out.includes(K1));
  assert.ok(!out.includes("wpn-peer 10.66.0.2"));
  assert.ok(out.includes(K2));
  assert.ok(out.includes("PrivateKey = SERVERPRIV"));
  assert.ok(out.includes("[Interface]"));
});

test("wireguard - removePeerFromConf is a no-op for unknown keys", () => {
  assert.strictEqual(_removePeerFromConf(CONF, K3), CONF);
});

test("wireguard - upsertPeerConf appends and replaces cleanly", () => {

  const added = _upsertPeerConf(CONF, {
    publicKey: K3, address: "10.66.0.4", allowedIps: "10.66.0.4/32",
  });
  assert.ok(added.includes(K3));
  assert.ok(added.includes("# wpn-peer 10.66.0.4"));

  const reAdded = _upsertPeerConf(added, {
    publicKey: K3, address: "10.66.0.9", allowedIps: "10.66.0.9/32",
  });
  assert.strictEqual(reAdded.split(K3).length - 1, 1, "pubkey appears exactly once");
  assert.ok(!reAdded.includes("10.66.0.4"));
  assert.ok(reAdded.includes("10.66.0.9/32"));
});

test("wireguard - parseConfPeers extracts pubkey → allowed-ips", () => {
  const peers = _parseConfPeers(CONF);
  assert.strictEqual(peers.length, 2);
  assert.strictEqual(peers[0].publicKey, K1);
  assert.deepStrictEqual(peers[0].allowedIps, ["10.66.0.2"]);
  assert.strictEqual(peers[1].publicKey, K2);
});
