"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { renderUnit, referenceUnit } = require("../src/service");

test("service - generated unit is sandboxed (NoNewPrivileges, ProtectHome, PrivateTmp)", () => {
  const unit = renderUnit({ agentPort: 44664 });
  for (const line of ["NoNewPrivileges=true", "ProtectHome=true", "PrivateTmp=true", "Restart=always"]) {
    assert.ok(unit.split("\n").includes(line), `missing ${line}`);
  }
  assert.ok(unit.includes("Environment=WPN_AGENT_PORT=44664"));
});

test("service - checked-in systemd/wpn-agent.service matches the template (run `npm run gen:unit`)", () => {
  const file = fs.readFileSync(path.join(__dirname, "..", "systemd", "wpn-agent.service"), "utf8");
  assert.strictEqual(file, referenceUnit());
});
