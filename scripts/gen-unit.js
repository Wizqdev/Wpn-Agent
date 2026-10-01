#!/usr/bin/env node
"use strict";

// Regenerates systemd/wpn-agent.service from the template in src/service.js.
const fs   = require("fs");
const path = require("path");
const { referenceUnit } = require("../src/service");

fs.writeFileSync(path.join(__dirname, "..", "systemd", "wpn-agent.service"), referenceUnit());
console.log("systemd/wpn-agent.service regenerated");
