#!/usr/bin/env node
"use strict";

const fs   = require("fs");
const path = require("path");
const { referenceUnit } = require("../src/service");

fs.writeFileSync(path.join(__dirname, "..", "systemd", "wpn-agent.service"), referenceUnit());
console.log("systemd/wpn-agent.service regenerated");
