// Compile WifWheel.sol and the test token with solc-js; writes build/<Name>.json (abi + bytecode).
// Usage: node contracts/compile.js
const fs = require("fs");
const path = require("path");
const solc = require("solc");

const root = __dirname;
const files = { "WifWheel.sol": "WifWheel.sol", "test/MockWIF.sol": "test/MockWIF.sol" };
const sources = {};
for (const [name, rel] of Object.entries(files)) sources[name] = { content: fs.readFileSync(path.join(root, rel), "utf8") };

const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: "paris",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (out.errors || []).filter((e) => e.severity === "error");
(out.errors || []).forEach((e) => console.error(e.formattedMessage));
if (errors.length) process.exit(1);

const build = path.join(root, "build");
fs.mkdirSync(build, { recursive: true });
for (const file of Object.keys(out.contracts)) {
  for (const [name, c] of Object.entries(out.contracts[file])) {
    fs.writeFileSync(path.join(build, `${name}.json`), JSON.stringify({ abi: c.abi, bytecode: "0x" + c.evm.bytecode.object }, null, 2));
    console.log(`compiled ${name}`);
  }
}
