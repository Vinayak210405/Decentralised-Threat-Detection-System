require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-chai-matchers");
const path = require("path");
const { subtask } = require("hardhat/config");
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");

const SOLC_VERSION = "0.8.24";

// Compile with the solc-js build from the `solc` npm package instead of letting
// Hardhat download a compiler, so compiling works offline and behind proxies.
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (args.solcVersion === SOLC_VERSION) {
    const compilerPath = path.join(__dirname, "node_modules", "solc", "soljson.js");
    return { compilerPath, isSolcJs: true, version: SOLC_VERSION, longVersion: require("solc/package.json").version };
  }
  return runSuper();
});

module.exports = {
  solidity: {
    version: SOLC_VERSION,
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    // `npx hardhat node` starts this on http://127.0.0.1:8545 for the Python demo.
    localhost: { url: process.env.RPC_URL || "http://127.0.0.1:8545" },
  },
  mocha: { timeout: 300000 },
};
