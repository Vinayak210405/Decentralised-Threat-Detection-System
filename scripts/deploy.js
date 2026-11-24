/*
 * Deploy the registry to a running chain and write deployments/<network>.json
 * (address + ABI + start block) for the Python nodes.
 *
 *   DTDS_MEMBERS=path/to/members.json DTDS_THRESHOLD=2 npx hardhat run scripts/deploy.js --network localhost
 *
 * members.json: ["<identity commitment>", ...]  (public values only)
 */
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const { deployRegistry } = require("./deploy_lib");

async function main() {
  const membersFile = process.env.DTDS_MEMBERS;
  const members = membersFile ? JSON.parse(fs.readFileSync(membersFile, "utf8")) : [];
  const threshold = Number(process.env.DTDS_THRESHOLD || 2);
  const votingPeriod = Number(process.env.DTDS_VOTING_PERIOD || 3 * 24 * 3600);
  const { registry } = await deployRegistry(hre.ethers, { members, threshold, votingPeriod });
  const receipt = await registry.deploymentTransaction().wait();
  const artifact = await hre.artifacts.readArtifact("ThreatRegistry");
  const out = {
    network: hre.network.name,
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
    address: await registry.getAddress(),
    startBlock: receipt.blockNumber,
    threshold,
    abi: artifact.abi,
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${hre.network.name}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  console.log(`ThreatRegistry deployed at ${out.address} with ${members.length} founding members -> ${file}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
