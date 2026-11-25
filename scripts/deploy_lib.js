/* Deploys PoseidonT3 (library), Groth16Verifier and ThreatRegistry. */
async function deployRegistry(ethers, { members = [], threshold = 2, votingPeriod = 3 * 24 * 3600 } = {}) {
  const poseidon = await (await ethers.getContractFactory("PoseidonT3")).deploy();
  await poseidon.waitForDeployment();
  const verifier = await (await ethers.getContractFactory("Groth16Verifier")).deploy();
  await verifier.waitForDeployment();
  const Registry = await ethers.getContractFactory("ThreatRegistry", {
    libraries: { PoseidonT3: await poseidon.getAddress() },
  });
  const registry = await Registry.deploy(await verifier.getAddress(), members, threshold, votingPeriod);
  await registry.waitForDeployment();
  return { registry, verifier, poseidon };
}

module.exports = { deployRegistry };
