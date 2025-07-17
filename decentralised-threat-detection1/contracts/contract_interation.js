// contract_interact.js
const fs = require("fs");
const snarkjs = require("snarkjs");
const { ethers } = require("ethers");
require("dotenv").config();

async function main() {
  // === Load processed threat data ===
  const data = JSON.parse(fs.readFileSync("threat_inbox/processed/threat_data_threat_report_20250715_113806_558866.json", "utf8"));

  const input = JSON.parse(fs.readFileSync("zk/input_generator/input.json", "utf8")); // should match the threat
  const zkeyPath = "zk/proof/threat_proof.zkey";
  const wasmPath = "zk/proof/threat_proof.wasm";

  // === Step 1: Generate proof ===
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  console.log("✅ ZK Proof Generated");

  // === Step 2: Compute proof hash ===
  const proofHash = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["uint[2]", "uint[2][2]", "uint[2]", "uint[1]"],
      [
        [proof.pi_a[0], proof.pi_a[1]],
        [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
        [proof.pi_c[0], proof.pi_c[1]],
        [publicSignals[0]]
      ]
    )
  );

  // === Step 3: Connect to contract ===
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
  const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

  const contractAddress = process.env.CONTRACT_ADDRESS;
  const abi = JSON.parse(fs.readFileSync("contract/ZKThreatDetectionSystemABI.json", "utf8"));
  const contract = new ethers.Contract(contractAddress, abi, signer);

  // === Step 4: Call submitThreatReport ===
  const tx = await contract.submitThreatReport(
    proofHash,
    data.metadata_hash_bytes32,
    data.public_metadata_cid,
    data.solidity_threat_type,
    data.solidity_severity,
    ethers.ZeroHash // no zk identity yet
  );
  await tx.wait();
  console.log("📤 Report Submitted");

  // === Step 5: Call verifyZKProof ===
  const reportId = await contract.getTotalReports(); // get latest
  const tx2 = await contract.verifyZKProof(
    reportId,
    [proof.pi_a[0], proof.pi_a[1]],
    [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
    [proof.pi_c[0], proof.pi_c[1]],
    [publicSignals[0]]
  );
  await tx2.wait();
  console.log("✅ Proof Verified!");
}

main().catch(console.error);
