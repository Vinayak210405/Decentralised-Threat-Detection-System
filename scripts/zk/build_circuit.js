#!/usr/bin/env node
/*
 * Compile the membership circuit and run the Groth16 setup.
 *
 * Outputs (committed, so you do NOT need circom just to run the demo):
 *   circuits/build/membership.wasm          witness generator
 *   circuits/build/membership_final.zkey    proving key
 *   circuits/build/verification_key.json    verification key
 *   contracts/Groth16Verifier.sol           on-chain verifier
 *
 * Requirements to rebuild: `circom` 2.1.x on PATH
 * (https://github.com/iden3/circom/releases). Phase 1 uses the public Hermez
 * "powers of tau" ceremony file (2^12 constraints is enough; the circuit has
 * ~2.9k). Set DTDS_PTAU to use a local .ptau file instead of downloading.
 *
 * NOTE: phase 2 here has a single contributor (this machine), which is fine
 * for a demo but not for production: whoever runs it could forge proofs if
 * they kept the randomness. A real consortium would run a multi-party phase 2
 * where every member contributes.
 */
const { execFileSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const CIRCUIT = path.join(ROOT, "circuits", "membership.circom");
const BUILD = path.join(ROOT, "circuits", "build");
const TMP = path.join(BUILD, "tmp");
const PTAU_URL = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_12.ptau";
const SNARKJS = path.join(ROOT, "node_modules", "snarkjs", "build", "cli.cjs");

function run(cmd, args) {
  console.log(`> ${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { stdio: "inherit" });
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (res) => {
      if (res.statusCode !== 200) return reject(new Error(`GET ${url} -> ${res.statusCode}`));
      res.pipe(file);
      file.on("finish", () => file.close(resolve));
    }).on("error", reject);
  });
}

async function main() {
  fs.mkdirSync(TMP, { recursive: true });

  run("circom", [CIRCUIT, "--r1cs", "--wasm", "--sym", "-o", TMP]);

  let ptau = process.env.DTDS_PTAU;
  if (!ptau) {
    ptau = path.join(TMP, "powersOfTau28_hez_final_12.ptau");
    if (!fs.existsSync(ptau)) {
      console.log(`Downloading ${PTAU_URL}`);
      await download(PTAU_URL, ptau);
    }
  }

  const r1cs = path.join(TMP, "membership.r1cs");
  const zkey0 = path.join(TMP, "membership_0000.zkey");
  const zkey = path.join(BUILD, "membership_final.zkey");
  run("node", [SNARKJS, "groth16", "setup", r1cs, ptau, zkey0]);
  run("node", [SNARKJS, "zkey", "contribute", zkey0, zkey, "--name=dtds-demo",
    `-e=${crypto.randomBytes(32).toString("hex")}`]);
  run("node", [SNARKJS, "zkey", "verify", r1cs, ptau, zkey]);
  run("node", [SNARKJS, "zkey", "export", "verificationkey", zkey,
    path.join(BUILD, "verification_key.json")]);
  run("node", [SNARKJS, "zkey", "export", "solidityverifier", zkey,
    path.join(ROOT, "contracts", "Groth16Verifier.sol")]);
  fs.copyFileSync(path.join(TMP, "membership_js", "membership.wasm"),
    path.join(BUILD, "membership.wasm"));
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log("Done. Artifacts in circuits/build/ and contracts/Groth16Verifier.sol");
}

main().catch((e) => { console.error(e); process.exit(1); });
