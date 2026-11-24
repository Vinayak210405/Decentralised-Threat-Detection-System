/*
 * Off-chain ZK helpers shared by the tests, the deploy script and the Python
 * node (which calls cli.js through a subprocess).
 */
const crypto = require("crypto");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const DEPTH = 10;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BUILD = path.resolve(__dirname, "..", "..", "circuits", "build");
const WASM = path.join(BUILD, "membership.wasm");
const ZKEY = path.join(BUILD, "membership_final.zkey");
const VKEY = path.join(BUILD, "verification_key.json");

let _poseidon;
async function poseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

async function hash(inputs) {
  const p = await poseidon();
  return p.F.toObject(p(inputs.map(BigInt)));
}

/** A company's private identity: a random field element and its public commitment. */
async function newIdentity() {
  // 31 random bytes < 2^248 < field size, so no modular bias to worry about.
  const secret = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
  return { secret, commitment: await hash([secret]) };
}

async function commitmentOf(secret) {
  return hash([BigInt(secret)]);
}

/**
 * Incremental Merkle tree identical to ThreatRegistry.sol: empty leaves are 0,
 * zeros[i+1] = H(zeros[i], zeros[i]).
 */
async function buildTree(leaves) {
  const zeros = [0n];
  for (let i = 0; i < DEPTH; i++) zeros.push(await hash([zeros[i], zeros[i]]));
  const levels = [leaves.map(BigInt)];
  for (let i = 0; i < DEPTH; i++) {
    const cur = levels[i];
    const next = [];
    for (let j = 0; j < Math.ceil(cur.length / 2); j++) {
      const l = cur[2 * j];
      const r = 2 * j + 1 < cur.length ? cur[2 * j + 1] : zeros[i];
      next.push(await hash([l, r]));
    }
    levels.push(next);
  }
  const root = levels[DEPTH].length ? levels[DEPTH][0] : zeros[DEPTH];

  function proof(index) {
    const pathElements = [];
    const pathIndices = [];
    let idx = index;
    for (let i = 0; i < DEPTH; i++) {
      const sib = idx ^ 1;
      pathElements.push(sib < levels[i].length ? levels[i][sib] : zeros[i]);
      pathIndices.push(idx & 1);
      idx >>= 1;
    }
    return { pathElements, pathIndices };
  }
  return { root, proof, zeros };
}

/** Proof arguments in the layout Groth16Verifier.sol expects (pi_b coordinates swapped). */
function toSolidity(proof) {
  return [
    proof.pi_a[0], proof.pi_a[1],
    proof.pi_b[0][1], proof.pi_b[0][0], proof.pi_b[1][1], proof.pi_b[1][0],
    proof.pi_c[0], proof.pi_c[1],
  ].map((x) => BigInt(x).toString());
}

/**
 * Prove membership for `scope` and `signalHash`.
 * @param secret     the company's identity secret
 * @param members    all identity commitments, in on-chain insertion order
 * @returns { proof: string[8], nullifier, root, publicSignals }
 */
async function prove({ secret, members, scope, signalHash }) {
  secret = BigInt(secret);
  members = members.map(BigInt);
  const commitment = await commitmentOf(secret);
  const index = members.findIndex((m) => m === commitment);
  if (index < 0) throw new Error("identity is not a member of the consortium");
  const tree = await buildTree(members);
  const { pathElements, pathIndices } = tree.proof(index);
  const input = {
    identitySecret: secret.toString(),
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
    root: tree.root.toString(),
    scope: (BigInt(scope) % FIELD).toString(),
    signalHash: (BigInt(signalHash) % FIELD).toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  // Public signal order: [nullifier (output), root, scope, signalHash]
  return {
    proof: toSolidity(proof),
    nullifier: publicSignals[0],
    root: publicSignals[1],
    publicSignals,
    rawProof: proof,
  };
}

async function verify(rawProof, publicSignals) {
  const vkey = require(VKEY);
  return snarkjs.groth16.verify(vkey, publicSignals, rawProof);
}

module.exports = { DEPTH, FIELD, hash, newIdentity, commitmentOf, buildTree, prove, verify, toSolidity };
