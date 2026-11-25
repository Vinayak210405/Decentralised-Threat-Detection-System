pragma circom 2.1.6;

// Anonymous membership proof for the threat-sharing consortium.
//
// A company proves, without revealing which company it is:
//   1. it knows the secret behind one of the identity commitments in the
//      consortium's Merkle tree (whose root is public, stored on-chain), and
//   2. its nullifier for this `scope` is Poseidon(secret, scope).
//
// For threat reports, scope = the keyed hash of the indicator (IOC). The same
// company reporting the same IOC twice produces the same nullifier, so the
// contract can count *distinct* companies per IOC while never learning who
// they are. Different IOCs give unlinkable nullifiers.
//
// For governance votes, scope = a hash of the proposal id, giving
// one-company-one-vote, anonymously.
//
// `signalHash` binds the rest of the message (category, severity, evidence
// CID, or the vote choice) to the proof, so a relayer or front-runner cannot
// change it without invalidating the proof.

include "../node_modules/circomlib/circuits/poseidon.circom";

template MerkleRoot(depth) {
    signal input leaf;
    signal input pathElements[depth];
    // pathIndices[i] = 1 if the current node is the RIGHT child at level i.
    signal input pathIndices[depth];
    signal output root;

    signal cur[depth + 1];
    signal left[depth];
    signal right[depth];
    component hashers[depth];

    cur[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        // Each index must be a bit.
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        // left  = idx ? sibling : cur
        // right = idx ? cur     : sibling
        left[i] <== cur[i] + pathIndices[i] * (pathElements[i] - cur[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (cur[i] - pathElements[i]);
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        cur[i + 1] <== hashers[i].out;
    }
    root <== cur[depth];
}

template ConsortiumMembership(depth) {
    // Private
    signal input identitySecret;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    // Public
    signal input root;
    signal input scope;
    signal input signalHash;
    signal output nullifier;

    component commitment = Poseidon(1);
    commitment.inputs[0] <== identitySecret;

    component tree = MerkleRoot(depth);
    tree.leaf <== commitment.out;
    for (var i = 0; i < depth; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    root === tree.root;

    component nul = Poseidon(2);
    nul.inputs[0] <== identitySecret;
    nul.inputs[1] <== scope;
    nullifier <== nul.out;

    // Public inputs that appear in no constraint can be swapped by an attacker
    // without breaking the proof; a dummy quadratic constraint ties signalHash in.
    signal signalSquare;
    signalSquare <== signalHash * signalHash;
}

// Depth 10 = up to 1024 member companies.
component main {public [root, scope, signalHash]} = ConsortiumMembership(10);
