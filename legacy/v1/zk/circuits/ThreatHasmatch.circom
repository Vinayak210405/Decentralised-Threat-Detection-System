pragma circom 2.0.0;

include "circomlib2/poseidon.circom"; // For fast in-circuit hashing

template ThreatHashMatch() {
    signal input threatType;
    signal input severity;

    signal input expectedHash;
    signal output isMatch;

    signal inputHash;
    component hasher = Poseidon(2);
    hasher.inputs[0] <== threatType;
    hasher.inputs[1] <== severity;
    inputHash <== hasher.out;

    isMatch <== inputHash === expectedHash;
}

component main = ThreatHashMatch();
