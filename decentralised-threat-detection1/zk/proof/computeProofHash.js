'use strict'; // Enforce stricter parsing and error handling

const fs = require('fs');
const { ethers } = require('ethers');

/**
 * @typedef {Object} ProofData
 * @property {string[]} pi_a - The 'A' component of the proof.
 * @property {string[][]} pi_b - The 'B' component of the proof.
 * @property {string[]} pi_c - The 'C' component of the proof.
 */

/**
 * @typedef {string[]} PublicSignalsData
 */

/**
 * @typedef {Object} ProofHashCalculationResult
 * @property {string[]} pi_a - The parsed pi_a component as an array of strings.
 * @property {string[]} pi_b - The flattened and padded pi_b component as an array of strings.
 * @property {string[]} pi_c - The parsed pi_c component as an array of strings.
 * @property {string[]} pubSignals - The public signals as an array of strings.
 * @property {string} proofHash - The calculated Keccak256 hash of the packed proof components.
 */

/**
 * Configuration for file paths.
 * @type {{PROOF_JSON_PATH: string, PUBLIC_JSON_PATH: string}}
 */
const CONFIG = {
    PROOF_JSON_PATH: './proof.json',
    PUBLIC_JSON_PATH: './public.json'
};

/**
 * Calculates the Keccak256 hash of ZK-proof components (pi_a, pi_b, pi_c) and public signals.
 * This function reads proof and public input data from specified JSON files,
 * sanitizes the inputs, and then encodes and hashes them according to `solidityPack` rules.
 *
 * @returns {Promise<ProofHashCalculationResult | void>} A promise that resolves to an object
 * containing the parsed proof components, public signals, and the
 * calculated proof hash. Returns void if an error occurs.
 */
async function calculateProofHash() {
    try {
        // 1. Read and parse input files
        /** @type {ProofData} */
        const proofJson = JSON.parse(fs.readFileSync(CONFIG.PROOF_JSON_PATH, 'utf8'));
        /** @type {PublicSignalsData} */
        const publicJson = JSON.parse(fs.readFileSync(CONFIG.PUBLIC_JSON_PATH, 'utf8'));

        // 2. Parse and sanitize each proof component and public signals
        // Ensure that components are converted to Ethers BigNumber objects.
        const piA = proofJson.pi_a.slice(0, 2).map(x => ethers.BigNumber.from(x));

        const piB_2x2 = [
            [ethers.BigNumber.from(proofJson.pi_b[0][0]), ethers.BigNumber.from(proofJson.pi_b[0][1])],
            [ethers.BigNumber.from(proofJson.pi_b[1][0]), ethers.BigNumber.from(proofJson.pi_b[1][1])]
        ];

        // Flatten pi_b for hashing and pad to a fixed size of 8 (uint256[8])
        let piB_flat = piB_2x2.flat();
        while (piB_flat.length < 8) {
            piB_flat.push(ethers.constants.Zero); // Use ethers.constants.Zero for clarity
        }

        const piC = proofJson.pi_c.slice(0, 2).map(x => ethers.BigNumber.from(x));
        const publicSignals = publicJson.map(x => ethers.BigNumber.from(x));

        // 3. Encode and hash the components
        const types = ['uint256[2]', 'uint256[8]', 'uint256[2]', `uint256[${publicSignals.length}]`];
        const values = [piA, piB_flat, piC, publicSignals];

        const encodedPackedData = ethers.utils.solidityPack(types, values);
        const proofHash = ethers.utils.keccak256(encodedPackedData);

        // 4. Output results to console
        console.log("--- ZK Proof Hash Calculation Results ---");
        console.log(`Proof A (pi_a): ${JSON.stringify(piA.map(x => x.toString()))}`);
        console.log(`Proof B (pi_b, flattened and padded): ${JSON.stringify(piB_flat.map(x => x.toString()))}`);
        console.log(`Proof C (pi_c): ${JSON.stringify(piC.map(x => x.toString()))}`);
        console.log(`Public Inputs (pubSignals): ${JSON.stringify(publicSignals.map(x => x.toString()))}`);
        console.log(`\n✅ Calculated Proof Hash: ${proofHash}`);

        console.log("\n--- For use in Solidity's verifyProof(...) call ---");
        console.log(`pi_a: ${JSON.stringify(piA.map(x => x.toString()))}`);
        console.log(`pi_b: ${JSON.stringify(piB_2x2.map(pair => pair.map(x => x.toString())))}`);
        console.log(`pi_c: ${JSON.stringify(piC.map(x => x.toString()))}`);
        console.log(`pubSignals: ${JSON.stringify(publicSignals.map(x => x.toString()))}`);
        console.log("-----------------------------------------");

        return {
            pi_a: piA.map(x => x.toString()),
            pi_b: piB_flat.map(x => x.toString()),
            pi_c: piC.map(x => x.toString()),
            pubSignals: publicSignals.map(x => x.toString()),
            proofHash: proofHash
        };

    } catch (error) {
        console.error("\n❌ An error occurred during proof hash calculation:");
        if (error.code === 'ENOENT') {
            console.error(`⚠️ Please ensure both '${CONFIG.PROOF_JSON_PATH}' and '${CONFIG.PUBLIC_JSON_PATH}' files exist.`);
            console.error(`Detailed error: ${error.message}`);
        } else if (error instanceof SyntaxError) {
            console.error(`⚠️ JSON parsing error. Please check the format of '${CONFIG.PROOF_JSON_PATH}' or '${CONFIG.PUBLIC_JSON_PATH}'.`);
            console.error(`Detailed error: ${error.message}`);
        } else {
            console.error(`❌ Unexpected error: ${error.message}`);
            console.error(error); // Log the full error for debugging
        }
    }
}

/**
 * Main execution block.
 * Invokes the proof hash calculation and handles its promise resolution.
 */
(async () => {
    console.log("Initiating ZK Proof Hash Calculation Script...");
    await calculateProofHash();
    console.log("Script execution completed.");
})();