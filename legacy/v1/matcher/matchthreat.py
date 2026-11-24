from web3 import Web3
import json

# Connect to your local or testnet Ethereum node
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))  # or Infura URL

# Load contract
with open("ZKThreatDetectionSystem_abi.json") as f:
    abi = json.load(f)

contract_address = "0xYourContractAddress"
contract = w3.eth.contract(address=contract_address, abi=abi)

# Load proof.json
with open("proof.json") as f:
    proof = json.load(f)

# Load public.json
with open("public.json") as f:
    public_inputs = json.load(f)

# Format proof
pi_a = [int(proof["pi_a"][0], 16), int(proof["pi_a"][1], 16)]
pi_b = [
    [int(proof["pi_b"][0][1], 16), int(proof["pi_b"][0][0], 16)],
    [int(proof["pi_b"][1][1], 16), int(proof["pi_b"][1][0], 16)]
]
pi_c = [int(proof["pi_c"][0], 16), int(proof["pi_c"][1], 16)]

# Format public signals
pub_inputs = [int(public_inputs[0], 16)]  # expectedHash

# Prepare transaction
account = w3.eth.accounts[0]
tx = contract.functions.matchThreat(
    Web3.toBytes(pub_inputs[0]),  # knownMetadataHash (bytes32)
    pi_a,
    pi_b,
    pi_c,
    pub_inputs
).build_transaction({
    'from': account,
    'gas': 500000,
    'nonce': w3.eth.get_transaction_count(account)
})

# Sign and send
private_key = "0xYourPrivateKeyHere"
signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

print(f"Sent! TX Hash: {tx_hash.hex()}")
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Confirmed in block: {receipt.blockNumber}")
