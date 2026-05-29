#type:ignore

import os
import json
from web3 import Web3
from web3.exceptions import Web3Exception

RPC_URL          = os.getenv("POLYGON_RPC_URL", "")
PRIVATE_KEY      = os.getenv("POLYGON_PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.getenv("POLYGON_CONTRACT_ADDRESS", "")

# Minimal ABI for CaptureRegistry contract
CONTRACT_ABI: list[dict] = json.loads("""[
  {
    "inputs": [
      {"internalType": "bytes32", "name": "merkleRoot",  "type": "bytes32"},
      {"internalType": "string",  "name": "captureType", "type": "string"}
    ],
    "name": "anchorCapture",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
    "name": "verify",
    "outputs": [
      {"internalType": "bool",    "name": "", "type": "bool"},
      {"internalType": "uint256", "name": "", "type": "uint256"}
    ],
    "stateMutability": "view",
    "type": "function"
  }
]""")


def _is_configured() -> bool:
    return bool(RPC_URL and PRIVATE_KEY and CONTRACT_ADDRESS)


def _get_web3() -> Web3:
    """Return a connected Web3 instance."""
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to RPC endpoint: {RPC_URL}")
    return w3


def anchor_to_polygon(merkle_root_hex: str, capture_type: str) -> dict:
    """
    Anchor a Merkle root to your Polygon smart contract.
    Returns tx_hash and block number on success.
    Returns a mock response when blockchain env vars are not configured.
    """
    if not _is_configured():
        return {
            "anchored":     False,
            "mock":         True,
            "reason":       (
                "Blockchain env vars not configured — "
                "set POLYGON_RPC_URL, POLYGON_PRIVATE_KEY, POLYGON_CONTRACT_ADDRESS"
            ),
            "merkle_root":  merkle_root_hex,
            "capture_type": capture_type,
        }

    try:
        w3       = _get_web3()
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=CONTRACT_ABI,
        )
        account = w3.eth.account.from_key(PRIVATE_KEY)

        merkle_bytes = bytes.fromhex(merkle_root_hex)

        # web3 7.x: build_transaction requires explicit gas or gas estimation
        fn   = contract.functions.anchorCapture(merkle_bytes, capture_type)
        gas  = fn.estimate_gas({"from": account.address})

        tx = fn.build_transaction({
            "from":     account.address,
            "nonce":    w3.eth.get_transaction_count(account.address),
            "gas":      gas,
            "gasPrice": w3.eth.gas_price,
        })

        signed  = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        # web3 7.x uses .raw_transaction (snake_case)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        return {
            "anchored":     True,
            "tx_hash":      tx_hash.hex(),
            "block_number": receipt["blockNumber"],
            "merkle_root":  merkle_root_hex,
            "capture_type": capture_type,
        }

    except Web3Exception as exc:
        return {
            "anchored":     False,
            "mock":         False,
            "error":        str(exc),
            "merkle_root":  merkle_root_hex,
            "capture_type": capture_type,
        }


def verify_on_chain(merkle_root_hex: str) -> dict:
    """Check if a Merkle root exists on chain."""
    if not _is_configured():
        return {"verified": False, "mock": True, "reason": "Blockchain not configured"}

    try:
        w3       = _get_web3()
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=CONTRACT_ABI,
        )

        exists, timestamp = contract.functions.verify(
            bytes.fromhex(merkle_root_hex)
        ).call()

        return {"verified": exists, "anchored_at": timestamp}

    except Web3Exception as exc:
        return {"verified": False, "error": str(exc)}
