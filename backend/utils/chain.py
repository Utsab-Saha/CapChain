#type: ignore

import hashlib
import hmac
import time
import os
import numpy as np
from utils.hashing import generate_sha256, generate_phash, generate_tiled_sha256
from utils.merkle import build_merkle_tree

SECRET_KEY = os.getenv("CAPTURE_HMAC_SECRET", "dev-secret-change-in-prod").encode()


class FrameChain:
    """
    Links frames cryptographically in sequence.
    Tampering with any single frame (modify, insert, delete, reorder)
    invalidates the entire chain from that point forward.
    """

    def __init__(self) -> None:
        self.previous_hash: str = hashlib.sha256(b"genesis").hexdigest()
        self.sequence: int = 0
        self._chain: list[dict] = []

    def add_frame(self, frame: np.ndarray) -> dict:
        """Fingerprint a frame and chain it to the previous one."""
        frame_sha256 = generate_sha256(frame)
        tiled        = generate_tiled_sha256(frame)
        phash        = generate_phash(frame)

        # Merkle root from tile hashes
        tile_list = [tiled["tiles"][k] for k in sorted(tiled["tiles"])]
        merkle    = build_merkle_tree(tile_list)

        # HMAC-signed chain hash — cannot be forged without SECRET_KEY
        chain_input = (
            f"{self.previous_hash}{frame_sha256}{self.sequence}"
        ).encode()
        chain_hash = hmac.new(
            SECRET_KEY, chain_input, digestmod=hashlib.sha256
        ).hexdigest()

        record: dict = {
            "sequence":      self.sequence,
            "captured_at":   time.time(),
            "sha256":        frame_sha256,
            "phash":         phash,
            "tiled":         tiled,
            "merkle_root":   merkle["root"],
            "previous_hash": self.previous_hash,
            "chain_hash":    chain_hash,
        }

        self._chain.append(record)
        self.previous_hash = chain_hash
        self.sequence     += 1

        return record

    def verify_chain(self) -> dict:
        """
        Re-walks the entire chain and checks every link.
        Call during audit or on suspicion of tampering.
        """
        expected_prev = hashlib.sha256(b"genesis").hexdigest()

        for record in self._chain:
            if record["previous_hash"] != expected_prev:
                return {
                    "valid":              False,
                    "broken_at_sequence": record["sequence"],
                    "reason":             "previous_hash mismatch — frame inserted, deleted, or reordered",
                }

            chain_input = (
                f"{record['previous_hash']}{record['sha256']}{record['sequence']}"
            ).encode()
            expected_chain = hmac.new(
                SECRET_KEY, chain_input, digestmod=hashlib.sha256
            ).hexdigest()

            if record["chain_hash"] != expected_chain:
                return {
                    "valid":              False,
                    "broken_at_sequence": record["sequence"],
                    "reason":             "chain_hash mismatch — frame content was modified",
                }

            expected_prev = record["chain_hash"]

        return {"valid": True, "broken_at_sequence": None, "reason": None}

    def get_chain(self) -> list[dict]:
        return self._chain

    def get_final_merkle_root(self) -> str | None:
        """Root of the last frame — use this for blockchain anchoring."""
        if not self._chain:
            return None
        return self._chain[-1]["merkle_root"]
