#type: ignore
import hashlib


def build_merkle_tree(tile_hashes: list[str]) -> dict:
    """
    Build a Merkle tree from tile hashes.
    Returns root hash + full tree for audit-proof generation.
    """
    if not tile_hashes:
        raise ValueError("No tile hashes provided")

    layer = tile_hashes[:]
    if len(layer) % 2 != 0:
        layer.append(layer[-1])

    tree: list[list[str]] = [layer]

    while len(layer) > 1:
        next_layer: list[str] = []
        for i in range(0, len(layer), 2):
            combined = hashlib.sha256(
                (layer[i] + layer[i + 1]).encode()
            ).hexdigest()
            next_layer.append(combined)
        if len(next_layer) > 1 and len(next_layer) % 2 != 0:
            next_layer.append(next_layer[-1])
        tree.append(next_layer)
        layer = next_layer

    return {
        "root":   tree[-1][0],
        "tree":   tree,
        "depth":  len(tree),
        "leaves": len(tile_hashes),
    }


def generate_merkle_proof(tree: list[list[str]], tile_index: int) -> list[dict]:
    """
    Generate an audit proof for a single tile.
    Verifier only needs this path + root — not all tile hashes.
    """
    proof: list[dict] = []
    idx = tile_index

    for layer in tree[:-1]:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        sibling_idx = min(sibling_idx, len(layer) - 1)
        proof.append({
            "sibling":   layer[sibling_idx],
            "direction": "right" if idx % 2 == 0 else "left",
        })
        idx //= 2

    return proof


def verify_merkle_proof(leaf_hash: str, proof: list[dict], root: str) -> bool:
    """Verify a tile belongs to the Merkle tree without needing all tiles."""
    current = leaf_hash
    for step in proof:
        if step["direction"] == "right":
            combined = step["sibling"] + current
        else:
            combined = current + step["sibling"]
        current = hashlib.sha256(combined.encode()).hexdigest()
    return current == root
