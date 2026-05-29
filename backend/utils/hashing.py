#type: ignore

import hashlib
import cv2
import numpy as np


# ─── SHA256 ───────────────────────────────────────────────────────────────────

def generate_sha256(frame: np.ndarray) -> str:
    """Exact identity hash — any single pixel change produces a different hash."""
    if frame is None or frame.size == 0:
        raise ValueError("Cannot hash null/empty frame")
    return hashlib.sha256(frame.tobytes()).hexdigest()


# ─── pHASH ────────────────────────────────────────────────────────────────────

def generate_phash(frame: np.ndarray, hash_size: int = 8) -> str:
    """
    Perceptual hash — visually similar frames produce identical or near-identical hashes.
    Robust to sensor noise, minor lighting shifts, and slight compression differences.
    """
    if frame is None or frame.size == 0:
        raise ValueError("Cannot hash null/empty frame")

    gray      = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    resized   = cv2.resize(gray, (hash_size + 1, hash_size), interpolation=cv2.INTER_AREA)
    # numpy 2.x: np.float32 is still valid; use explicit dtype= kwarg for clarity
    dct       = cv2.dct(resized.astype(np.float32))
    dct_block = dct[:hash_size, :hash_size]
    mean_val  = float(dct_block.mean())
    bits      = (dct_block > mean_val).flatten()
    return format(int("".join("1" if b else "0" for b in bits), 2), "016x")


def hamming_distance(hash1: str, hash2: str) -> int:
    """Lower = more visually similar. <8 → likely same scene."""
    return bin(int(hash1, 16) ^ int(hash2, 16)).count("1")


# ─── TILED SHA256 ─────────────────────────────────────────────────────────────

def generate_tiled_sha256(frame: np.ndarray, grid: tuple[int, int] = (8, 8)) -> dict:
    """
    Splits frame into grid tiles and hashes each independently.
    Also stores tile data for pixel-level comparison during verification.
    Localizes exactly which region was tampered.
    """
    if frame is None or frame.size == 0:
        raise ValueError("Cannot tile-hash null/empty frame")

    rows, cols         = grid
    h, w               = frame.shape[:2]
    tile_h, tile_w     = h // rows, w // cols
    tile_hashes: dict  = {}
    tile_data: dict    = {}

    for r in range(rows):
        for c in range(cols):
            tile = frame[
                r * tile_h : (r + 1) * tile_h,
                c * tile_w : (c + 1) * tile_w,
            ]
            key = f"{r}_{c}"
            tile_hashes[key] = hashlib.sha256(tile.tobytes()).hexdigest()
            # Store tile data for later pixel-level comparison
            tile_data[key] = tile

    root = hashlib.sha256(
        "".join(
            tile_hashes[f"{r}_{c}"]
            for r in range(rows)
            for c in range(cols)
        ).encode()
    ).hexdigest()

    return {
        "grid": f"{rows}x{cols}",
        "tiles": tile_hashes,
        "tile_data": tile_data,  # For pixel-level comparison
        "root": root,
    }


def _calculate_tile_diff_pct(tile1: np.ndarray, tile2: np.ndarray) -> float:
    """Calculate percentage of pixels that differ between two tiles (0-100)."""
    if tile1.shape != tile2.shape:
        return 100.0
    
    # Compute absolute difference per pixel
    diff = cv2.absdiff(tile1, tile2)
    # Consider a pixel changed if any channel differs by >5 (out of 255)
    threshold = 5
    changed_pixels = np.any(diff > threshold, axis=2) if len(diff.shape) > 2 else diff > threshold
    pct = float(np.sum(changed_pixels) / changed_pixels.size * 100)
    return pct


def detect_tampered_tiles(
    original: dict,
    suspect: dict,
    pixel_tolerance_pct: float = 5.0,
) -> dict:
    """
    Compare two tiled fingerprints — returns which tiles were significantly altered.
    Uses pixel-level comparison with tolerance to filter out sensor noise.
    
    Args:
        original: Original tiled fingerprint dict (with tile_data)
        suspect: Suspect tiled fingerprint dict (with tile_data)
        pixel_tolerance_pct: Percentage of pixels that can differ before marking tile as changed (default 5%)
    
    Returns:
        Dict with tampering details
    """
    changed = []
    
    # Compare tiles pixel-by-pixel with tolerance
    for key in original["tiles"]:
        suspect_hash = suspect["tiles"].get(key)
        original_hash = original["tiles"][key]
        
        # If hashes differ, check pixel-level difference
        if original_hash != suspect_hash:
            orig_data = original["tile_data"].get(key)
            sus_data = suspect["tile_data"].get(key)
            
            # If we have tile data, use pixel-level comparison with tolerance
            if orig_data is not None and sus_data is not None:
                diff_pct = _calculate_tile_diff_pct(orig_data, sus_data)
                # Only mark as changed if difference exceeds tolerance
                if diff_pct > pixel_tolerance_pct:
                    changed.append(key)
            else:
                # Fallback: no tile data, so mark as changed if hashes differ
                changed.append(key)
    
    rows, cols  = map(int, original["grid"].split("x"))
    total_tiles = rows * cols
    change_pct  = round((len(changed) / total_tiles) * 100, 2)

    return {
        "tampered":      len(changed) > 0,
        "changed_tiles": changed,
        "change_pct":    change_pct,
        "likely_region": _describe_region(changed, rows, cols),
        "tolerance_pct": pixel_tolerance_pct,
    }


def _describe_region(tiles: list[str], rows: int, cols: int) -> str:
    if not tiles:
        return "none"
    rs = [int(t.split("_")[0]) for t in tiles]
    cs = [int(t.split("_")[1]) for t in tiles]
    v  = "top"    if max(rs) < rows // 3 else "bottom" if min(rs) > 2 * rows // 3 else "center"
    h  = "left"   if max(cs) < cols // 3 else "right"  if min(cs) > 2 * cols // 3 else ""
    return f"{v}-{h}".strip("-")


def visualize_tampered_tiles(
    frame: np.ndarray,
    tamper_result: dict,
    grid: tuple[int, int] = (8, 8),
    color: tuple[int, int, int] = (0, 0, 255),
    alpha: float = 0.4,
) -> np.ndarray:
    """Draw semi-transparent overlay on tampered tiles. Returns annotated frame copy."""
    output = frame.copy()

    if not tamper_result["tampered"]:
        return output

    rows, cols     = grid
    h, w           = frame.shape[:2]
    tile_h, tile_w = h // rows, w // cols
    overlay        = frame.copy()

    for tile_key in tamper_result["changed_tiles"]:
        r, c   = map(int, tile_key.split("_"))
        x1, y1 = c * tile_w, r * tile_h
        x2, y2 = x1 + tile_w, y1 + tile_h
        cv2.rectangle(overlay, (x1, y1), (x2, y2), color, thickness=-1)
        cv2.putText(
            overlay, tile_key, (x1 + 4, y1 + 16),
            cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1, cv2.LINE_AA,
        )

    cv2.addWeighted(overlay, alpha, output, 1 - alpha, 0, output)

    label = f"TAMPERED | {tamper_result['change_pct']}% | {tamper_result['likely_region']}"
    cv2.rectangle(output, (0, 0), (w, 28), (0, 0, 180), -1)
    cv2.putText(
        output, label, (8, 20),
        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1, cv2.LINE_AA,
    )

    return output


# ─── FULL FINGERPRINT ─────────────────────────────────────────────────────────

def fingerprint_frame(frame: np.ndarray) -> dict:
    """Single call — returns all hashes. Use this in your pipeline."""
    return {
        "sha256": generate_sha256(frame),
        "phash":  generate_phash(frame),
        "tiled":  generate_tiled_sha256(frame),
    }
