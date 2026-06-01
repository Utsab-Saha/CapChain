# type:ignore

import base64
import time
import cv2
import numpy as np

from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    File,
    Form,
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from typing import Optional

from pydantic import BaseModel, field_validator
from dotenv import load_dotenv

load_dotenv()

from utils.hashing import (
    fingerprint_frame,
    detect_tampered_tiles,
    visualize_tampered_tiles,
    hamming_distance,
    generate_sha256,
    _calculate_tile_diff_pct,
    generate_tile_phash,
    tile_phash_similarity,
)

from utils.merkle import build_merkle_tree
from utils.chain import FrameChain
from utils.blockchain import anchor_to_polygon, verify_on_chain

from utils.database import (
    init_db,
    store_snapshot,
    store_tiled_hashes,
    get_snapshot,
    get_tiled_hashes,
    search_by_sha256,
    search_by_phash,
    get_all_snapshots,
)


# ─── Frontend Setup ──────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"


# ─── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):

    try:
        await init_db()
        print("✓ Database initialized")

    except Exception as e:
        print(f"✗ Database initialization failed: {e}")

    yield

    active_chains.clear()
    snapshot_store.clear()
    tile_data_store.clear()


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CaptureChain API",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── In-memory store ─────────────────────────────────────────────────────────

snapshot_store: dict[str, dict] = {}
tile_data_store: dict[str, dict] = {}
active_chains: dict[str, FrameChain] = {}


# ─── Models ──────────────────────────────────────────────────────────────────

class FramePayload(BaseModel):
    image_b64: str


class VerifyPayload(BaseModel):
    image_b64: str
    original_sha256: Optional[str] = None

    @field_validator("original_sha256", mode="before")
    @classmethod
    def normalise_sha(cls, v: object) -> str:
        if v is None:
            return ""
        return str(v).strip()


class VideoSessionPayload(BaseModel):
    session_id: str


class SearchPayload(BaseModel):
    query: str = ""
    limit: int = 10


# ─── Helpers ─────────────────────────────────────────────────────────────────

def decode_frame(image_b64: str) -> np.ndarray:

    try:

        _, data = (
            image_b64.split(",", 1)
            if "," in image_b64
            else ("", image_b64)
        )

        img_bytes = base64.b64decode(data)

        np_arr = np.frombuffer(
            img_bytes,
            dtype=np.uint8
        )

        frame = cv2.imdecode(
            np_arr,
            cv2.IMREAD_COLOR
        )

        if frame is None:
            raise ValueError(
                "cv2.imdecode returned None"
            )

        return frame

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=f"Invalid image data: {exc}"
        ) from exc


def encode_frame(frame: np.ndarray) -> str:

    _, buffer = cv2.imencode(
        ".jpg",
        frame,
        [cv2.IMWRITE_JPEG_QUALITY, 90]
    )

    return (
        "data:image/jpeg;base64,"
        + base64.b64encode(buffer).decode()
    )


def _verdict(
    exact_match: bool,
    hd: int,
    tamper: dict
) -> str:

    if exact_match:
        return "CLEAN — identical to original"

    if not tamper["tampered"] and hd < 8:
        return (
            "CLEAN — visually identical, "
            "minor sensor noise only"
        )

    if tamper["tampered"] and hd < 8:

        return (
            f"TAMPERED — local edit detected in "
            f"{tamper['likely_region']} region "
            f"({tamper['change_pct']}% of frame)"
        )

    return (
        "DIFFERENT — entirely new or heavily modified frame"
    )


# ─── Frontend Route ──────────────────────────────────────────────────────────

@app.get("/")
async def serve_frontend():

    index_file = FRONTEND_DIR / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    return {
        "service": "CaptureChain API",
        "status": "running",
        "docs": "/docs",
        "error": "frontend/index.html not found"
    }


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:

    return {
        "status": "ok",
        "timestamp": time.time()
    }


# ─── Snapshot Routes ─────────────────────────────────────────────────────────

@app.post("/snapshot")
async def process_snapshot(payload: FramePayload) -> dict:

    frame = decode_frame(payload.image_b64)

    fp = fingerprint_frame(frame)

    tile_data = fp["tiled"].pop("tile_data", {})

    tile_data_store[fp["sha256"]] = tile_data

    tile_list = [
        fp["tiled"]["tiles"][k]
        for k in sorted(fp["tiled"]["tiles"])
    ]

    merkle = build_merkle_tree(tile_list)

    blockchain_result = anchor_to_polygon(
        fp["sha256"],
        "snapshot"
    )

    captured_at = time.time()

    await store_snapshot(
        sha256=fp["sha256"],
        phash=fp["phash"],
        captured_at=captured_at,
        capture_type="snapshot",
        merkle_root=merkle["root"],
        blockchain_result=blockchain_result,
    )

    await store_tiled_hashes(
        sha256=fp["sha256"],
        grid_size=fp["tiled"]["grid"],
        tiles=fp["tiled"]["tiles"],
        tile_phashes=fp["tiled"].get("tile_phashes", {}),
    )

    record: dict = {
        "type": "snapshot",
        "captured_at": captured_at,
        "sha256": fp["sha256"],
        "phash": fp["phash"],
        "tiled": fp["tiled"],
        "merkle_root": merkle["root"],
        "merkle_depth": merkle["depth"],
        "blockchain": blockchain_result,
        "storage": {
            "postgres": "✓ phash + tiled_hashes stored",
            "blockchain": "✓ sha256 anchored",
            "memory": "✓ tile_data cached for verification"
        }
    }

    snapshot_store[fp["sha256"]] = record

    return record


# ─── Verify Routes ───────────────────────────────────────────────────────────

@app.post("/verify")
async def verify_frame(payload: VerifyPayload) -> dict:

    suspect_frame = decode_frame(payload.image_b64)

    suspect_fp = fingerprint_frame(suspect_frame)

    suspect_tile_data = suspect_fp["tiled"].pop("tile_data", {})

    # Normalise: treat anything that isn't a full 64-char hex SHA256 as "no SHA provided"
    sha_provided = payload.original_sha256.strip()
    is_valid_sha = (
        len(sha_provided) == 64
        and all(c in "0123456789abcdefABCDEF" for c in sha_provided)
    )

    print(f"[verify] original_sha256={repr(sha_provided)} | valid_sha={is_valid_sha}")

    # ── Auto-search mode: no valid original SHA256 provided ──────────
    # Fingerprint the image, search Postgres by SHA256 + phash,
    # and check Polygon blockchain for the merkle root.
    if not is_valid_sha:

        suspect_fp["tiled"]["tile_data"] = suspect_tile_data

        # 1. Exact SHA256 match
        exact_db_match = await search_by_sha256(suspect_fp["sha256"])

        # 2. Hamming-distance search across ALL snapshots (search_by_phash is exact-only)
        #    Threshold <=10 bits (~84%+ similar)
        HAMMING_THRESHOLD = 10
        all_snaps = await get_all_snapshots()
        similar_matches = []
        for snap in all_snaps:
            if snap["sha256"] == suspect_fp["sha256"]:
                continue
            if not snap.get("phash"):
                continue
            hd = hamming_distance(suspect_fp["phash"], snap["phash"])
            if hd <= HAMMING_THRESHOLD:
                similar_matches.append({
                    **snap,
                    "hamming_distance": hd,
                    "similarity_pct": round((64 - hd) / 64 * 100, 1),
                })
        similar_matches.sort(key=lambda m: m["hamming_distance"])

        # Similarity % for exact match
        if exact_db_match and exact_db_match.get("phash"):
            hd_exact = hamming_distance(suspect_fp["phash"], exact_db_match["phash"])
            exact_similarity_pct = round((64 - hd_exact) / 64 * 100, 1)
        else:
            exact_similarity_pct = 100.0 if exact_db_match else None

        # 3. Per-tile similarity vs best match (tile hashes from DB — no pixel data needed)
        tile_similarity: dict = {}
        best_match_sha = None
        if exact_db_match:
            best_match_sha = exact_db_match["sha256"]
        elif similar_matches:
            best_match_sha = similar_matches[0]["sha256"]

        if best_match_sha:
            original_tiled = await get_tiled_hashes(best_match_sha)
            print(f"[tile-sim] original_tiled={original_tiled is not None} orig_tph_count={len(original_tiled.get('tile_phashes',{})) if original_tiled else 0} suspect_tph_count={len(suspect_fp['tiled'].get('tile_phashes',{}))}")
            if original_tiled:
                suspect_tiles   = suspect_fp["tiled"]["tiles"]
                suspect_tph     = suspect_fp["tiled"].get("tile_phashes", {})
                orig_tiles      = original_tiled.get("tiles", {})
                orig_tph        = original_tiled.get("tile_phashes", {})
                orig_px_cache   = tile_data_store.get(best_match_sha, {})
                suspect_td      = suspect_fp["tiled"].get("tile_data", suspect_tile_data)

                exact_count = phash_count = pixel_count = zero_count = 0
                for key in suspect_tiles:
                    if key not in orig_tiles:
                        tile_similarity[key] = 0.0
                        zero_count += 1
                    elif suspect_tiles[key] == orig_tiles[key]:
                        tile_similarity[key] = 100.0
                        exact_count += 1
                    else:
                        # --- Fallback priority: pHash → pixel → 0 ---
                        # 1) Try pHash if both sides have a stored hash
                        s_ph = suspect_tph.get(key)
                        o_ph = orig_tph.get(key)

                        if s_ph and o_ph:
                            tile_similarity[key] = tile_phash_similarity(s_ph, o_ph)
                            phash_count += 1

                        # 2) If orig pHash is missing from DB but we have orig pixel
                        #    data in memory, compute it on the fly
                        elif s_ph:
                            orig_px = orig_px_cache.get(key)
                            if orig_px is not None:
                                o_ph_computed = generate_tile_phash(orig_px)
                                tile_similarity[key] = tile_phash_similarity(s_ph, o_ph_computed)
                                phash_count += 1
                            else:
                                # No orig pixel data either — cannot compare
                                tile_similarity[key] = 0.0
                                zero_count += 1

                        # 3) Pixel-level comparison
                        else:
                            orig_px = orig_px_cache.get(key)
                            sus_px  = suspect_td.get(key)
                            if orig_px is not None and sus_px is not None:
                                diff_pct = _calculate_tile_diff_pct(orig_px, sus_px)
                                tile_similarity[key] = round(100.0 - diff_pct, 1)
                                pixel_count += 1
                            else:
                                tile_similarity[key] = 0.0
                                zero_count += 1

                print(f"[tile-sim] exact={exact_count} phash={phash_count} pixel={pixel_count} zero={zero_count} sample={list(tile_similarity.items())[:4]}")

        # 4. Blockchain check
        blockchain_result = verify_on_chain(suspect_fp["sha256"])

        print(f"[verify] best_match_sha={best_match_sha} tile_similarity_count={len(tile_similarity)} sample={list(tile_similarity.items())[:4]}")

        # Build verdict
        chain_ok = blockchain_result.get("verified", False)
        if exact_db_match and chain_ok:
            verdict = "VERIFIED — exact match found in database and confirmed on Polygon"
        elif exact_db_match:
            verdict = "FOUND — exact match in database (blockchain not configured or pending)"
        elif similar_matches:
            verdict = (
                f"SIMILAR — {len(similar_matches)} visually similar "
                f"snapshot(s) found; no exact SHA256 match"
            )
        else:
            verdict = "NOT FOUND — no matching or similar snapshot in database"

        return {
            "standalone": True,
            "sha256": suspect_fp["sha256"],
            "phash": suspect_fp["phash"],
            "merkle_root": suspect_fp["sha256"],
            "exact_match": exact_db_match is not None,
            "exact_record": exact_db_match,
            "exact_similarity_pct": exact_similarity_pct,
            "similar_count": len(similar_matches),
            "similar_matches": similar_matches,
            "tile_similarity": tile_similarity,        # per-tile 0-100% vs best match
            "best_match_sha": best_match_sha,
            "blockchain": blockchain_result,
            "in_database": exact_db_match is not None,
            "captured_at": exact_db_match["captured_at"] if exact_db_match else None,
            "hamming_distance": None,
            "visually_similar": len(similar_matches) > 0,
            "tamper": {
                "tampered": False,
                "changed_tiles": [],
                "change_pct": 0.0,
                "likely_region": "none",
            },
            "annotated_image": None,
            "verdict": verdict,
        }

    # ── Comparison mode: original SHA256 provided ────────────────────

    original_record = snapshot_store.get(
        payload.original_sha256
    )

    if not original_record:

        db_record = await get_snapshot(
            payload.original_sha256
        )

        if not db_record:

            raise HTTPException(
                status_code=404,
                detail=(
                    "Original record not found — "
                    "capture a snapshot first"
                ),
            )

        tiled_data = await get_tiled_hashes(
            payload.original_sha256
        )

        if not tiled_data:

            raise HTTPException(
                status_code=404,
                detail="Tiled hash data not found",
            )

        original_record = {
            "sha256": db_record["sha256"],
            "phash": db_record["phash"],
            "tiled": tiled_data,
        }

    original_tiled = original_record["tiled"].copy()

    suspect_tiled = suspect_fp["tiled"]

    original_tiled["tile_data"] = (
        tile_data_store.get(
            payload.original_sha256,
            {}
        )
    )

    suspect_tiled["tile_data"] = suspect_tile_data

    exact_match = (
        suspect_fp["sha256"]
        == payload.original_sha256
    )

    hd = hamming_distance(
        suspect_fp["phash"],
        original_record["phash"]
    )

    tamper_result = detect_tampered_tiles(
        original_tiled,
        suspect_tiled
    )

    annotated_frame = visualize_tampered_tiles(
        suspect_frame,
        tamper_result
    )

    annotated_b64 = encode_frame(
        annotated_frame
    )

    return {
        "standalone": False,
        "exact_match": exact_match,
        "hamming_distance": hd,
        "visually_similar": hd < 8,
        "tamper": tamper_result,
        "annotated_image": annotated_b64,
        "verdict": _verdict(
            exact_match,
            hd,
            tamper_result,
        ),
    }


# ─── Upload Verify ───────────────────────────────────────────────────────────

@app.post("/verify/upload")
async def verify_upload(
    file: bytes = File(...),
    original_sha256: str = Form(...)
) -> dict:

    try:

        np_arr = np.frombuffer(
            file,
            dtype=np.uint8
        )

        suspect_frame = cv2.imdecode(
            np_arr,
            cv2.IMREAD_COLOR
        )

        if suspect_frame is None:
            raise ValueError("Invalid JPG")

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=f"Invalid JPG file: {exc}"
        ) from exc

    suspect_fp = fingerprint_frame(
        suspect_frame
    )

    return {
        "message": "Upload verification working",
        "sha256": suspect_fp["sha256"],
        "phash": suspect_fp["phash"],
    }


# ─── Video Session Routes ────────────────────────────────────────────────────

@app.post("/video/start")
def start_video_session(
    payload: VideoSessionPayload
) -> dict:

    active_chains[payload.session_id] = FrameChain()

    return {
        "session_id": payload.session_id,
        "started": True
    }


@app.post("/video/frame/{session_id}")
def add_video_frame(
    session_id: str,
    payload: FramePayload
) -> dict:

    if session_id not in active_chains:

        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )

    frame = decode_frame(payload.image_b64)

    chain = active_chains[session_id]

    record = chain.add_frame(frame)

    return {
        "sequence": record["sequence"],
        "chain_hash": record["chain_hash"],
        "merkle_root": record["merkle_root"],
    }


@app.post("/video/end/{session_id}")
def end_video_session(session_id: str) -> dict:

    if session_id not in active_chains:

        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )

    chain = active_chains.pop(session_id)

    verify = chain.verify_chain()

    anchor = None

    if verify["valid"]:

        final_root = chain.get_final_merkle_root()

        if final_root:

            anchor = anchor_to_polygon(
                final_root,
                "video_clip"
            )

    return {
        "session_id": session_id,
        "frame_count": chain.sequence,
        "chain": verify,
        "blockchain": anchor,
    }


# ─── Blockchain Verification ────────────────────────────────────────────────

@app.get("/verify/chain/{merkle_root}")
def verify_on_blockchain(
    merkle_root: str
) -> dict:

    return verify_on_chain(merkle_root)


# ─── Search Routes ───────────────────────────────────────────────────────────

@app.post("/search/hashes")
async def search_video_hashes(
    payload: SearchPayload
) -> dict:

    all_snapshots = await get_all_snapshots()

    if not all_snapshots:

        return {
            "query": payload.query,
            "total_matches": 0,
            "results": [],
            "total_in_database": 0,
        }

    results = []

    if (
        not payload.query
        or payload.query.strip() == ""
    ):

        results = all_snapshots[:payload.limit]

    else:

        results = [
            s for s in all_snapshots
            if payload.query.lower()
            in s["sha256"].lower()
        ][:payload.limit]

    return {
        "query": payload.query,
        "total_matches": len(results),
        "results": results,
        "total_in_database": len(all_snapshots),
    }


# ─── WebSocket ───────────────────────────────────────────────────────────────

@app.websocket("/ws/live/{session_id}")
async def websocket_live(
    websocket: WebSocket,
    session_id: str
) -> None:

    await websocket.accept()

    chain = FrameChain()

    try:

        while True:

            data = await websocket.receive_text()

            frame = decode_frame(data)

            record = chain.add_frame(frame)

            await websocket.send_json({
                "sequence": record["sequence"],
                "sha256": (
                    record["sha256"][:16] + "..."
                ),
                "phash": record["phash"],
                "chain_hash": (
                    record["chain_hash"][:16] + "..."
                ),
                "merkle_root": (
                    record["merkle_root"][:16] + "..."
                ),
            })

    except WebSocketDisconnect:
        pass


# ─── Frontend Fallback ───────────────────────────────────────────────────────

@app.get("/{full_path:path}")
async def frontend_routes(full_path: str):

    excluded_routes = (
        "snapshot",
        "verify",
        "video",
        "search",
        "health",
        "docs",
        "openapi.json",
        "ws",
    )

    if full_path.startswith(excluded_routes):

        raise HTTPException(
            status_code=404,
            detail="Not found"
        )

    index_file = FRONTEND_DIR / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    raise HTTPException(
        status_code=404,
        detail="Frontend not found"
    )