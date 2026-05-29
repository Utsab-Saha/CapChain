# type:ignore

import base64
import time
import cv2
import numpy as np
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from utils.hashing import (
    fingerprint_frame,
    detect_tampered_tiles,
    visualize_tampered_tiles,
    hamming_distance,
    generate_sha256,
)
from utils.merkle import build_merkle_tree
from utils.chain import FrameChain
from utils.blockchain import anchor_to_polygon, verify_on_chain
from utils.database import init_db, store_snapshot, store_tiled_hashes, get_snapshot, get_tiled_hashes, search_by_sha256, search_by_phash, get_all_snapshots


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — initialize database
    try:
        await init_db()
        print("✓ Database initialized")
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
    
    yield
    
    # Shutdown — clear active sessions
    active_chains.clear()
    snapshot_store.clear()
    tile_data_store.clear()


app = FastAPI(title="CaptureChain API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory store (swap for Redis/Postgres in full production) ─────────────
snapshot_store: dict[str, dict] = {}        # sha256 → record
tile_data_store: dict[str, dict] = {}       # sha256 → tile_data (numpy arrays, not JSON-serialized)
active_chains:  dict[str, FrameChain] = {}  # session_id → FrameChain


# ─── Models ───────────────────────────────────────────────────────────────────

class FramePayload(BaseModel):
    image_b64: str          # base64-encoded JPEG from browser webcam


class VerifyPayload(BaseModel):
    image_b64:       str
    original_sha256: str    # SHA256 of the original frame to compare against


class VideoSessionPayload(BaseModel):
    session_id: str


class SearchPayload(BaseModel):
    query: str = ""  # SHA256, pHash, or empty for all
    limit: int = 10  # Max results to return


# ─── Helpers ──────────────────────────────────────────────────────────────────

def decode_frame(image_b64: str) -> np.ndarray:
    """Decode base64 JPEG → OpenCV BGR numpy array."""
    try:
        _, data  = image_b64.split(",", 1) if "," in image_b64 else ("", image_b64)
        img_bytes = base64.b64decode(data)
        np_arr    = np.frombuffer(img_bytes, dtype=np.uint8)
        frame     = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if frame is None:
            raise ValueError("cv2.imdecode returned None — invalid image bytes")
        return frame
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid image data: {exc}") from exc


def encode_frame(frame: np.ndarray) -> str:
    """Encode OpenCV frame → base64 JPEG string."""
    _, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
    return "data:image/jpeg;base64," + base64.b64encode(buffer).decode()


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "timestamp": time.time()}


@app.post("/snapshot")
async def process_snapshot(payload: FramePayload) -> dict:
    """
    Fingerprint a single captured frame.
    - Stores phash and tiled SHA256 in PostgreSQL
    - Anchors only sha256 to blockchain
    - Returns complete fingerprint data
    """
    frame = decode_frame(payload.image_b64)
    fp    = fingerprint_frame(frame)

    # Extract and store tile_data separately (not JSON-serializable)
    tile_data = fp["tiled"].pop("tile_data", {})
    tile_data_store[fp["sha256"]] = tile_data

    # Build merkle tree from tile hashes
    tile_list = [fp["tiled"]["tiles"][k] for k in sorted(fp["tiled"]["tiles"])]
    merkle    = build_merkle_tree(tile_list)
    
    # ✓ Anchor ONLY sha256 to blockchain (not entire tiled data)
    blockchain_result = anchor_to_polygon(fp["sha256"], "snapshot")

    # ✓ Store phash and tiled SHA256 in PostgreSQL
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
    )

    record: dict = {
        "type":         "snapshot",
        "captured_at":  captured_at,
        "sha256":       fp["sha256"],
        "phash":        fp["phash"],
        "tiled":        fp["tiled"],
        "merkle_root":  merkle["root"],
        "merkle_depth": merkle["depth"],
        "blockchain":   blockchain_result,
        "storage": {
            "postgres": "✓ phash + tiled_hashes stored",
            "blockchain": "✓ sha256 anchored",
            "memory": "✓ tile_data cached for verification"
        }
    }

    snapshot_store[fp["sha256"]] = record
    return record


@app.post("/verify")
async def verify_frame(payload: VerifyPayload) -> dict:
    """
    Compare a suspect frame against a stored original.
    Retrieves phash and tiled hashes from PostgreSQL.
    Returns tamper-detection results with annotated image.
    """
    suspect_frame = decode_frame(payload.image_b64)
    suspect_fp    = fingerprint_frame(suspect_frame)

    # Extract and store suspect tile_data
    suspect_tile_data = suspect_fp["tiled"].pop("tile_data", {})

    # Try to get original record from memory, then from PostgreSQL
    original_record = snapshot_store.get(payload.original_sha256)
    
    if not original_record:
        # Try fetching from PostgreSQL
        db_record = await get_snapshot(payload.original_sha256)
        if not db_record:
            raise HTTPException(
                status_code=404,
                detail="Original record not found — capture a snapshot first",
            )
        
        # Fetch tiled hashes from PostgreSQL
        tiled_data = await get_tiled_hashes(payload.original_sha256)
        if not tiled_data:
            raise HTTPException(
                status_code=404,
                detail="Tiled hash data not found in database",
            )
        
        original_record = {
            "sha256": db_record["sha256"],
            "phash": db_record["phash"],
            "tiled": tiled_data,
        }

    original_tiled = original_record["tiled"].copy()
    suspect_tiled  = suspect_fp["tiled"]

    # Add tile_data back for pixel-level comparison
    original_tiled["tile_data"] = tile_data_store.get(payload.original_sha256, {})
    suspect_tiled["tile_data"] = suspect_tile_data

    exact_match   = suspect_fp["sha256"] == payload.original_sha256
    hd            = hamming_distance(suspect_fp["phash"], original_record["phash"])
    tamper_result = detect_tampered_tiles(original_tiled, suspect_tiled)

    annotated_frame = visualize_tampered_tiles(suspect_frame, tamper_result)
    annotated_b64   = encode_frame(annotated_frame)

    return {
        "exact_match":      exact_match,
        "hamming_distance": hd,
        "visually_similar": hd < 8,
        "tamper":           tamper_result,
        "annotated_image":  annotated_b64,
        "verdict":          _verdict(exact_match, hd, tamper_result),
    }


@app.post("/verify/upload")
async def verify_upload(file: bytes = File(...), original_sha256: str = Form(...)) -> dict:
    """
    Verify an uploaded JPG file against a stored original snapshot.
    Retrieves phash and tiled hashes from PostgreSQL.
    Returns tamper-detection results with annotated image.
    """
    try:
        # Decode JPG bytes → OpenCV BGR numpy array
        np_arr    = np.frombuffer(file, dtype=np.uint8)
        suspect_frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if suspect_frame is None:
            raise ValueError("cv2.imdecode returned None — invalid JPG file")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JPG file: {exc}") from exc

    suspect_fp    = fingerprint_frame(suspect_frame)

    # Extract and store suspect tile_data
    suspect_tile_data = suspect_fp["tiled"].pop("tile_data", {})

    # Try to get original record from memory, then from PostgreSQL
    original_record = snapshot_store.get(original_sha256)
    
    if not original_record:
        # Try fetching from PostgreSQL
        db_record = await get_snapshot(original_sha256)
        if not db_record:
            raise HTTPException(
                status_code=404,
                detail="Original record not found — capture a snapshot first",
            )
        
        # Fetch tiled hashes from PostgreSQL
        tiled_data = await get_tiled_hashes(original_sha256)
        if not tiled_data:
            raise HTTPException(
                status_code=404,
                detail="Tiled hash data not found in database",
            )
        
        original_record = {
            "sha256": db_record["sha256"],
            "phash": db_record["phash"],
            "tiled": tiled_data,
        }

    original_tiled = original_record["tiled"].copy()
    suspect_tiled  = suspect_fp["tiled"]

    # Add tile_data back for pixel-level comparison
    original_tiled["tile_data"] = tile_data_store.get(original_sha256, {})
    suspect_tiled["tile_data"] = suspect_tile_data

    exact_match   = suspect_fp["sha256"] == original_sha256
    hd            = hamming_distance(suspect_fp["phash"], original_record["phash"])
    tamper_result = detect_tampered_tiles(original_tiled, suspect_tiled)

    annotated_frame = visualize_tampered_tiles(suspect_frame, tamper_result)
    annotated_b64   = encode_frame(annotated_frame)

    return {
        "exact_match":      exact_match,
        "hamming_distance": hd,
        "visually_similar": hd < 8,
        "tamper":           tamper_result,
        "annotated_image":  annotated_b64,
        "verdict":          _verdict(exact_match, hd, tamper_result),
    }


def _verdict(exact_match: bool, hd: int, tamper: dict) -> str:
    if exact_match:
        return "CLEAN — identical to original"
    if not tamper["tampered"] and hd < 8:
        return "CLEAN — visually identical, minor sensor noise only"
    if tamper["tampered"] and hd < 8:
        return (
            f"TAMPERED — local edit detected in {tamper['likely_region']} region "
            f"({tamper['change_pct']}% of frame)"
        )
    return "DIFFERENT — entirely new or heavily modified frame"


# ─── Database Authentication Routes ───────────────────────────────────────────

@app.post("/verify/check-database")
async def check_database_authenticity(payload: VerifyPayload) -> dict:
    """
    Check if the SHA256 and pHash exist in the database (PostgreSQL).
    Compare against all stored snapshots and blockchain records.
    Verify merkle roots on live blockchain (Polygon).
    Perform tamper detection on exact matches.
    Returns match status, similar records, blockchain verification, and tile comparison.
    """
    suspect_frame = decode_frame(payload.image_b64)
    suspect_fp    = fingerprint_frame(suspect_frame)
    
    suspect_sha256 = suspect_fp["sha256"]
    suspect_phash  = suspect_fp["phash"]
    
    # Extract and store suspect tile_data
    suspect_tile_data = suspect_fp["tiled"].pop("tile_data", {})
    
    # Search for exact SHA256 match
    sha256_match = await search_by_sha256(suspect_sha256)
    
    # Search for exact pHash match
    phash_matches = await search_by_phash(suspect_phash)
    
    # Get all snapshots to find similar pHashes
    all_snapshots = await get_all_snapshots()
    
    similar_hashes = []
    if all_snapshots:
        for snapshot in all_snapshots:
            # Skip exact matches we already found
            if snapshot["sha256"] == suspect_sha256:
                continue
            
            hd = hamming_distance(suspect_phash, snapshot["phash"])
            if hd < 8:  # Similar if hamming distance < 8
                similar_hashes.append({
                    "sha256": snapshot["sha256"],
                    "phash": snapshot["phash"],
                    "hamming_distance": hd,
                    "capture_type": snapshot.get("capture_type", "unknown"),
                    "captured_at": snapshot.get("captured_at"),
                    "merkle_root": snapshot.get("merkle_root"),
                })
    
    # Determine authenticity
    is_authentic = sha256_match is not None or phash_matches is not None
    
    # Perform tamper detection on exact SHA256 match
    tamper_result = None
    if sha256_match:
        # Fetch tiled hashes for comparison
        tiled_data = await get_tiled_hashes(sha256_match["sha256"])
        if tiled_data:
            original_tiled = tiled_data.copy()
            suspect_tiled  = suspect_fp["tiled"]
            
            # Add tile_data back for pixel-level comparison
            original_tiled["tile_data"] = tile_data_store.get(sha256_match["sha256"], {})
            suspect_tiled["tile_data"] = suspect_tile_data
            
            tamper_result = detect_tampered_tiles(original_tiled, suspect_tiled)
    
    # If no exact SHA256 match but we have pHash matches, perform tamper detection on first pHash match
    if not tamper_result and phash_matches:
        best_match = phash_matches[0]
        tiled_data = await get_tiled_hashes(best_match["sha256"])
        if tiled_data:
            original_tiled = tiled_data.copy()
            suspect_tiled  = suspect_fp["tiled"]
            
            # Add tile_data back for pixel-level comparison
            original_tiled["tile_data"] = tile_data_store.get(best_match["sha256"], {})
            suspect_tiled["tile_data"] = suspect_tile_data
            
            tamper_result = detect_tampered_tiles(original_tiled, suspect_tiled)
    
    # If no exact matches but we have similar hashes, perform tamper detection on best similar match
    if not tamper_result and similar_hashes:
        best_match = similar_hashes[0]
        tiled_data = await get_tiled_hashes(best_match["sha256"])
        if tiled_data:
            original_tiled = tiled_data.copy()
            suspect_tiled  = suspect_fp["tiled"]
            
            # Add tile_data back for pixel-level comparison
            original_tiled["tile_data"] = tile_data_store.get(best_match["sha256"], {})
            suspect_tiled["tile_data"] = suspect_tile_data
            
            tamper_result = detect_tampered_tiles(original_tiled, suspect_tiled)
    
    # Verify merkle roots on blockchain
    blockchain_records = []
    
    if sha256_match and sha256_match.get("merkle_root"):
        on_chain_result = verify_on_chain(sha256_match["merkle_root"])
        sha256_match["blockchain_verified"] = on_chain_result.get("verified", False)
        sha256_match["blockchain_anchored_at"] = on_chain_result.get("anchored_at")
        sha256_match["blockchain_error"] = on_chain_result.get("error")
        
        blockchain_records.append({
            "type": "exact_match",
            "merkle_root": sha256_match["merkle_root"],
            "tx_hash": sha256_match.get("blockchain_tx_hash"),
            "block_number": sha256_match.get("blockchain_block_number"),
            "verified_on_chain": on_chain_result.get("verified", False),
            "anchored_at": on_chain_result.get("anchored_at"),
            "error": on_chain_result.get("error"),
        })
    
    if phash_matches:
        for match in phash_matches:
            if match.get("merkle_root"):
                on_chain_result = verify_on_chain(match["merkle_root"])
                match["blockchain_verified"] = on_chain_result.get("verified", False)
                match["blockchain_anchored_at"] = on_chain_result.get("anchored_at")
                
                blockchain_records.append({
                    "type": "phash_match",
                    "sha256": match["sha256"],
                    "merkle_root": match["merkle_root"],
                    "tx_hash": match.get("blockchain_tx_hash"),
                    "block_number": match.get("blockchain_block_number"),
                    "verified_on_chain": on_chain_result.get("verified", False),
                    "anchored_at": on_chain_result.get("anchored_at"),
                })
    
    # Generate annotated image if we have tamper results
    annotated_b64 = None
    if tamper_result:
        annotated_frame = visualize_tampered_tiles(suspect_frame, tamper_result)
        annotated_b64 = encode_frame(annotated_frame)
    
    return {
        "suspect_sha256": suspect_sha256,
        "suspect_phash": suspect_phash,
        "is_authentic": is_authentic,
        "exact_sha256_match": sha256_match,
        "exact_phash_matches": phash_matches or [],
        "similar_hashes": similar_hashes,
        "tamper": tamper_result,
        "annotated_image": annotated_b64,
        "blockchain_records": blockchain_records,
        "total_similar": len(similar_hashes),
        "database_count": len(all_snapshots) if all_snapshots else 0,
    }


# ─── Video Session Routes ─────────────────────────────────────────────────────

@app.post("/video/start")
def start_video_session(payload: VideoSessionPayload) -> dict:
    """Start a new chained video session."""
    active_chains[payload.session_id] = FrameChain()
    return {"session_id": payload.session_id, "started": True}


@app.post("/video/frame/{session_id}")
def add_video_frame(session_id: str, payload: FramePayload) -> dict:
    """Add a frame to an active video chain session."""
    if session_id not in active_chains:
        raise HTTPException(
            status_code=404,
            detail="Session not found — call /video/start first",
        )

    frame  = decode_frame(payload.image_b64)
    chain  = active_chains[session_id]
    record = chain.add_frame(frame)

    return {
        "sequence":    record["sequence"],
        "chain_hash":  record["chain_hash"][:16] + "...",
        "merkle_root": record["merkle_root"][:16] + "...",
    }


@app.post("/video/end/{session_id}")
def end_video_session(session_id: str) -> dict:
    """
    End a video session — verify chain integrity and anchor final Merkle root to Polygon.
    """
    if session_id not in active_chains:
        raise HTTPException(status_code=404, detail="Session not found")

    chain  = active_chains.pop(session_id)
    verify = chain.verify_chain()
    anchor = None

    if verify["valid"]:
        final_root = chain.get_final_merkle_root()
        if final_root:
            anchor = anchor_to_polygon(final_root, "video_clip")

    return {
        "session_id":  session_id,
        "frame_count": chain.sequence,
        "chain":       verify,
        "blockchain":  anchor,
    }


@app.get("/verify/chain/{merkle_root}")
def verify_on_blockchain(merkle_root: str) -> dict:
    """Check if a Merkle root exists on Polygon."""
    return verify_on_chain(merkle_root)


@app.post("/search/hashes")
async def search_video_hashes(payload: SearchPayload) -> dict:
    """
    Search for video hashes in the database.
    - If query is empty: returns all snapshots
    - If query is 64 chars (SHA256): searches for exact match
    - If query is 16 chars (pHash): searches for exact pHash match
    - If query is shorter: returns matches
    Returns paginated results with metadata.
    """
    all_snapshots = await get_all_snapshots()
    
    if not all_snapshots:
        return {
            "query": payload.query,
            "total_matches": 0,
            "results": [],
            "total_in_database": 0,
        }
    
    results = []
    
    # If query is empty, return all snapshots
    if not payload.query or payload.query.strip() == "":
        results = all_snapshots[:payload.limit]
    # If query looks like SHA256 (64 hex chars)
    elif len(payload.query) == 64 and all(c in '0123456789abcdefABCDEF' for c in payload.query):
        match = await search_by_sha256(payload.query)
        if match:
            results = [match]
    # If query looks like pHash (16 hex chars or shorter pHash)
    elif all(c in '0123456789abcdefABCDEF' for c in payload.query):
        # Try as pHash exact match
        phash_matches = await search_by_phash(payload.query)
        if phash_matches:
            results = phash_matches[:payload.limit]
        # Also search by partial SHA256 prefix
        else:
            results = [
                s for s in all_snapshots 
                if s["sha256"].lower().startswith(payload.query.lower())
            ][:payload.limit]
    else:
        # Fallback: return all snapshots if query is invalid
        results = all_snapshots[:payload.limit]
    
    # Add blockchain verification info
    for result in results:
        if result.get("merkle_root"):
            on_chain = verify_on_chain(result["merkle_root"])
            result["blockchain_verified"] = on_chain.get("verified", False)
            result["blockchain_anchored_at"] = on_chain.get("anchored_at")
    
    return {
        "query": payload.query,
        "total_matches": len(results),
        "results": results,
        "total_in_database": len(all_snapshots),
    }


@app.post("/search/video")
async def search_video_file(file: bytes = File(...), frame_interval: int = 10) -> dict:
    """
    Upload a video file and search the database + blockchain for matching frames.
    - Extracts frames at specified interval (default: every 10 frames)
    - Generates SHA256 and pHash for each frame
    - Searches database for exact/similar matches
    - Verifies matches on Polygon blockchain
    - Returns all matches with blockchain verification status
    """
    try:
        # Save video temporarily
        import tempfile
        import os
        
        temp_video = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
        temp_video.write(file)
        temp_video.close()
        
        video_path = temp_video.name
        
        # Open video and extract frames
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            os.unlink(video_path)
            raise HTTPException(status_code=400, detail="Invalid video file")
        
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        
        extracted_frames = []
        frame_index = 0
        
        # Extract frames at interval
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            if frame_index % frame_interval == 0:
                extracted_frames.append({
                    "frame_number": frame_index,
                    "timestamp": frame_index / fps if fps > 0 else 0,
                    "frame": frame,
                })
            
            frame_index += 1
        
        cap.release()
        os.unlink(video_path)
        
        if not extracted_frames:
            raise HTTPException(status_code=400, detail="No frames extracted from video")
        
        # Process each frame
        all_snapshots = await get_all_snapshots()
        frame_results = []
        
        for frame_data in extracted_frames:
            # Generate fingerprints
            fp = fingerprint_frame(frame_data["frame"])
            frame_sha256 = fp["sha256"]
            frame_phash = fp["phash"]
            
            # Search database
            exact_match = await search_by_sha256(frame_sha256)
            similar_matches = []
            
            if all_snapshots:
                for snapshot in all_snapshots:
                    if snapshot["sha256"] == frame_sha256:
                        continue
                    hd = hamming_distance(frame_phash, snapshot["phash"])
                    if hd < 8:
                        similar_matches.append({
                            "sha256": snapshot["sha256"],
                            "phash": snapshot["phash"],
                            "hamming_distance": hd,
                            "capture_type": snapshot.get("capture_type", "unknown"),
                            "captured_at": snapshot.get("captured_at"),
                        })
            
            # Verify on blockchain
            blockchain_status = None
            if exact_match and exact_match.get("merkle_root"):
                bc_result = verify_on_chain(exact_match["merkle_root"])
                blockchain_status = {
                    "merkle_root": exact_match["merkle_root"],
                    "verified": bc_result.get("verified", False),
                    "anchored_at": bc_result.get("anchored_at"),
                    "error": bc_result.get("error"),
                }
            
            frame_results.append({
                "frame_number": frame_data["frame_number"],
                "timestamp": frame_data["timestamp"],
                "sha256": frame_sha256,
                "phash": frame_phash,
                "exact_match": exact_match,
                "similar_matches": similar_matches,
                "blockchain_status": blockchain_status,
                "found_in_database": exact_match is not None or len(similar_matches) > 0,
            })
        
        # Summary statistics
        frames_with_matches = sum(1 for f in frame_results if f["found_in_database"])
        frames_on_blockchain = sum(1 for f in frame_results if f["blockchain_status"] and f["blockchain_status"]["verified"])
        
        return {
            "video_info": {
                "total_frames": frame_count,
                "extracted_frames": len(extracted_frames),
                "fps": fps,
                "frame_interval": frame_interval,
            },
            "summary": {
                "frames_with_matches": frames_with_matches,
                "frames_on_blockchain": frames_on_blockchain,
                "total_similar_matches": sum(len(f["similar_matches"]) for f in frame_results),
            },
            "frame_results": frame_results,
            "total_database_records": len(all_snapshots) if all_snapshots else 0,
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Video processing error: {str(e)}")


# ─── WebSocket — live frame stream ────────────────────────────────────────────

@app.websocket("/ws/live/{session_id}")
async def websocket_live(websocket: WebSocket, session_id: str) -> None:
    """
    WebSocket endpoint for continuous live capture fingerprinting.
    Client sends base64 frames; server responds with hash + chain status.
    """
    await websocket.accept()
    chain = FrameChain()

    try:
        while True:
            data   = await websocket.receive_text()
            frame  = decode_frame(data)
            record = chain.add_frame(frame)

            await websocket.send_json({
                "sequence":    record["sequence"],
                "sha256":      record["sha256"][:16] + "...",
                "phash":       record["phash"],
                "chain_hash":  record["chain_hash"][:16] + "...",
                "merkle_root": record["merkle_root"][:16] + "...",
            })

    except WebSocketDisconnect:
        pass
