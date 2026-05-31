# type: ignore

import os
import json
import hashlib
from contextlib import asynccontextmanager

# Try to import psycopg — if not available, use in-memory fallback
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/capturechain"
)

DB_AVAILABLE = False
try:
    import psycopg
    DB_AVAILABLE = True
except ImportError:
    print("⚠ PostgreSQL (psycopg) not available — using in-memory fallback for phash and tiled hashes")


# ─── In-Memory Fallback Store ─────────────────────────────────────────────────
_db_store: dict = {
    "snapshots": {},      # sha256 → snapshot record
    "tiled_hashes": {},   # sha256 → tiled data
}


async def get_connection():
    """Get async connection to PostgreSQL (if available)."""
    if not DB_AVAILABLE:
        return None
    try:
        conn = await psycopg.AsyncConnection.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"⚠ Failed to connect to PostgreSQL: {e} — falling back to in-memory")
        return None


async def init_db():
    """Initialize database schema (if PostgreSQL available)."""
    if not DB_AVAILABLE:
        print("✓ In-memory storage ready (PostgreSQL not available)")
        return
    
    conn = await get_connection()
    if not conn:
        print("✓ In-memory storage ready (PostgreSQL connection failed)")
        return
    
    try:
        async with conn.cursor() as cur:
            # Create snapshots table
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id SERIAL PRIMARY KEY,
                    sha256 VARCHAR(64) UNIQUE NOT NULL,
                    phash VARCHAR(16) NOT NULL,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    capture_type VARCHAR(50),
                    merkle_root VARCHAR(64),
                    blockchain_tx_hash VARCHAR(66),
                    blockchain_block_number INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_snapshots_sha256 ON snapshots(sha256);
                CREATE INDEX IF NOT EXISTS idx_snapshots_phash ON snapshots(phash);
                CREATE INDEX IF NOT EXISTS idx_snapshots_merkle_root ON snapshots(merkle_root);
            """)
            
            # Create tiled_hashes table
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS tiled_hashes (
                    id SERIAL PRIMARY KEY,
                    sha256_parent VARCHAR(64) NOT NULL REFERENCES snapshots(sha256) ON DELETE CASCADE,
                    grid_size VARCHAR(10) NOT NULL,
                    tile_key VARCHAR(20) NOT NULL,
                    tile_hash VARCHAR(64) NOT NULL,
                    tile_phash VARCHAR(16),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(sha256_parent, tile_key)
                );
                
                CREATE INDEX IF NOT EXISTS idx_tiled_parent ON tiled_hashes(sha256_parent);
                CREATE INDEX IF NOT EXISTS idx_tiled_root_hash ON tiled_hashes(tile_hash);
            """)

            # Migration: add tile_phash column if it doesn't exist yet
            await cur.execute("""
                ALTER TABLE tiled_hashes
                ADD COLUMN IF NOT EXISTS tile_phash VARCHAR(16);
            """)

            await conn.commit()
            print("✓ PostgreSQL database schema initialized")
    except Exception as e:
        print(f"✓ PostgreSQL not fully available — using in-memory: {e}")
    finally:
        if conn:
            await conn.close()


async def store_snapshot(
    sha256: str,
    phash: str,
    captured_at: float,
    capture_type: str,
    merkle_root: str,
    blockchain_result: dict,
) -> bool:
    """Store snapshot metadata. Uses PostgreSQL if available, else in-memory."""
    
    # Store in in-memory first (always works)
    _db_store["snapshots"][sha256] = {
        "sha256": sha256,
        "phash": phash,
        "captured_at": captured_at,
        "capture_type": capture_type,
        "merkle_root": merkle_root,
        "blockchain_tx_hash": blockchain_result.get("tx_hash"),
        "blockchain_block_number": blockchain_result.get("block_number"),
    }
    
    # Also try PostgreSQL if available
    if not DB_AVAILABLE:
        return True
    
    conn = await get_connection()
    if not conn:
        return True  # In-memory store succeeded
    
    try:
        tx_hash = blockchain_result.get("tx_hash", None)
        block_num = blockchain_result.get("block_number", None)
        
        async with conn.cursor() as cur:
            await cur.execute("""
                INSERT INTO snapshots 
                (sha256, phash, captured_at, capture_type, merkle_root, blockchain_tx_hash, blockchain_block_number)
                VALUES (%s, %s, to_timestamp(%s), %s, %s, %s, %s)
                ON CONFLICT (sha256) DO NOTHING;
            """, (sha256, phash, captured_at, capture_type, merkle_root, tx_hash, block_num))
            
            await conn.commit()
    except Exception as e:
        print(f"PostgreSQL store_snapshot failed: {e}")
    finally:
        if conn:
            await conn.close()
    
    return True


async def store_tiled_hashes(
    sha256: str,
    grid_size: str,
    tiles: dict,
    tile_phashes: dict | None = None,
) -> bool:
    """Store tiled SHA256 hashes. Uses PostgreSQL if available, else in-memory."""
    
    # Store in in-memory first (always works)
    _db_store["tiled_hashes"][sha256] = {
        "grid_size":    grid_size,
        "tiles":        tiles,
        "tile_phashes": tile_phashes or {},
    }
    
    # Also try PostgreSQL if available
    if not DB_AVAILABLE:
        return True
    
    conn = await get_connection()
    if not conn:
        return True  # In-memory store succeeded
    
    try:
        async with conn.cursor() as cur:
            for tile_key, tile_hash in tiles.items():
                tp = (tile_phashes or {}).get(tile_key)
                await cur.execute("""
                    INSERT INTO tiled_hashes
                    (sha256_parent, grid_size, tile_key, tile_hash, tile_phash)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (sha256_parent, tile_key) DO UPDATE
                    SET tile_hash = EXCLUDED.tile_hash,
                        tile_phash = EXCLUDED.tile_phash;
                """, (sha256, grid_size, tile_key, tile_hash, tp))
            
            await conn.commit()
    except Exception as e:
        print(f"PostgreSQL store_tiled_hashes failed: {e}")
    finally:
        if conn:
            await conn.close()
    
    return True


async def get_snapshot(sha256: str) -> dict | None:
    """Retrieve snapshot. Tries PostgreSQL first, falls back to in-memory."""
    
    # Try PostgreSQL first
    if DB_AVAILABLE:
        conn = await get_connection()
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute("""
                        SELECT sha256, phash, captured_at, capture_type, merkle_root, 
                               blockchain_tx_hash, blockchain_block_number, created_at
                        FROM snapshots WHERE sha256 = %s;
                    """, (sha256,))
                    
                    row = await cur.fetchone()
                    if row:
                        return {
                            "sha256": row[0],
                            "phash": row[1],
                            "captured_at": row[2].timestamp() if row[2] else None,
                            "capture_type": row[3],
                            "merkle_root": row[4],
                            "blockchain_tx_hash": row[5],
                            "blockchain_block_number": row[6],
                            "created_at": row[7],
                        }
            except Exception as e:
                print(f"PostgreSQL get_snapshot failed: {e}")
            finally:
                if conn:
                    await conn.close()
    
    # Fall back to in-memory
    record = _db_store["snapshots"].get(sha256)
    if record:
        return record
    
    return None


async def get_tiled_hashes(sha256: str) -> dict | None:
    """Retrieve tiled hashes. Tries PostgreSQL first, falls back to in-memory."""
    
    # Try PostgreSQL first
    if DB_AVAILABLE:
        conn = await get_connection()
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute("""
                        SELECT grid_size, tile_key, tile_hash, tile_phash
                        FROM tiled_hashes WHERE sha256_parent = %s
                        ORDER BY tile_key;
                    """, (sha256,))
                    
                    rows = await cur.fetchall()
                    if rows:
                        grid_size = rows[0][0]
                        tiles        = {row[1]: row[2] for row in rows}
                        tile_phashes = {row[1]: row[3] for row in rows if row[3]}
                        
                        # Calculate root hash from ordered tiles
                        tile_list = [tiles[f"{r}_{c}"] 
                                    for r, c in sorted([(int(k.split('_')[0]), int(k.split('_')[1])) 
                                                       for k in tiles.keys()])]
                        root_hash = _calculate_root_from_tiles(tile_list)
                        
                        return {
                            "grid":         grid_size,
                            "tiles":        tiles,
                            "tile_phashes": tile_phashes,
                            "root":         root_hash,
                        }
            except Exception as e:
                print(f"PostgreSQL get_tiled_hashes failed: {e}")
            finally:
                if conn:
                    await conn.close()
    
    # Fall back to in-memory
    stored = _db_store["tiled_hashes"].get(sha256)
    if stored:
        grid_size = stored["grid_size"]
        tiles = stored["tiles"]
        
        # Calculate root hash from ordered tiles
        tile_list = [tiles[f"{r}_{c}"] 
                    for r, c in sorted([(int(k.split('_')[0]), int(k.split('_')[1])) 
                                       for k in tiles.keys()])]
        root_hash = _calculate_root_from_tiles(tile_list)
        
        return {
            "grid":         grid_size,
            "tiles":        tiles,
            "tile_phashes": stored.get("tile_phashes", {}),
            "root":         root_hash,
        }
    
    return None


def _calculate_root_from_tiles(tile_list: list[str]) -> str:
    """Recalculate root hash from ordered tile hashes."""
    return hashlib.sha256("".join(tile_list).encode()).hexdigest()


async def search_by_phash(phash: str) -> list[dict] | None:
    """Search for snapshots with similar phash (exact match)."""
    
    # Try PostgreSQL first
    if DB_AVAILABLE:
        conn = await get_connection()
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute("""
                        SELECT sha256, phash, captured_at, capture_type, merkle_root
                        FROM snapshots WHERE phash = %s
                        ORDER BY captured_at DESC;
                    """, (phash,))
                    
                    rows = await cur.fetchall()
                    if rows:
                        return [
                            {
                                "sha256": row[0],
                                "phash": row[1],
                                "captured_at": row[2].timestamp() if row[2] else None,
                                "capture_type": row[3],
                                "merkle_root": row[4],
                            }
                            for row in rows
                        ]
            except Exception as e:
                print(f"PostgreSQL search_by_phash failed: {e}")
            finally:
                if conn:
                    await conn.close()
    
    # Fall back to in-memory
    matches = [
        record for record in _db_store["snapshots"].values()
        if record["phash"] == phash
    ]
    
    if matches:
        return sorted(matches, key=lambda x: x["captured_at"], reverse=True)
    
    return None


async def search_by_sha256(sha256: str) -> dict | None:
    """Search for exact SHA256 match in database."""
    
    # Try PostgreSQL first
    if DB_AVAILABLE:
        conn = await get_connection()
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute("""
                        SELECT sha256, phash, captured_at, capture_type, merkle_root,
                               blockchain_tx_hash, blockchain_block_number, created_at
                        FROM snapshots WHERE sha256 = %s;
                    """, (sha256,))
                    
                    row = await cur.fetchone()
                    if row:
                        return {
                            "sha256": row[0],
                            "phash": row[1],
                            "captured_at": row[2].timestamp() if row[2] else None,
                            "capture_type": row[3],
                            "merkle_root": row[4],
                            "blockchain_tx_hash": row[5],
                            "blockchain_block_number": row[6],
                            "created_at": row[7].timestamp() if row[7] else None,
                        }
            except Exception as e:
                print(f"PostgreSQL search_by_sha256 failed: {e}")
            finally:
                if conn:
                    await conn.close()
    
    # Fall back to in-memory
    return _db_store["snapshots"].get(sha256)


async def get_all_snapshots() -> list[dict]:
    """Get all snapshots from database for comparison."""
    
    # Try PostgreSQL first
    if DB_AVAILABLE:
        conn = await get_connection()
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute("""
                        SELECT sha256, phash, captured_at, capture_type, merkle_root,
                               blockchain_tx_hash, blockchain_block_number, created_at
                        FROM snapshots ORDER BY created_at DESC;
                    """)
                    
                    rows = await cur.fetchall()
                    if rows:
                        return [
                            {
                                "sha256": row[0],
                                "phash": row[1],
                                "captured_at": row[2].timestamp() if row[2] else None,
                                "capture_type": row[3],
                                "merkle_root": row[4],
                                "blockchain_tx_hash": row[5],
                                "blockchain_block_number": row[6],
                                "created_at": row[7].timestamp() if row[7] else None,
                            }
                            for row in rows
                        ]
            except Exception as e:
                print(f"PostgreSQL get_all_snapshots failed: {e}")
            finally:
                if conn:
                    await conn.close()
    
    # Fall back to in-memory
    snapshots = list(_db_store["snapshots"].values())
    return sorted(snapshots, key=lambda x: x.get("created_at", 0), reverse=True)