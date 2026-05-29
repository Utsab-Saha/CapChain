# CaptureChain Database Migration Summary

## Changes Made

### 1. **Storage Architecture** ✓
- **PostgreSQL**: Stores `phash` and `tiled_sha256` with metadata
- **Blockchain**: Anchors **only `sha256`** (not entire tiled data)
- **Memory**: Caches tile pixel data temporarily for verification

### 2. **Database Schema** (PostgreSQL)

#### `snapshots` table
```sql
sha256 (VARCHAR 64, UNIQUE) — primary identifier
phash (VARCHAR 16) — perceptual hash
captured_at (TIMESTAMP)
capture_type (VARCHAR 50)
merkle_root (VARCHAR 64)
blockchain_tx_hash (VARCHAR 66)
blockchain_block_number (INTEGER)
created_at (TIMESTAMP)
```

#### `tiled_hashes` table
```sql
sha256_parent (FK to snapshots)
grid_size (VARCHAR 10) — e.g., "8x8"
tile_key (VARCHAR 20) — e.g., "0_0", "1_2"
tile_hash (VARCHAR 64)
created_at (TIMESTAMP)
```

### 3. **API Changes**

#### `/snapshot` endpoint
- **Now async**
- Stores `phash` + tiled hashes in PostgreSQL via `store_snapshot()` and `store_tiled_hashes()`
- Anchors **only sha256** to blockchain (changed from merkle root)
- Returns storage status indicating where each piece is stored

**Request:**
```json
{
  "image_b64": "data:image/jpeg;base64,..."
}
```

**Response:**
```json
{
  "sha256": "abc123...",
  "phash": "1a2b3c4d5e6f7g8h",
  "tiled": {
    "grid": "8x8",
    "tiles": {
      "0_0": "hash1",
      "0_1": "hash2",
      ...
    },
    "root": "rootHash"
  },
  "blockchain": {
    "anchored": true,
    "tx_hash": "0x...",
    "block_number": 12345
  },
  "storage": {
    "postgres": "✓ phash + tiled_hashes stored",
    "blockchain": "✓ sha256 anchored",
    "memory": "✓ tile_data cached for verification"
  }
}
```

#### `/verify` endpoint
- **Now async**
- Attempts to fetch original record from memory first
- Falls back to PostgreSQL if not in memory
- Reconstructs tiled data from database for comparison
- Full tampering detection still works

#### `/verify/upload` endpoint
- **Now async**
- Same behavior as `/verify` — fetches from PostgreSQL if needed

### 4. **Dependencies Added**
```
psycopg==3.1.17  # PostgreSQL async driver
```

### 5. **Configuration**
Set environment variable:
```
DATABASE_URL=postgresql://user:password@localhost:5432/capturechain
```

### 6. **Database Initialization**
- Automatically creates tables on app startup
- Indexes created for fast queries:
  - `idx_snapshots_sha256`
  - `idx_snapshots_phash`
  - `idx_snapshots_merkle_root`
  - `idx_tiled_parent`
  - `idx_tiled_root_hash`

## Data Flow Diagram

```
1. Capture Frame
   ↓
2. Fingerprint (SHA256 + pHash + Tiled)
   ├─→ PostgreSQL: phash + tiled_sha256
   ├─→ Blockchain: sha256 only ✓
   └─→ Memory: tile pixel data (temp)
   ↓
3. Return Response
```

## Verification Flow

```
1. Submit suspect frame
   ↓
2. Check memory store → not found
   ↓
3. Query PostgreSQL for phash + tiled hashes
   ↓
4. Reconstruct tiled structure
   ↓
5. Compare with suspect frame
   ↓
6. Return tamper detection results
```

## Key Benefits
- ✓ **Scalable**: PostgreSQL replaces in-memory storage
- ✓ **Persistent**: Data survives service restarts
- ✓ **Blockchain optimized**: Only essential SHA256 anchored (smaller, faster)
- ✓ **Query-friendly**: Fast searches by phash or merkle root
- ✓ **Hybrid approach**: Combines benefits of all three storage layers

## Files Modified
1. `requirements.txt` — Added psycopg
2. `utils/database.py` — Created (new file)
3. `backend/main.py` — Updated endpoints to use PostgreSQL

## Next Steps (Optional)
- [ ] Add search endpoints (by phash, merkle_root)
- [ ] Add backup/export functionality
- [ ] Add data retention policies
- [ ] Monitor database performance
