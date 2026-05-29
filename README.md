 
### Backend

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # fill in your values
uvicorn main:app --reload --port 8000
```

### Frontend

Open `frontend/index.html` directly in your browser — no build step needed.  
It talks to `http://localhost:8000` by default. Change the `API` constant at the top of the `<script>` block if your backend runs elsewhere.

 
## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET  | `/health`                    | Health check |
| POST | `/snapshot`                  | Fingerprint a single frame |
| POST | `/verify`                    | Compare suspect frame vs stored original |
| POST | `/verify/upload`             | Upload JPG file for verification vs stored original |
| POST | `/verify/check-database`     | **NEW** Check if SHA256/pHash exists in database; find similar images |
| POST | `/video/start`               | Start a chained video session |
| POST | `/video/frame/{id}`          | Add a frame to a session |
| POST | `/video/end/{id}`            | End session, verify chain, anchor to Polygon |
| GET  | `/verify/chain/{merkle_root}`| Check if a root exists on Polygon |
| WS   | `/ws/live/{session_id}`      | WebSocket live stream fingerprinting |

## Layers 

| Threat | SHA256 | pHash | Tiled | Chain |
 

 