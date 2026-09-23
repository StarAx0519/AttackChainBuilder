# Attack Chain Builder

Offline prototype for mapping heterogeneous security alerts to **MITRE ATT&CK** techniques/tactics and reconstructing **tactic-guided attack chains**—without external enrichment APIs or cloud LLMs.

**System Overview**

Tailored for air-gapped and connectivity-limited environments, our method adheres to three fundamental constraints ensuring auditability and evidence faithfulness:

C1: Static Knowledge Grounding. Alignment relies exclusively on a fixed offline ATT\&CK snapshot, precluding online retrieval or dynamic fine-tuning to ensure deterministic reproducibility.

C2: Traceable Provenance. Every non-null output encodes its derivation path within the cascade (identifiers, rules, heuristics, or fallbacks), thereby prohibiting opaque end-to-end mappings.

C3: Evidence-Faithful Reconstruction.We refrain from imputing unobserved tactics, ensuring reconstructed chains represent a verifiable lower bound on adversary activity.

These constraints mandate achieving accuracy through hierarchical fusion rather than external augmentation, distinguishing our approach from both SIEM correlation and LLM-based labeling.

![System](D:\AttackChainBuilder\System1.png)

![System](D:\AttackChainBuilder\System2.png)

**This repository is intended for local demonstration and paper review. On Windows, reviewers can start the UI with a double-click.**

---

## Features

- **Alert → ATT&CK alignment** via a multi-granularity evidence cascade (explicit IDs, alert-type rules, lexicon/name matching, conservative fallback), with an auditable layer tag and confidence
- **Attack-chain construction** via temporal–entity coupling inside an association window
- **Browser UI**: batch mapping, tactic coverage matrix, chain visualization
- **Optional MongoDB**: persist mapped alerts and chains when you click “store”; without MongoDB the demo runs in memory mode

---

## Requirements

| Software | Required? | Notes |
|----------|-----------|--------|
| **Node.js 16+** | **Yes** | Runs the Express API and serves the frontend |
| **MongoDB 5+** | Optional | Needed only for persistence / cumulative stats; demo works without it |
| **npm** | Yes (with Node) | Installs backend packages |
| Nginx | No (local) | Only for production reverse-proxy deployments |

Check versions:

```bash
node -v
npm -v
```

Install Node from [https://nodejs.org](https://nodejs.org) (LTS) if needed. Restart the terminal after install.

---

## npm packages (backend)

Declared in `backend/package.json`:

| Package | Role |
|---------|------|
| `express` | HTTP API and static file hosting |
| `mongoose` | MongoDB access (optional at runtime) |
| `cors` | Cross-origin support |
| `multer` | File upload for alert batches |
| `xlsx` | Excel sample import |
| `uuid` | Identifiers |

Install (automatic if you use `start-local.bat`):

```bash
cd backend
npm install
```

---

## Quick start (Windows — recommended for reviewers)

1. Clone or unpack this repository.
2. Ensure `data/ATTCK.json` exists (ATT&CK knowledge used offline at inference).
3. Double-click **`start-local.bat`** in the repository root.
4. Wait until the console shows the server is listening.
5. Open a browser at **http://127.0.0.1:3000/**

The script will:

- `cd` into `backend/`
- run `npm install` if `node_modules` is missing
- free port `3000` if an old Node process is still bound
- start `node app.js` with `ATTCK_PATH` pointing at `data/ATTCK.json`

Stop the server with **Ctrl+C** in that console window.

**Suggested demo path in the UI**

1. Load sample alerts (built-in samples or sample list, if seeded).
2. Run mapping / one-click pipeline.
3. Inspect the tactic coverage matrix and reconstructed chains.
4. (Optional) Click store only if MongoDB is running and connected.

---

## Quick start (command line)

### Windows (PowerShell)

```powershell
.\start-local.bat
```

Or:

```powershell
cd backend
npm install
$env:ATTCK_PATH="..\data\ATTCK.json"
$env:PORT="3000"
npm start
```

### Linux / macOS

```bash
cd backend
npm install
export ATTCK_PATH="$(pwd)/../data/ATTCK.json"
export PORT=3000
npm start
```

Then open **http://127.0.0.1:3000/**

---

## MongoDB (optional)

Default URI:

```text
mongodb://127.0.0.1:27017/qy_attack_chain
```

Override with `MONGO_URI` if needed.

- **Without MongoDB**: the API starts in **memory mode**. Mapping and chain building still work; “store” / cumulative history will not persist across restarts.
- **With MongoDB**: start the database service, then optionally initialize indexes and demo samples:

```bash
cd backend
export ATTCK_PATH=/absolute/path/to/data/ATTCK.json
export MONGO_URI=mongodb://127.0.0.1:27017/qy_attack_chain
npm run init-db
```

Health check (includes Mongo status):

```bash
curl -s http://127.0.0.1:3000/api/health
```

Expect `"ok": true`. `"mongo": true` only when the database is connected.

---

## Repository layout

```text
.
├── start-local.bat          # Windows one-click start
├── start-local.ps1          # PowerShell alternative (if present)
├── frontend/                # Static UI (index.html, css/, js/)
├── backend/                 # Express API (app.js, src/, scripts/)
│   ├── package.json
│   └── deploy.sh / stop.sh  # Linux server helpers
├── data/
│   ├── ATTCK.json           # Required offline ATT&CK corpus
│   ├── sample_alerts.json   # Built-in demo alerts
│   └── ca_serialized_pc1.xlsx   # Optional batch samples
├── deploy/nginx.conf        # Optional production reverse proxy
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP listen port (falls back to the next free port if busy) |
| `ATTCK_PATH` | auto-detected under `data/` | Absolute path to `ATTCK.json` |
| `MONGO_URI` | `mongodb://127.0.0.1:27017/qy_attack_chain` | MongoDB connection string |
| `CA_SAMPLES_XLSX` | `../data/ca_serialized_pc1.xlsx` | Optional Excel samples path |

---

## Main API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Liveness; reports Mongo connectivity |
| GET | `/api/attck/tactics` | Tactic/technique dictionary |
| POST | `/api/mapping/batch` | Batch alignment (compute only) |
| POST | `/api/chains/build` | Build chains (compute only) |
| POST | `/api/pipeline` | Map + build in one call |
| POST | `/api/persist` | Write alerts/chains/stats to Mongo |
| GET | `/api/samples` | List sample alerts |

Mapping and chain construction **do not write** to Mongo until `/api/persist` (or the UI store button) is used.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ATTCK.json` not found | Wrong working directory / path | Set `ATTCK_PATH` to the absolute path of `data/ATTCK.json` |
| `npm install` fails | No Node/npm or network blocked | Install Node LTS; retry in `backend/` |
| Page loads, API fails | Backend not running | Keep the `start-local.bat` window open; check `/api/health` |
| Store fails | MongoDB not running | Start `mongod`, or ignore store and use memory mode |
| Port in use | Old Node process | The bat script tries to free `:3000`; or change `PORT` |
