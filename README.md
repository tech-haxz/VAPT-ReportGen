# VAPT-ReportGen

Local-first VAPT finding and editable Word report workspace. It stores assessment data in SQLite, keeps original screenshots as separate files with SHA-256 identifiers, and generates versioned `.docx` reports from the data currently saved. AI is optional and only called when a user explicitly requests analysis on a saved finding.

## Requirements

- Python 3.10+ (3.13 supported)
- Node.js 20+ and npm

## Run on Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

In a second terminal from the project root:

```powershell
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. On first launch, create the local workspace account with a password of at least 12 characters; only one account is allowed so multiple users cannot share this local workspace accidentally. Later launches require login. SQLite, evidence, and reports are written under `data/` by default. Set `VAPT_DATA_DIR` to change that location. Keep the service bound to localhost and protect the host and data directory.

## Authentication

The first signup creates the one local account. Passwords are stored using salted PBKDF2-HMAC-SHA256 hashes; browser sessions use random opaque tokens stored as hashes in SQLite and sent in an HttpOnly, SameSite=Strict cookie that expires after 8 hours. All application APIs except health and authentication endpoints require a valid session. For an HTTPS deployment, set `VAPT_COOKIE_SECURE=true`; keep the app bound to loopback for local use.

## AI provider (optional)

Copy `.env.example` to `.env` and set `LLM_API_KEY`, `LLM_MODEL`, and optionally `LLM_API_URL` for an OpenAI-compatible Chat Completions endpoint. The backend does not automatically load `.env`; export variables in the shell before starting Uvicorn, or use a local environment loader of your choice. PowerShell example:

```powershell
$env:LLM_API_KEY = 'your-key'
$env:LLM_MODEL = 'gpt-4o-mini'
python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Secrets stay in the backend environment. Without a key, manual entry and export continue to work. AI analysis sends the saved finding text to the configured endpoint only after clicking **Generate draft**; screenshots are not transmitted. Review and edit every AI field before report export. Never place production credentials in source control.

## Demo data

With the backend environment active, run `python backend/seed_demo.py`. It creates a clearly fictional Lab assessment and placeholder observation. It does not make network requests or include fabricated screenshots.

## Tests and build

```powershell
pytest backend\tests
npm run build
```

## Workflow

1. Create an assessment and document authorized scope.
2. Add findings with exact affected locations, observed behavior, evidence, remediation, and optional screenshots.
3. Save before invoking AI; generation is an editable draft and does not overwrite persisted fields until you apply and save it.
4. Mark findings reviewed or explicitly choose to include drafts on the review screen.
5. Export the Word report. It contains only Table 1 (vulnerable location, vulnerability name, and references), the “Other Information” tools list, and Part 2 with location, proof/verification steps, screenshots, and workaround/solutions. Each export is stored as a separate version and can be downloaded again.

Uploads accept PNG/JPEG/WebP, validate image content, and cap each file at 12 MB. Original evidence is retained unchanged. The report embeds uploaded images and captions. Evidence IDs include a SHA-256 hash, which is an integrity identifier and not proof of authenticity. Deleting an assessment or finding removes its evidence files. Back up the complete `data/` directory while the application is stopped.

## Current scope and limitations

- Local single-account app; multi-user access and per-user workspaces are intentionally not supported. Keep it on loopback and protect the host and data directory.
- CSV/JSON bulk import, user-managed section order/branding, redaction/annotation, reorderable image captions, and advanced duplicate detection are not implemented yet.
- Report contents are generated from saved assessment and finding fields. The Word table and detailed finding sections remain editable.
- AI uses a configurable OpenAI-compatible Chat Completions interface and expects JSON output. Provider compatibility varies. AI is not required and no AI score is treated as verified.
- References are user/AI supplied text; the app does not claim that URLs were externally verified.
