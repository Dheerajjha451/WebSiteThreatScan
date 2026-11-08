# WebsiteThreatScan

WebsiteThreatScan helps website owners find public security misconfigurations and understand how to repair them. Findings start collapsed: select an issue's **ⓘ Why & how to fix** control to see the severity reasoning, observation, numbered repair steps, verification instructions and an OWASP reference.

Two complementary review modes are available:

- **Public website scan:** anonymous, bounded GET requests inspect HTTPS, security headers, cookies, forms, mixed content, database error disclosures, directory listings and exposed credential patterns, including privileged Supabase-style keys.
- **Local source review:** an optional command identifies patterns related to signup roles, email verification, reset enumeration, browser/PDF rendering, JavaScript cookie storage, mail endpoints, container users and environment documentation. Import its JSON report into the web interface without uploading source code. Dependency advisory lookup is available through `--npm-audit`.

These checks report observations and review candidates. They do not establish exploitability or guarantee security. Scan only sites you own or have permission to review.

## Requirements

- Python **3.12+**
- Node.js **22.13+** (Node.js 24 used for development and CI)
- npm

## Run locally

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/python backend/app.py
```

The backend listens on `http://127.0.0.1:5000` with debug mode disabled. In another terminal:

```sh
cd frontend
npm ci
cp .env.local.example .env.local
npm run dev
```

Open `http://localhost:3000`. Enter a complete HTTP/HTTPS URL, confirm permission, optionally choose the page/depth limits, and start the scan. Select a severity card or search to narrow the findings. Expand an issue for instructions, or download the full JSON report.

The frontend uses its own `/api/scan` endpoint, which calls the backend server. No `NEXT_PUBLIC_BASE_URL` is needed. `SCANNER_API_URL` defaults to `http://127.0.0.1:5000`. The backend does **not** load `.env` files automatically; export variables in its shell or set them in your process manager.

## Local source review

```sh
.venv/bin/python backend/source_audit.py /path/to/your/project --output report.json
```

Open **Review source code or open a saved report → Open JSON report** in the UI. The report is read locally by the browser. It is not sent to the backend and is not saved to browser storage.

To query current npm dependency advisories as well:

```sh
.venv/bin/python backend/source_audit.py /path/to/your/project --npm-audit --output report.json
```

This option calls `npm audit --json --ignore-scripts --package-lock-only` for existing npm lockfiles. It contacts configured registries, runs no application scripts, and does not install dependencies or apply fixes. It does not cover other package managers or dependency ecosystems. Pattern matching is heuristic: middleware, helper functions, comments, unused code and infrastructure may cause missed findings or false positives. Source reports always require manual review.

## Tests and audits

```sh
.venv/bin/pip install -r backend/requirements-dev.txt
.venv/bin/python -m pytest backend/tests -q
.venv/bin/pip-audit -r backend/requirements.txt
```

```sh
cd frontend
npm run lint
npm run typecheck
npm test
npm run build
npm audit
```

One backend integration test starts a local HTTP fixture. Tests never scan third-party websites. GitHub Actions runs tests, lint, type checks, builds and dependency audits; Dependabot checks for updates.

## Deployment

For the backend, use a production WSGI server behind your private application network or reverse proxy:

```sh
cd backend
../.venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 1 --threads 4 --timeout 65 app:app
```

Build the frontend using `npm run build` and start it using `npm start`. Set `SCANNER_API_URL` to the backend's internal address. To require authentication between the two services, set the same strong `SCANNER_API_KEY` on **both servers**. Never expose that key as a `NEXT_PUBLIC_` variable. The API key protects the backend connection; it does not authenticate users of the frontend. Add user authentication and shared gateway quotas before offering a private or large-scale scanning service.

Behind a reverse proxy, set SCANNER_APP_ORIGIN on the Next.js server to the exact public origin (for example https://scanner.example.com). Terminate HTTPS at your edge, configure deployment-appropriate HSTS, block outbound private/metadata networks, and add shared rate limits. Process-local limits are conservative and are not a distributed quota system. See the [security model](docs/SECURITY.md) for proxy, CSP, privacy and operating constraints.

## Documentation

- [Changes and migration notes](docs/CHANGES.md)
- [API contract and limits](docs/API.md)
- [What each mode can detect, with verification guidance](docs/CAPABILITIES.md)
- [Security model and deployment guidance](docs/SECURITY.md)
