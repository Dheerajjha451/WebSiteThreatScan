# WebsiteThreatScan frontend

Next.js 16, React 19 and TypeScript. Requires Node.js 22.13+; CI uses Node.js 24.

```sh
npm ci
cp .env.local.example .env.local
npm run dev
```

Run the Python backend separately as described in the [project README](../README.md). The browser uses `/api/scan`; its server-side proxy reads `SCANNER_API_URL` and optional `SCANNER_API_KEY`. Neither variable is embedded into client bundles. Restart the Next.js server after changing environment settings.

Findings are collapsed initially. Expand the ⓘ control for severity reasoning and numbered fixes. Severity cards, text search, JSON downloads and browser-local report imports are supported. Source reviews are performed through the Python CLI and require manual verification.

```sh
npm run lint
npm run typecheck
npm test
npm run build
npm start
```

The UI uses local CSS and system fonts, with no remote font download needed for builds. See [project documentation](../docs/CHANGES.md) for security changes, limitations and migration details.
