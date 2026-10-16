# DOOMX Owner Dashboard — complete project

## Files
- `index.html`, `styles.css`, `app.js`: browser dashboard
- `worker.js`: complete Cloudflare Worker including owner sessions, key creation, list, activate/deactivate, delete, bulk deactivate/delete, and customer `/activate` + `/validate`
- `worker-additions.js`: reference-only older patch file; the complete `worker.js` is the main Worker source.

## Before deploying
1. Back up the current Worker source.
2. Confirm D1 binding name is `DB`, bound to your existing `doomx-keys` database.
3. Confirm Worker secret `DOOMX_OWNER_SECRET` is set in Cloudflare Secrets.
4. Confirm D1 tables exist:
   - `access_keys(key_hash TEXT PRIMARY KEY, active INTEGER NOT NULL, expires_at INTEGER NOT NULL, device_id TEXT, created_at INTEGER NOT NULL)`
   - `owner_sessions(token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`
   Do not drop existing tables or data. The owner_sessions table was already created in the prior steps.
5. Replace the Worker source with `worker.js` and deploy. This preserves the customer route logic and uses your existing table schema.
6. Test `GET /health`, owner login, key creation, list, individual deactivate/delete, bulk deactivate and bulk delete. Bulk delete is permanent.

## Deploy dashboard to Cloudflare Pages
1. Upload `index.html`, `styles.css`, `app.js`, and `README.md` to a GitHub repository root.
2. Cloudflare Dashboard → Workers & Pages → Create → Pages → Connect to Git.
3. Framework preset: None. Build command: empty. Output directory `/` (or `.` if the UI requires it).
4. Deploy and open the generated `pages.dev` URL.
5. Restrict `Access-Control-Allow-Origin` in `worker.js` to your exact Pages origin and redeploy the Worker. Replace `*` with your exact origin, e.g. `https://your-project.pages.dev`. Do not guess it.

## Security and limitations
- Never place `DOOMX_OWNER_SECRET` in HTML, JavaScript, GitHub, or the Android APK.
- Browser holds the session token in memory only; refresh requires login again. Sessions expire after one hour.
- CORS is not authentication; each owner route checks the server-side session.
- Raw customer key is shown only once; keep it private.
- Bulk delete permanently removes all keys. Use it carefully.
- Device details currently show the UUID sent by the Android app. Model/name/OS are not available until the Android app sends them.
- “Lifetime” is implemented as approximately 100 years.
