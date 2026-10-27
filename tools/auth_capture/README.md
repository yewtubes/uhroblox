# Capture authenticated original Roblox client pages

Use `capture-authenticated.js` in **your own Chrome tab**, already signed in normally at `https://www.roblox.com/home`.

1. Open the JavaScript file in a text editor and copy its contents.
2. Open Chrome DevTools. Paste and run it in Console, or create **Sources → Snippets → New snippet**, paste it there, and run with **Ctrl+Enter** (Mac: Command+Enter).
3. Leave the tab open while it runs. It fetches original signed-in Home, Settings, Avatar, Friends, your Profile, and your Inventory documents, then attempts their public bundles, CSS, fonts, and static UI images.
4. It downloads **roblox-authenticated-client-capture.json**. Review it before sharing it. The script scrubs recognized account bootstrap/security fields, but it cannot guarantee removal of every personal detail from every HTML variant.

You do not need to provide a cookie, password, authentication header, account export, or browser profile. Do not export browser credentials. The script never reads cookies or web storage. It performs read-only GET requests and creates one local download; it has no upload destination or background recorder. It does not submit forms, change the account, install anything, disable browser protections, or make a purchase.

Run only on the logged-in Roblox tab. It refuses other origins or a document without the original signed-in metadata. A redirected or signed-out response is recorded as unavailable, not as an authenticated page.

To cancel: `RobloxClientCapture.stop()`.

To capture one specific page after the first run: `RobloxClientCapture.run({pages:[location.pathname]})`. Navigate normally to the page first; full navigation requires running the snippet again. Console code does not survive a page reload. API response bodies—including messages, transactions, contacts, settings responses, and inventory records—are intentionally excluded.

## What it preserves

The capture contains the actual **HTTP HTML response** for each page, not a DOM reconstruction, screenshot, or invented page. Recognized account bootstrap values are replaced with markers such as `__LOCAL_USER_ID__` and `__LOCAL_USERNAME__`. Known hydration records and production game recommendation items are cleared. Each document carries the source hash before scrubbing and the stored hash after scrubbing; the scrubbed bytes are not claimed to be the unmodified original response.

Public JavaScript/CSS/font/image bytes are stored unchanged with SHA-256 hashes and source URLs. No authenticated JSON API response body is copied into the export. The local platform must provide its own account state and other data when binding these original page documents.

## Limits

This is a bounded document/static-resource capture, not a full network debugger. A Console snippet cannot read past network response bodies or bypass CORS. Failed or blocked cross-origin assets are listed as missing; their public URLs can later be downloaded anonymously with the project's capture tool. Resources loaded only after interacting with tabs or dialogs may require another run on that page. No capture claims that every lazy-loaded route or feature is complete.

If a needed response body cannot be recovered, Chrome's **Network → Preserve log** and **Export HAR (sanitized)** can supply original traffic across normal navigation. Chrome strips Cookie, Set-Cookie, and Authorization headers from its sanitized export, but HAR response bodies can still contain account data. Do not upload a HAR here as an alternative to this scrubbed capture; have it filtered and reviewed locally first. Never select HAR “with sensitive data” for this task.

Chrome documentation:

- https://developer.chrome.com/docs/devtools/javascript/snippets
- https://developer.chrome.com/docs/devtools/network/reference

## Local import

After reviewing the JSON, the included importer validates hashes and writes to a separate staging folder:

```sh
python3 tools/auth_capture/import-authenticated.py roblox-authenticated-client-capture.json --project-root /path/to/roblox-original-client
```

If using the standalone kit, run `python3 import-authenticated.py ... --project-root /path/to/roblox-original-client`.

The importer performs no network calls and executes no captured code. It does **not** overwrite guest captures, activate authenticated documents, or load captured account values into SQLite. Its staged manifest is marked `activation_allowed: false`; the project must bind its own identity, configuration, and backend responses before using it. That protects the existing guest Play branches and avoids presenting a captured real account as a local user.
