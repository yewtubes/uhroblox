/*
 * Original Client Preservation — authenticated document capture, v2 (complete replacement).
 * Run on https://www.roblox.com while already signed in.
 * Only GETs same-origin documents and public static resources. No uploads.
 * Never reads cookies, web storage, passwords, request headers or API bodies.
 * Exports scrubbed response HTML, NOT document.documentElement.outerHTML.
 * Redaction is best-effort: review the downloaded JSON before sharing it.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.RobloxClientCapture = api;
    api.run().catch(e => console.error('[Capture] ' + e.message));
  }
})(globalThis, function () {
  'use strict';
  const FORMAT = 'roblox-original-client-auth-capture';
  const ORIGIN = 'https://www.roblox.com';
  const SECRET_KEY = new RegExp("csrf|xsrf|password|authorization|securitytoken|sessiontoken|accesstoken|refreshtoken|authtoken|authenticationticket|privatekey|privateServerLinkCode|accessCode|email|phone|birthdate|birthday|ipaddress", "i");
  const SECRET_QUERY = new RegExp("(?:token|signature|policy|key-pair-id|auth|ticket|password|code|session|email|phone|access)", "i");
  const ALLOWED_QUERY = new Set(['v', 'version', 'locale', 'languagecode']);
  let controller = null;
  let busy = false;

  function normalizeRoute(value, ownId = '') {
    const u = new URL(value, ORIGIN);
    if (u.origin !== ORIGIN) throw new Error('Only same-origin Roblox pages are allowed');
    let path = u.pathname;
    if (ownId && new RegExp("^\\d+$", "").test(String(ownId))) path = path.replace(new RegExp('^/users/' + ownId + '(?=/|$)'), '/users/__LOCAL_USER_ID__');
    return path; // Do not export query strings or fragments from account pages.
  }

  function allowedPage(value) {
    try {
      const u = new URL(value, ORIGIN);
      return u.origin === ORIGIN && new RegExp("^(?:\\/home\\/?|\\/my\\/(?:account|avatar)\\/?|\\/users\\/friends\\/?|\\/users\\/\\d+\\/(?:profile|inventory)\\/?)$", "").test(u.pathname);
    } catch (_) { return false; }
  }

  function staticURL(value, base = ORIGIN) {
    try {
      const u = new URL(value, base);
      if (u.protocol !== 'https:' || u.username || u.password || u.hash) return null;
      for (const key of u.searchParams.keys()) if (SECRET_QUERY.test(key) || !ALLOWED_QUERY.has(key.toLowerCase())) return null;
      if (u.origin === ORIGIN && new RegExp("^\\/js\\/", "").test(u.pathname) && new RegExp("\\.js$", "i").test(u.pathname)) return u.href;
      if (!(u.hostname === 'rbxcdn.com' || u.hostname.endsWith('.rbxcdn.com'))) return null;
      // Exclude game/avatar thumbnails and account-specific signed delivery URLs.
      if (new RegExp("^(?:tr|thumbnails|sourcemaps)\\.", "i").test(u.hostname)) return null;
      if (!new RegExp("\\.(?:js|css|woff2?|ttf|otf|png|jpe?g|webp|gif|svg|ico)(?:\\/fetch)?$", "i").test(u.pathname)) return null;
      return u.href;
    } catch (_) { return null; }
  }

  function scrubJSON(value, context = '') {
    if (Array.isArray(value)) return value.map(x => scrubJSON(x, context));
    if (!value || typeof value !== 'object') return value;
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEY.test(key)) out[key] = '__REDACTED_' + key.toUpperCase().replace(new RegExp("[^A-Z0-9]", "g"), '_') + '__';
      else if (new RegExp("^(?:userId|authenticatedUserId|currentUserId)$", "i").test(key)) out[key] = '__LOCAL_USER_ID__';
      else if (new RegExp("^(?:username|displayName|userDisplayName)$", "i").test(key)) out[key] = '__LOCAL_' + (new RegExp("display", "i").test(key) ? 'DISPLAY_NAME' : 'USERNAME') + '__';
      else if (key === 'id' && new RegExp("^(?:user|currentUser|authenticatedUser)$", "i").test(context)) out[key] = '__LOCAL_USER_ID__';
      else if (key === 'name' && new RegExp("^(?:user|currentUser|authenticatedUser)$", "i").test(context)) out[key] = '__LOCAL_USERNAME__';
      else if (key === 'hydrationData' && item && typeof item === 'object') out[key] = Object.fromEntries(Object.keys(item).map(k => [k, {}]));
      else if (new RegExp("^(?:universeItems|gameItems|gameItemsCompact)$", "").test(key)) out[key] = [];
      else out[key] = scrubJSON(item, key);
    }
    return out;
  }

  function scrubHTML(raw) {
    const changes = {userMetadata: 0, secrets: 0, inputValues: 0, bootstrapJSON: 0};
    let html = raw;
    html = html.replace(new RegExp("<meta\\b[^>]*>", "gi"), tag => {
      if (new RegExp("\\bname\\s*=\\s*[\"']user-data[\"']", "i").test(tag)) {
        changes.userMetadata++;
        return tag.replace(new RegExp("(\\bdata-(userid|name|displayname|created|email|phone)\\s*=\\s*)([\"'])([\\s\\S]*?)\\3", "gi"), (all, prefix, key, q) => {
          const marker = {userid:'__LOCAL_USER_ID__',name:'__LOCAL_USERNAME__',displayname:'__LOCAL_DISPLAY_NAME__',created:'__LOCAL_CREATED__'}[key.toLowerCase()] || '__REDACTED__';
          return prefix + q + marker + q;
        });
      }
      if (new RegExp("(?:csrf|xsrf|hba|auth-token|authentication-token)", "i").test(tag)) {
        changes.secrets++;
        return tag.replace(new RegExp("(\\b(?:content|data-token|data-csrf-token|data-xsrf-token|data-public-key|data-server-nonce)\\s*=\\s*)([\"'])([\\s\\S]*?)\\2", "gi"),
          (all, prefix, q) => prefix + q + '__LOCAL_SECURITY_VALUE__' + q);
      }
      return tag;
    });
    html = html.replace(new RegExp("<input\\b[^>]*>", "gi"), tag => tag.replace(new RegExp("(\\bvalue\\s*=\\s*)([\"'])([\\s\\S]*?)\\2", "gi"), (all, prefix, q) => {
      changes.inputValues++; return prefix + q + q;
    }));
    html = html.replace(new RegExp("(<textarea\\b[^>]*>)[\\s\\S]*?(<\\/textarea>)", "gi"), '$1$2');
    html = html.replace(new RegExp("(<script\\b[^>]*\\btype\\s*=\\s*[\"']application\\/(?:ld\\+)?json[\"'][^>]*>)([\\s\\S]*?)(<\\/script>)", "gi"), (all, start, body, end) => {
      try { changes.bootstrapJSON++; return start + JSON.stringify(scrubJSON(JSON.parse(body))).replace(new RegExp("<\\/", "g"), '<\\/') + end; }
      catch (_) { return all; }
    });
    // Token values in legacy inline bootstraps; preserve their surrounding code.
    html = html.replace(new RegExp("((?:[\"']?(?:csrfToken|xsrfToken|authToken|accessToken|refreshToken|sessionToken|password|email|phoneNumber|birthdate|birthday)[\"']?)\\s*[:=]\\s*)([\"'])([^\"'<>\\r\\n]*)\\2", "gi"),
      (all, prefix, q) => { changes.secrets++; return prefix + q + '__REDACTED__' + q; });
    html = html.replace(new RegExp("((?:XsrfToken|CsrfToken)\\.setToken\\(\\s*)([\"'])([^\"'<>\\r\\n]*)\\2", "gi"),
      (all, prefix, q) => { changes.secrets++; return prefix + q + '__LOCAL_CSRF_TOKEN__' + q; });
    // Recognizable email literals anywhere in the document, including JSON strings.
    html = html.replace(new RegExp("[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}", "gi"), () => { changes.secrets++; return '__REDACTED_EMAIL__'; });
    html = html.replace(new RegExp("\\.ROBLOSECURITY\\s*=[^\\s;\"'<>]+", "gi"), () => { changes.secrets++; return '.ROBLOSECURITY=__REDACTED__'; });
    return {html, changes};
  }

  async function hash(bytes) {
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
  }
  function base64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
    return btoa(binary);
  }
  async function limitedBytes(response, limit) {
    const expected = Number(response.headers.get('Content-Length') || 0);
    if (expected > limit) throw new Error('resource-too-large');
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) { await reader.cancel(); throw new Error('resource-too-large'); }
      chunks.push(value);
    }
    const result = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
  }

  async function run(options = {}) {
    if (busy) throw new Error('Capture already running. Call RobloxClientCapture.stop() to cancel it.');
    if (location.origin !== ORIGIN) throw new Error('Run this on https://www.roblox.com after signing in normally.');
    const userMeta = document.querySelector('meta[name="user-data"]');
    if (!userMeta) throw new Error('This document does not contain the original signed-in user metadata. Open Home after signing in.');
    const ownId = userMeta.getAttribute('data-userid') || '';
    const defaults = ['/home', '/my/account', '/my/avatar', '/users/friends'];
    if (new RegExp("^\\d+$", "").test(ownId)) defaults.push('/users/' + ownId + '/profile', '/users/' + ownId + '/inventory');
    if (allowedPage(location.href)) defaults.unshift(location.pathname);
    const pages = [...new Set(options.pages || defaults)];
    if (pages.length > 12 || pages.some(p => !allowedPage(p))) throw new Error('Capture accepts up to 12 Home, Settings, Avatar, Friends, Profile, or Inventory document routes.');
    const maxFile = 12 * 1024 * 1024, maxTotal = 96 * 1024 * 1024;
    const urls = new Set(), attempted = new Set();
    const result = {format: FORMAT, version: 1, createdAt: new Date().toISOString(),
      privacy: {manualReviewRequired: true, rawAccountAPIBodiesCaptured: false, requestHeadersCaptured: false,
        cookiesRead: false, storageRead: false, uploadsPerformed: false, completeAnonymizationGuaranteed: false},
      pages: [], resources: [], assetUrls: [], issues: []};
    controller = new AbortController(); busy = true; let total = 0;
    const add = (value, base) => { const u = staticURL(value, base); if (u) urls.add(u); };
    try {
      for (const path of pages) {
        if (controller.signal.aborted) break;
        const route = normalizeRoute(path, ownId);
        console.info('[Capture] Fetching original document:', route);
        try {
          const response = await fetch(new URL(path, ORIGIN), {method:'GET', credentials:'same-origin', cache:'no-store', headers:{Accept:'text/html'}, signal:controller.signal});
          if (!response.ok || new URL(response.url).origin !== ORIGIN) throw new Error('document-not-available');
          if (!(response.headers.get('Content-Type') || '').includes('text/html')) throw new Error('not-html');
          const bytes = await limitedBytes(response, maxFile);
          const raw = new TextDecoder().decode(bytes);
          const parsed = new DOMParser().parseFromString(raw, 'text/html');
          if (!parsed.querySelector('meta[name="user-data"]')) throw new Error('response-is-not-authenticated');
          for (const e of parsed.querySelectorAll('script[src],link[href],img[src]')) add(e.getAttribute('src') || e.getAttribute('href'), response.url);
          for (const m of raw.matchAll(new RegExp("(?:https?:)?\\/\\/[A-Za-z0-9.-]+\\.rbxcdn\\.com\\/[^\\s\"'<>`\\\\(){}]+", "g"))) add(m[0], response.url);
          const scrubbed = scrubHTML(raw);
          result.pages.push({route, finalRoute:normalizeRoute(response.url, ownId), authenticated:true,
            sourceSha256:await hash(bytes), storedSha256:await hash(new TextEncoder().encode(scrubbed.html)),
            contentType:'text/html; charset=utf-8', html:scrubbed.html, redactions:scrubbed.changes});
        } catch (_) { result.issues.push({phase:'document',route,reason:controller.signal.aborted?'cancelled':'unavailable-or-redirected'}); }
      }
      if (!result.pages.length) throw new Error('No authenticated response documents were captured. Nothing was exported; open Home in your signed-in tab and try the snippet there.');
      // Names only from the current page's resource timing entries, never response bodies.
      for (const entry of performance.getEntriesByType('resource')) add(entry.name, location.href);
      let index = 0;
      async function worker() {
        while (!controller.signal.aborted && attempted.size < 650) {
          const url = Array.from(urls).find(u => !attempted.has(u));
          if (!url) return;
          attempted.add(url); index++;
          try {
            if (total >= maxTotal) throw new Error('capture-size-limit');
            const response = await fetch(url,{method:'GET',credentials:'omit',redirect:'follow',signal:controller.signal});
            if (!response.ok || !staticURL(response.url)) throw new Error('static-resource-unavailable');
            const type = response.headers.get('Content-Type') || 'application/octet-stream';
            if (new RegExp("html|json", "i").test(type)) throw new Error('unexpected-nonstatic-response');
            const bytes = await limitedBytes(response, maxFile);
            if (total + bytes.length > maxTotal) throw new Error('capture-size-limit');
            total += bytes.length;
            result.resources.push({url,contentType:type,encoding:'base64',body:base64(bytes),bytes:bytes.length,sha256:await hash(bytes)});
            if (new RegExp("css", "i").test(type)) {
              const text = new TextDecoder().decode(bytes);
              for (const m of text.matchAll(new RegExp("url\\(\\s*[\"']?([^\\s)\"']+)", "g"))) add(m[1], url);
            }
            if (index % 25 === 0) console.info('[Capture] Public resources saved:',result.resources.length);
          } catch (_) { result.issues.push({phase:'resource',url,reason:controller.signal.aborted?'cancelled':'cors-or-resource-unavailable-or-size-limit'}); }
        }
      }
      await Promise.all([worker(),worker(),worker()]);
      result.assetUrls = Array.from(urls).sort();
      const blob = new Blob([JSON.stringify(result)],{type:'application/json'});
      const downloadURL = URL.createObjectURL(blob), a = document.createElement('a');
      a.href = downloadURL; a.download = 'roblox-authenticated-client-capture.json'; a.click();
      setTimeout(()=>URL.revokeObjectURL(downloadURL),60000);
      console.info('[Capture] Downloaded. Review the JSON before sharing. Documents:',result.pages.length,'public resources:',result.resources.length,'unavailable:',result.issues.length);
      console.info('[Capture] Cross-origin response bodies blocked by CORS are listed, not claimed as captured. API response bodies are intentionally excluded.');
      return {documents:result.pages.length,resources:result.resources.length,unavailable:result.issues.length};
    } finally { busy = false; controller = null; }
  }
  function stop() { if (controller) controller.abort(); }
  return {run,stop,normalizeRoute,allowedPage,staticURL,scrubJSON,scrubHTML};
});
