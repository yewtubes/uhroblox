/* Transport adapter only: does not create, replace, style, or render UI. */
(() => {
  'use strict';
  const origin = location.origin;
  const isPlatformHost = h => h === 'roblox.com' || h.endsWith('.roblox.com') ||
    h === 'rbxcdn.com' || h.endsWith('.rbxcdn.com') ||
    h.endsWith('.robloxlabs.com');
  function localURL(input) {
    const u = new URL(String(input), location.href);
    if (u.origin === origin || u.protocol === 'data:' || u.protocol === 'blob:') return u.href;
    if (!isPlatformHost(u.hostname)) throw new TypeError('External service unavailable in independent mode');
    return origin + (['www.roblox.com', 'roblox.com'].includes(u.hostname) ? '' : '/__upstream/' + u.hostname) + u.pathname + u.search + u.hash;
  }
  const fetchOriginal = window.fetch.bind(window);
  window.fetch = (input, init) => {
    try {
      if (input instanceof Request) {
        return fetchOriginal(new Request(localURL(input.url), input), init);
      }
      return fetchOriginal(localURL(input), init);
    } catch (e) { return Promise.reject(e); }
  };
  const openOriginal = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    return openOriginal.call(this, method, localURL(url), ...args);
  };
  // Rebase resource assignments before the browser loads them. Keeping the
  // URLs inside the captured bundles intact preserves their URL validators.
  for (const [ctor, prop] of [
    [window.HTMLImageElement, 'src'], [window.HTMLScriptElement, 'src'],
    [window.HTMLLinkElement, 'href'], [window.HTMLMediaElement, 'src'],
    [window.HTMLSourceElement, 'src'], [window.HTMLIFrameElement, 'src'],
    [window.HTMLVideoElement, 'poster']
  ]) {
    const descriptor = ctor && Object.getOwnPropertyDescriptor(ctor.prototype, prop);
    if (!descriptor || !descriptor.set) continue;
    Object.defineProperty(ctor.prototype, prop, {...descriptor, set(value) {
      let mapped = value;
      try { mapped = localURL(value); } catch (_) { mapped = origin + '/__local/external-resource-unavailable'; }
      return descriptor.set.call(this, mapped);
    }});
  }
  const setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    if (['src','poster'].includes(String(name).toLowerCase()) ||
        (this.tagName === 'LINK' && String(name).toLowerCase() === 'href')) {
      try { value = localURL(value); } catch (_) { value = origin + '/__local/external-resource-unavailable'; }
    }
    return setAttribute.call(this, name, value);
  };
  if (navigator.sendBeacon) {
    const beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url, data) => {
      try { return beacon(localURL(url), data); } catch (_) { return false; }
    };
  }
  // Real-time and native game protocols require independent services first.
  window.WebSocket = class { constructor() { throw new Error('Independent realtime service not implemented'); } };
  document.addEventListener('click', e => {
    const a = e.target.closest && e.target.closest('a[href]');
    if (!a) return;
    const href = a.getAttribute('href');
    if (/^(roblox|roblox-player|roblox-studio):/i.test(href)) { e.preventDefault(); return; }
    try {
      const u = new URL(a.href);
      if (u.origin !== origin && /^https?:/.test(u.protocol)) {
        e.preventDefault();
        if (isPlatformHost(u.hostname)) location.assign(localURL(u.href));
      }
    } catch (_) { e.preventDefault(); }
  }, true);
})();
