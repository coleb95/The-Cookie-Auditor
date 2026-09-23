"use strict";

// Set which web requests to watch and prepare a separate update queue for each tab.
const REQUEST_FILTER = { urls: ["http://*/*", "https://*/*"] };
const STORAGE_PREFIX = "cookie-list-";
const operationQueues = new Map();

// Convert a value into a URL only when it is a normal HTTP or HTTPS web address.
function asWebUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}

// Reduce a host name to the site domain used to compare first- and third-party requests.
function siteDomain(hostname) {
  const labels = hostname.toLowerCase().replace(/^\.|\.$/g, "").split(".");
  return labels.length > 2 ? labels.slice(-2).join(".") : labels.join(".");
}

// Build the session-storage key used for one browser tab.
function storageKey(tabId) {
  return `${STORAGE_PREFIX}${tabId}`;
}

// Run storage updates for the same tab in order so they do not overwrite each other.
function queue(tabId, operation) {
  const previous = operationQueues.get(tabId) || Promise.resolve();
  const next = previous.catch(() => undefined).then(operation);
  const settled = next.catch(() => undefined);
  operationQueues.set(tabId, settled);
  void settled.finally(() => {
    if (operationQueues.get(tabId) === settled) {
      operationQueues.delete(tabId);
    }
  });
  return next;
}

// Start a fresh cookie list whenever a tab begins loading a new web page.
async function resetTab(tabId, pageUrl) {
  const url = asWebUrl(pageUrl);
  if (!url) {
    return;
  }

  await chrome.storage.session.set({
    [storageKey(tabId)]: {
      topLevelDomain: siteDomain(url.hostname),
      cookies: []
    }
  });
}

// Read all values for a named header from a request or response.
function headerValues(headers, name) {
  return (headers || [])
    .filter((header) => header.name?.toLowerCase() === name)
    .map((header) => header.value)
    .filter((value) => typeof value === "string");
}

// Extract cookie names from the Cookie header sent with a request.
function requestCookieNames(headers) {
  return headerValues(headers, "cookie").flatMap((value) =>
    value
      .split(";")
      .map((part) => part.slice(0, part.indexOf("=")).trim())
      .filter(Boolean)
  );
}

// Extract cookie names from Set-Cookie headers returned in a response.
function responseCookieNames(headers) {
  return headerValues(headers, "set-cookie")
    .map((value) => /^\s*([^=;\s]+)\s*=/.exec(value)?.[1])
    .filter(Boolean);
}

// Save cookies seen on another domain, while avoiding duplicate name-and-domain pairs.
async function recordThirdPartyCookies(details, names) {
  const requestUrl = asWebUrl(details.url);
  if (!requestUrl || !names.length) {
    return;
  }

  const key = storageKey(details.tabId);
  const stored = await chrome.storage.session.get(key);
  const state = stored[key];
  if (!state || siteDomain(requestUrl.hostname) === state.topLevelDomain) {
    return;
  }

  const cookies = new Map(
    (state.cookies || []).map((cookie) => [`${cookie.domain}\0${cookie.name}`, cookie])
  );
  for (const name of names) {
    cookies.set(`${requestUrl.hostname}\0${name}`, {
      name,
      domain: requestUrl.hostname
    });
  }

  state.cookies = [...cookies.values()];
  await chrome.storage.session.set({ [key]: state });
}

// Reset tracking when the main page in a tab starts loading.
chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (details.tabId >= 0 && details.type === "main_frame") {
    void queue(details.tabId, () => resetTab(details.tabId, details.url));
  }
}, REQUEST_FILTER);

// Inspect cookies that the browser sends with outgoing requests.
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (details.tabId >= 0) {
      const names = requestCookieNames(details.requestHeaders);
      void queue(details.tabId, () => recordThirdPartyCookies(details, names));
    }
  },
  REQUEST_FILTER,
  ["requestHeaders", "extraHeaders"]
);

// Inspect cookies that servers ask the browser to store in incoming responses.
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId >= 0) {
      const names = responseCookieNames(details.responseHeaders);
      void queue(details.tabId, () => recordThirdPartyCookies(details, names));
    }
  },
  REQUEST_FILTER,
  ["responseHeaders", "extraHeaders"]
);

// Remove saved tracking data after its tab is closed.
chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove(storageKey(tabId));
});

// Return the active tab's recorded third-party cookies when the popup asks for them.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "get-third-party-cookies") {
    return;
  }

  const tabId = Number(message.tabId);
  const pageUrl = asWebUrl(message.tabUrl);
  if (!Number.isInteger(tabId) || !pageUrl) {
    sendResponse([]);
    return;
  }

  void queue(tabId, async () => {
    const stored = await chrome.storage.session.get(storageKey(tabId));
    const state = stored[storageKey(tabId)];
    return state?.topLevelDomain === siteDomain(pageUrl.hostname)
      ? state.cookies || []
      : [];
  })
    .then(sendResponse)
    .catch(() => sendResponse([]));
  return true;
});