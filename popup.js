"use strict";

// Keep references to the page elements that the popup updates.
const elements = {
  site: document.querySelector("#current-site"),
  results: document.querySelector("#results"),
  unsupported: document.querySelector("#unsupported"),
  error: document.querySelector("#error"),
  firstPartyList: document.querySelector("#first-party-list"),
  storedThirdPartyList: document.querySelector("#stored-third-party-list"),
  unconfirmedThirdPartyList: document.querySelector("#unconfirmed-third-party-list")
};

// Convert a value into a URL only when it is a normal HTTP or HTTPS web address.
function asWebUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}

// Remove duplicate cookies, sort them, and display them in the requested list.
function renderCookies(list, cookies, emptyMessage = "No cookies found.") {
  const uniqueCookies = new Map();
  for (const cookie of cookies) {
    const name = cookie.name || "(unnamed)";
    const domain = cookie.domain || "unknown domain";
    uniqueCookies.set(`${domain}\0${name}`, { name, domain });
  }

  const sortedCookies = [...uniqueCookies.values()].sort(
    (left, right) =>
      left.domain.localeCompare(right.domain) || left.name.localeCompare(right.name)
  );

  if (!sortedCookies.length) {
    const item = document.createElement("li");
    item.className = "empty-state";
    item.textContent = emptyMessage;
    list.replaceChildren(item);
    return;
  }

  list.replaceChildren(
    ...sortedCookies.map((cookie) => {
      const item = document.createElement("li");
      item.className = "cookie-item";
      item.textContent = `${cookie.name} (${cookie.domain})`;
      return item;
    })
  );
}

// Show the message used for browser pages that extensions cannot inspect.
function showUnsupported() {
  elements.site.textContent = "Unsupported page";
  elements.unsupported.classList.remove("is-hidden");
}

// Show a general error when cookie inspection fails.
function showError() {
  elements.error.textContent = "Cookies could not be read for this page.";
  elements.error.classList.remove("is-hidden");
}

// Find the browser cookie store that belongs to the active tab.
async function getCookieStoreFilter(tabId) {
  const stores = await chrome.cookies.getAllCookieStores();
  const store = stores.find((entry) => entry.tabIds.includes(tabId));
  return store ? { storeId: store.id } : {};
}

// Get cookies that belong to the current page's URL or domain.
async function getFirstPartyCookies(tabId, pageUrl) {
  const storeFilter = await getCookieStoreFilter(tabId);
  const [urlCookies, domainCookies] = await Promise.all([
    chrome.cookies.getAll({ ...storeFilter, url: pageUrl.href }),
    chrome.cookies.getAll({ ...storeFilter, domain: pageUrl.hostname })
  ]);
  return [...urlCookies, ...domainCookies];
}

// Get the current tab's partition key when the browser supports partitioned cookies.
async function getCurrentPartitionKey(tabId) {
  if (typeof chrome.cookies.getPartitionKey !== "function") {
    return null;
  }

  try {
    const result = await chrome.cookies.getPartitionKey({ tabId, frameId: 0 });
    const topLevelSite = result?.partitionKey?.topLevelSite;
    return topLevelSite ? { topLevelSite } : null;
  } catch {
    return null;
  }
}

// Check whether a stored cookie belongs to the domain where it was observed.
function cookieMatchesDomain(cookie, observedDomain) {
  const cookieDomain = cookie.domain.toLowerCase().replace(/^\./, "");
  const requestDomain = observedDomain.toLowerCase();
  return requestDomain === cookieDomain || requestDomain.endsWith(`.${cookieDomain}`);
}

// Separate observed third-party cookies into stored cookies and cookies not found in storage.
async function splitThirdPartyCookies(tabId, observedCookies) {
  const [storeFilter, partitionKey] = await Promise.all([
    getCookieStoreFilter(tabId),
    getCurrentPartitionKey(tabId)
  ]);

  const classifications = await Promise.all(
    observedCookies.map(async (observedCookie) => {
      const filters = [{ ...storeFilter, name: observedCookie.name }];
      if (partitionKey) {
        filters.push({ ...storeFilter, name: observedCookie.name, partitionKey });
      }

      const results = await Promise.allSettled(
        filters.map((filter) => chrome.cookies.getAll(filter))
      );
      const storedCookies = results
        .flatMap((result) => (result.status === "fulfilled" ? result.value : []))
        .filter((cookie) => cookieMatchesDomain(cookie, observedCookie.domain))
        .map((cookie) => ({ name: cookie.name, domain: cookie.domain }));

      return storedCookies.length
        ? { stored: storedCookies, unconfirmed: [] }
        : { stored: [], unconfirmed: [observedCookie] };
    })
  );

  return {
    stored: classifications.flatMap((result) => result.stored),
    unconfirmed: classifications.flatMap((result) => result.unconfirmed)
  };
}

// Inspect the active tab and fill each cookie section in the popup.
async function inspectActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const pageUrl = asWebUrl(tab?.url);
  if (!pageUrl || !Number.isInteger(tab.id)) {
    showUnsupported();
    return;
  }

  elements.site.textContent = pageUrl.hostname;
  const firstPartyCookies = await getFirstPartyCookies(tab.id, pageUrl);
  renderCookies(elements.firstPartyList, firstPartyCookies);
  elements.results.classList.remove("is-hidden");

  const observedThirdPartyCookies = await chrome.runtime
    .sendMessage({
      type: "get-third-party-cookies",
      tabId: tab.id,
      tabUrl: pageUrl.href
    })
    .catch(() => []);

  const thirdPartyCookies = await splitThirdPartyCookies(
    tab.id,
    observedThirdPartyCookies
  );
  renderCookies(
    elements.storedThirdPartyList,
    thirdPartyCookies.stored,
    "No stored third-party cookies found."
  );
  renderCookies(
    elements.unconfirmedThirdPartyList,
    thirdPartyCookies.unconfirmed,
    "No unconfirmed third-party cookies found."
  );
}

// Begin the inspection when the popup opens, and show an error if it fails.
inspectActiveTab().catch(showError);