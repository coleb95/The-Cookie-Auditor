"use strict";

// Keep references to the page elements that the popup updates.
const elements = {
  site: document.querySelector("#current-site"),
  results: document.querySelector("#results"),
  unsupported: document.querySelector("#unsupported"),
  error: document.querySelector("#error"),
  loading: document.querySelector("#loading"),
  firstPartyList: document.querySelector("#first-party-list"),
  storedThirdPartyList: document.querySelector("#stored-third-party-list"),
  unconfirmedThirdPartyList: document.querySelector("#unconfirmed-third-party-list"),
  // For Level and Threat Identifacation
  collectedInformationList: document.querySelector("#collected-information-list"),
  informationStatus: document.querySelector("#information-status")
};

// remember which browser tab the popup is inspecting
let inspectedTabId = null;
const REFRESH_DELAY_MS = 150;
let refreshTimer = null;
let refreshInProgress = false;
let refreshPending = false;
let inspectionVersion = 0;
let popupClosed = false;
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

//Display Potentially Collected Information
function renderCollectedInformation(result)
{
  const list = elements.collectedInformationList;
  const status = elements.informationStatus;

  //checks if information was detected
  if (!result || !Array.isArray(result.informationTypes) || result.informationTypes.length === 0)
  {
    const item = document.createElement("li");
    item.className = "empty-slate";
    item.textContent = "No matching information detected";
    list.replaceChildren(item);
    status.textContent = "No recognized information fields observed";
    return;
  }

  // Make Internal Name Easier To Understand
  const informationCategories = 
  {
    location: "Location Information",
    ipAddress: "IP Address Information",
    personal: "Personal Information",
    browsing: "Browsing Activity",
    shopping: "Shopping Information",
  };

  // List For Each Catigory Above
  const items = result.informationTypes.map((category)=> 
  {
    const item = document.createElement("li");
    item.className = "cookie-item";
    item.textContent = informationCategories[category] || category;
    return item;
  });

  // Display Categories That Were Detected
  list.replaceChildren(...items);

  //Display Domain Reciving Information
  status.textContent = `Latest matching request sent to: ${result.receivingDomain || "Unknown"}`;
}

//Retrieve Detected Information Stored
async function getCollectedInformation(tabId)
{
  const storageKey = `detection_${tabId}`;

  //Retrieve Most Recent Detection
  const data = await chrome.storage.session.get(storageKey);

  return data[storageKey];
}

// Show the message used for browser pages that extensions cannot inspect.
function showUnsupported() {
  elements.results.classList.add("is-hidden");
  elements.loading.classList.add("is-hidden");
  elements.error.classList.add("is-hidden");
  elements.site.textContent = "Unsupported page";
  elements.unsupported.classList.remove("is-hidden");
}

// Show a general error when cookie inspection fails.
function showError() {
  elements.error.textContent = "Cookies could not be read for this page.";
  elements.error.classList.remove("is-hidden");
}

function showLoading(isLoading) {
  elements.loading.classList.toggle("is-hidden", !isLoading);
}

function isCurrentInspection(version) {
  return !popupClosed && version === inspectionVersion;
}

// Batch bursts of events and run only one inspection at a time.
function scheduleRefresh() {
  if (popupClosed || inspectedTabId === null) {
    return;
  }

  inspectionVersion += 1;
  refreshPending = true;
  if (refreshTimer !== null || refreshInProgress) {
    return;
  }

  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    void refreshCookies();
  }, REFRESH_DELAY_MS);
}

async function refreshCookies() {
  if (popupClosed || refreshInProgress) {
    return;
  }

  refreshInProgress = true;
  refreshPending = false;
  const version = inspectionVersion;
  try {
    await inspectTab(version);
  } catch (error) {
    if (isCurrentInspection(version)) {
      console.error("Cookie inspection error:", error);
      showError();
    }
  } finally {
    refreshInProgress = false;
    if (refreshPending && !popupClosed) {
      scheduleRefresh();
    }
  }
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

// Inspect the same tab throughout the popup's lifetime.
async function inspectTab(version) {
  const tab = await chrome.tabs.get(inspectedTabId);
  if (!isCurrentInspection(version)) {
    return;
  }
  const pageUrl = asWebUrl(tab?.url);
  if (!pageUrl) {
    showUnsupported();
    return;
  }

  elements.site.textContent = pageUrl.hostname;
  elements.unsupported.classList.add("is-hidden");
  showLoading(tab.status === "loading");

  //Retrieve Potentially Collected Information
  let collectedInformation;
  let informationError = false;
  try
  {
    collectedInformation = await getCollectedInformation(tab.id);

  }
  catch (error)
  {
    console.error("Information Detection Error:", error);
    informationError = true;
  }

  const firstPartyCookies = await getFirstPartyCookies(tab.id, pageUrl);

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
  // A navigation or newer cookie event makes this snapshot obsolete.
  if (!isCurrentInspection(version)) {
    return;
  }

  elements.error.classList.add("is-hidden");
  renderCollectedInformation(collectedInformation);
  if (informationError) {
    elements.informationStatus.textContent = "unable to retrieve information detection results.";
  }
  renderCookies(elements.firstPartyList, firstPartyCookies);
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
  elements.results.classList.remove("is-hidden");
}

// Refresh on load completion, redirects, and navigation in the inspected tab.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tabId !== inspectedTabId || (!changeInfo.status && !changeInfo.url)) {
    return;
  }

  showLoading(tab.status === "loading");
  if (changeInfo.status === "loading" || changeInfo.url) {
    elements.results.classList.add("is-hidden");
    elements.error.classList.add("is-hidden");
  }
  scheduleRefresh();
});

// Cookie changes also catch cookies created after load or after user interaction.
chrome.cookies.onChanged.addListener(scheduleRefresh);

// Background observations include third-party cookies that were never stored.
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "session" || inspectedTabId === null) {
    return;
  }

  if (changes[`cookie-list-${inspectedTabId}`] || changes[`detection_${inspectedTabId}`]) {
    scheduleRefresh();
  }
});

window.addEventListener("unload", () => {
  popupClosed = true;
  inspectionVersion += 1;
  clearTimeout(refreshTimer);
});

// Register listeners before reading the tab so changes during startup are covered.
async function initializePopup() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (popupClosed) {
    return;
  }
  if (!Number.isInteger(tab?.id)) {
    showUnsupported();
    return;
  }

  inspectedTabId = tab.id;
  await refreshCookies();
}

initializePopup().catch(showError);
