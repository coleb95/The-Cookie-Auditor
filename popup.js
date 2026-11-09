"use strict";

// Keep references to the page elements that the popup updates.
const elements = {
  site: document.querySelector("#current-site"),
  results: document.querySelector("#results"),
  unsupported: document.querySelector("#unsupported"),
  error: document.querySelector("#error"),
  loading: document.querySelector("#loading"),
  riskMeter: document.querySelector("#risk-meter"),
  riskStatus: document.querySelector("#risk-status"),
  riskReasons: document.querySelector("#risk-reasons"),
  cookieSummary: document.querySelector("#cookie-summary"),
  firstPartyList: document.querySelector("#first-party-list"),
  storedThirdPartyList: document.querySelector("#stored-third-party-list"),
  unconfirmedThirdPartyList: document.querySelector("#unconfirmed-third-party-list"),
  // For Level and Threat Identifacation
  collectedInformationList: document.querySelector("#collected-information-list"),
  informationStatus: document.querySelector("#information-status")
};

// remember which browser tab the popup is inspecting
let inspectedTabId = null;
let detectedReceivingDomains = new Set();
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

// Only cookie attributes determine risk; request observations remain informational.
function calculateRisk(ratings = []) {
  const reasons = [];
  const assessed = ratings.filter((rating) => Number.isFinite(rating.score));
  if (ratings.length && !assessed.length) return null;
  // Use the highest cookie score so duplicates or many low-risk cookies cannot
  // inflate the result or dilute a more concerning cookie.
  const cookieScore = Math.max(0, ...assessed.map((rating) => rating.score));
  if (assessed.length) {
    reasons.push(`Highest cookie attribute score: ${cookieScore} points`);
  } else {
    reasons.push("No cookies available to rate; no attribute concerns observed.");
  }
  if (ratings.some((rating) => rating.missing.length)) {
    reasons.push("Some cookie attributes are unavailable; those attributes were not scored.");
  }
  return { score: cookieScore, reasons };
}

function renderRisk(risk, status = "Checking...") {
  elements.riskMeter.classList.toggle("is-hidden", !risk);
  elements.riskReasons.replaceChildren();
  if (!risk) {
    elements.riskStatus.textContent = status;
    elements.riskMeter.value = 0;
    return;
  }
  const level = riskLevel(risk.score);
  elements.riskMeter.value = risk.score;
  elements.riskMeter.dataset.level = level.toLowerCase();
  elements.riskStatus.textContent = `${level} - ${risk.score} points`;
  for (const reason of risk.reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    elements.riskReasons.append(item);
  }
  if (!risk.reasons.length) {
    elements.riskStatus.textContent += " · No scored signals observed";
  }
}

//Checking Whether Cookie Domain Matches Domain
//Receiving Potentially Sensitive Information
function matchesDetectedReceiver(cookieDomain)
{
  if (typeof cookieDomain !== "string")
  {
    return false;
  }
  const domain = cookieDomain.toLowerCase().replace(/^\./,"");
  return [...detectedReceivingDomains].some(receivingDomain => 
  {
     //Make Sure Receiving Domain Is Valid
    if (typeof receivingDomain !== "string")
    {
      return false;
    }
    const receiver = receivingDomain.toLocaleLowerCase().replace(/^\./,"");
    return receivingDomain == domain || receivingDomain.endsWith(`.${domain}`);
  });
}

//Update Highlighting Of Cookies Displayed In Extention
function updatecCookieHighlights()
{
  const cookieItems = document.querySelectorAll(".cookie-item[data-cookie-domain]");
  for (const item of cookieItems)
  {
    const cookieDomain = item.dataset.cookieDomain;
    if (matchesDetectedReceiver(cookieDomain))
    {
      item.classList.add("possible-data-recipient");
    }
    else
    {
      item.classList.remove("possible-data-recipient");
    }
  }
}

// Remove duplicate cookies, sort them, and display them in the requested list.
function renderCookies(list, cookies, emptyMessage = "No cookies found.") {
  const sortedCookies = [...cookies].sort(
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
      const title = document.createElement("strong");
      title.textContent = `${cookie.name || "(unnamed)"} (${cookie.domain})`;
      const rating = cookie.rating;
      const badge = document.createElement("span");
      badge.className = "cookie-rating";
      badge.dataset.level = rating.level.toLowerCase();
      badge.textContent = rating.score === null ? "Unknown risk" :
        `${rating.level} risk - ${rating.score} points${rating.missing.length ? " (partial)" : ""}`;
      const details = document.createElement("p");
      details.className = "cookie-details";
      const flag = (value) => typeof value === "boolean" ? (value ? "Yes" : "No") : "Unknown";
      const sameSite = { strict: "Strict", lax: "Lax", no_restriction: "None", unspecified: "Not explicit" };
      const expiry = cookie.session === true ? "Session" : Number.isFinite(cookie.expirationDate) &&
        !Number.isNaN(new Date(cookie.expirationDate * 1000).getTime()) ?
        new Date(cookie.expirationDate * 1000).toLocaleString() : "Unknown";
      details.textContent = `Secure: ${flag(cookie.secure)} | HttpOnly: ${flag(cookie.httpOnly)} | SameSite: ${sameSite[cookie.sameSite] || "Unknown"}. Path: ${cookie.path ?? "Unknown"}. Scope: ${cookie.hostOnly === true ? "Host only" : cookie.hostOnly === false ? "Includes subdomains" : "Unknown"}. Expiration: ${expiry}.`;
      if (cookie.partitionKey) details.textContent += ` Partition: ${cookie.partitionKey.topLevelSite || "Unknown"}.`;
      const findings = document.createElement("ul");
      findings.className = "cookie-findings";
      const explanations = [...rating.reasons];
      if (rating.score === null) explanations.push("Attributes could not be verified from browser storage; no attribute rating is assigned.");
      else if (!explanations.length) explanations.push("No concerns found in the attributes checked. This does not guarantee safety.");
      if (rating.missing.length && rating.score !== null) explanations.push(`Not assessed: ${rating.missing.join(", ")}.`);
      for (const explanation of explanations) {
        const finding = document.createElement("li");
        finding.textContent = explanation;
        findings.append(finding);
      }
      item.append(title, badge, details, findings);

      //Store What Cookie Should Be Highlighted
      item.dataset.cookieDomain = cookie.domain;

      //Check If The Cookie Should Be Highlighted *Safe Guard*
      if (matchesDetectedReceiver(cookie.domain))
      {
        item.classList.add("possible-data-recipient")
      }
      return item;
    })
  );  
}

//Display Potentially Collected Information
function renderCollectedInformation(result)
{
  const list = elements.collectedInformationList;
  const status = elements.informationStatus;

  //Retrieve Domains Receiving Recognized Information
  const domainData = result?.receivingDomains?.length ? result.receivingDomains : result?.receivingDomain || [];

  //Make Sure Domain Data Is An Array
  const highlightDomains = Array.isArray(domainData) ? domainData : [domainData];

  // Remove Nested Array And Invalid Values
  const validDomains = highlightDomains.flat(Infinity).filter(domain => typeof domain === "string").map(domain => domain.toLowerCase().replace(/^\./,""));

  //Save Receiving Domains
  detectedReceivingDomains = new Set(validDomains);

  //Update Highlighting Displayed Cookies
  updatecCookieHighlights();

  //checks if information was detected
  if (!result || !Array.isArray(result.informationTypes) || result.informationTypes.length === 0)
  {
    list.replaceChildren();
    status.textContent = "No known tracking information detected.";
    return;
  }

  // Make Internal Name Easier To Understand
  const informationCategories = 
  {
    location: "Location Information",
    ipAddress: "IP Address Information",
    personal: "Personal Information",
    browsing: "Browsing Activity",
    shopping: "Shopping Information/Activity",
    identifiers: "User, Device, and Session Identifiers",
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

  //Display All Domain Reciving Information
  const domains = result.receivingDomains?.lenth?result.receivingDomains:[result.receivingDomain || "Unknown"];
  status.textContent = `Receiving Domains: ${domains.join(", ")}`;
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
  renderRisk(null, "Unavailable on this page.");
  elements.results.classList.add("is-hidden");
  elements.loading.classList.add("is-hidden");
  elements.error.classList.add("is-hidden");
  elements.site.textContent = "Unsupported page";
  elements.unsupported.classList.remove("is-hidden");
}

// Show a general error when cookie inspection fails.
function showError() {
  renderRisk(null, "Unavailable: Inspection failed.");
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

// Get cookies for the full hostname, including parent-domain cookies at other paths.
async function getFirstPartyCookies(tabId, pageUrl) {
  const storeFilter = await getCookieStoreFilter(tabId);
  const hostname = pageUrl.hostname.toLowerCase();
  // Include every ancestor without assuming hosts have two or three labels.
  const domains = [hostname];
  if (!hostname.startsWith("[") && !/^\d+(\.\d+){3}$/.test(hostname)) {
    for (let dot = hostname.indexOf("."); dot !== -1; dot = hostname.indexOf(".", dot + 1)) {
      const parent = hostname.slice(dot + 1);
      if (parent.includes(".")) domains.push(parent);
    }
  }
  const results = await Promise.all([
    chrome.cookies.getAll({ ...storeFilter, url: pageUrl.href }),
    ...domains.map((domain) => chrome.cookies.getAll({ ...storeFilter, domain }))
  ]);
  return uniqueCookies(results.flat().filter((cookie) =>
    cookieMatchesDomain(cookie, hostname)));
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
  return requestDomain === cookieDomain ||
    (!cookie.hostOnly && requestDomain.endsWith(`.${cookieDomain}`));
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
      if (results.every((result) => result.status === "rejected")) {
        throw new Error("Third-party cookie attributes could not be read.");
      }
      const storedCookies = results
        .flatMap((result) => (result.status === "fulfilled" ? result.value : []))
        .filter((cookie) => cookieMatchesDomain(cookie, observedCookie.domain))
        .map(cookieMetadata);

      return storedCookies.length
        ? { stored: storedCookies, unconfirmed: [] }
        : { stored: [], unconfirmed: [observedCookie] };
    })
  );

  return {
    stored: uniqueCookies(classifications.flatMap((result) => result.stored)),
    unconfirmed: uniqueCookies(classifications.flatMap((result) => result.unconfirmed))
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

  let cookieObservationError = false;
  const observedThirdPartyCookies = await chrome.runtime
    .sendMessage({
      type: "get-third-party-cookies",
      tabId: tab.id,
      tabUrl: pageUrl.href
    })
    .catch(() => {
      cookieObservationError = true;
      return [];
    });

  const thirdPartyCookies = await splitThirdPartyCookies(
    tab.id,
    observedThirdPartyCookies
  );
  // A navigation or newer cookie event makes this snapshot obsolete.
  if (!isCurrentInspection(version)) {
    return;
  }

  elements.error.classList.add("is-hidden");
  const nowSeconds = Date.now() / 1000;
  const rate = (cookies) => cookies.map((cookie) => ({ ...cookie, rating: rateCookie(cookie, nowSeconds) }));
  const ratedFirstParty = rate(firstPartyCookies);
  const ratedStored = rate(thirdPartyCookies.stored);
  const ratedUnconfirmed = rate(thirdPartyCookies.unconfirmed);
  const ratings = [...ratedFirstParty, ...ratedStored, ...ratedUnconfirmed].map((cookie) => cookie.rating);
  const counts = { Low: 0, Moderate: 0, High: 0, Unknown: 0 };
  ratings.forEach((rating) => counts[rating.level]++);
  if (cookieObservationError) {
    renderRisk(null, "Unavailable: Some inspection results could not be read.");
  } else {
    renderRisk(calculateRisk(ratings), "Unavailable: No cookie attributes could be assessed.");
  }
  renderCollectedInformation(collectedInformation);
  if (informationError) {
    elements.informationStatus.textContent = "unable to retrieve information detection results.";
  }
  renderCookies(elements.firstPartyList, ratedFirstParty);
  renderCookies(
    elements.storedThirdPartyList,
    ratedStored,
    "No confirmed third-party cookies found."
  );
  renderCookies(
    elements.unconfirmedThirdPartyList,
    ratedUnconfirmed,
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
    renderRisk(null);
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
