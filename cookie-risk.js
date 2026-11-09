"use strict";

// Heuristic concern scores, not probabilities or proof of malicious use.
function riskLevel(score) {
  return score >= 60 ? "High" : score >= 30 ? "Moderate" : "Low";
}

// Keep only metadata; cookie values must never reach rendering or saved findings.
function cookieMetadata(cookie) {
  const { name, domain, path, storeId, partitionKey, secure, httpOnly,
    sameSite, session, expirationDate, hostOnly } = cookie;
  return { name, domain, path, storeId, partitionKey, secure, httpOnly,
    sameSite, session, expirationDate, hostOnly };
}

function uniqueCookies(cookies) {
  const entries = new Map();
  for (const cookie of cookies) {
    const key = JSON.stringify([cookie.storeId, cookie.domain, cookie.name, cookie.path,
      cookie.partitionKey?.topLevelSite, cookie.partitionKey?.hasCrossSiteAncestor]);
    entries.set(key, cookieMetadata(cookie));
  }
  return [...entries.values()];
}

function rateCookie(cookie, nowSeconds = Date.now() / 1000) {
  const reasons = [];
  let score = 0;
  const add = (points, explanation) => {
    score += points;
    reasons.push(`${explanation} (+${points})`);
  };
  if (cookie.secure === false) {
    add(25, "No Secure flag: this cookie is not restricted to HTTPS connections.");
  }
  if (cookie.httpOnly === false) {
    add(5, "No HttpOnly flag: Page scripts can access this cookie. Some features may require this access.");
  }
  if (cookie.sameSite === "no_restriction") {
    add(5, "SameSite = None: This permits cross-site use. It may be needed for embedded services.");
  } else if (cookie.sameSite === "unspecified") {
    reasons.push("SameSite is not explicit. The browser applies its default cross-site policy. Informational, so no points added.");
  }
  if (cookie.session !== true && Number.isFinite(cookie.expirationDate)) {
    const days = (cookie.expirationDate - nowSeconds) / 86400;
    if (days > 365) add(10, "Expires more than a year from now: Allows long-term persistence.");
    else if (days > 90) add(5, "Expires more than 90 days from now: Allows extended persistence.");
  }
  if (cookie.hostOnly === false) {
    reasons.push("Not hostOnly: This may support services across the site. Informational, so no points added.");
  }
  const missing = [];
  if (typeof cookie.secure !== "boolean") missing.push("Secure");
  if (typeof cookie.httpOnly !== "boolean") missing.push("HttpOnly");
  if (!["strict", "lax", "no_restriction", "unspecified"].includes(cookie.sameSite)) missing.push("SameSite");
  if (typeof cookie.hostOnly !== "boolean") missing.push("domain scope");
  if (cookie.session !== true && !Number.isFinite(cookie.expirationDate)) missing.push("expiration");
  const known = missing.length < 5;
  return { score: known ? Math.min(score, 100) : null,
    level: known ? riskLevel(score) : "Unknown", reasons, missing };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { riskLevel, cookieMetadata, uniqueCookies, rateCookie };
}
