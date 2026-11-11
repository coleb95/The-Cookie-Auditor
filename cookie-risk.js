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

  // Identify possible authentication/session cookies by name.
  // Not proof of cookie purpose.
  const authLike = /(?:^|[._-])(session(?:id)?|sess|sid|auth|jwt|access_token|refresh_token)(?:$|[._-])/i
    .test(cookie.name || "");

  // Secure: restricts sending the cookie to secure connections.
  if (cookie.secure === false) {
    add(25, "No Secure flag: cookie is not restricted to HTTPS.");
  }

  // HttpOnly: small general penalty because some cookies require JS.
  if (cookie.httpOnly === false) {
    add(3, "No HttpOnly flag: page scripts can access this cookie.");
  }

  // SameSite: cross-site use can be legitimate.
  if (cookie.sameSite === "no_restriction") {
    add(3, "SameSite=None permits cross-site cookie use.");
  } else if (cookie.sameSite === "unspecified") {
    reasons.push("SameSite not explicitly set. Informational.");
  }

  // Expiration: smaller penalties for longer persistence.
  if (cookie.session !== true &&
      Number.isFinite(cookie.expirationDate)) {
    const days = (cookie.expirationDate - nowSeconds) / 86400;

    if (days > 365) {
      add(5, "Cookie persists for more than one year.");
    } else if (days > 90) {
      add(2, "Cookie persists for more than 90 days.");
    }
  }

  // Additional contextual concern for possible auth cookies.
  if (authLike && cookie.secure === false) {
    add(35, "Name suggests authentication/session use. missing Secure could expose a sensitive identifier.");
  }

  if (authLike && cookie.httpOnly === false) {
    add(27, "Name suggests authentication/session use. JavaScript accessibility may expose a sensitive identifier.");
  }

  // Domain scope remains informational.
  if (cookie.hostOnly === false) {
    reasons.push("Cookie includes subdomains. Informational.");
  }

  const missing = [];

  if (typeof cookie.secure !== "boolean")
    missing.push("Secure");

  if (typeof cookie.httpOnly !== "boolean")
    missing.push("HttpOnly");

  if (!["strict", "lax", "no_restriction", "unspecified"]
      .includes(cookie.sameSite))
    missing.push("SameSite");

  if (typeof cookie.hostOnly !== "boolean")
    missing.push("domain scope");

  if (cookie.session !== true &&
      !Number.isFinite(cookie.expirationDate))
    missing.push("expiration");

  const known = missing.length < 5;
  const finalScore = Math.min(score, 100);

  return {
    score: known ? finalScore : null,
    level: known ? riskLevel(finalScore) : "Unknown",
    reasons,
    missing
  };
}


if (typeof module !== "undefined" && module.exports) {
  module.exports = { riskLevel, cookieMetadata, uniqueCookies, rateCookie };
}
