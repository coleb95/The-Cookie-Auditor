# The Cookie Auditor

A Chromeium-based extension that inspects cookies for the current page.

- **First-party cookies** come from Chrome's Cookies API for the active page.
- **Confirmed stored third-party cookies** were observed in a third-party `Cookie` or `Set-Cookie` header and currently have a matching cookie in the browser's cookie store.
- **Unconfirmed third-party cookies** were observed in one of those headers but have no current cookie-store match. They may have been blocked, expired, deleted, or rejected.

The extension does not decide whether a cookie is used for tracking. Cookie values are not displayed or stored.

## Privacy risk estimate

The Risk Level meter scores cookie attributes from 0 to 100: green/Low (0–29), orange/Moderate (30–59), and red/High (60–100). It refreshes with cookie results and shows Unavailable if cookie inspection fails or no observed cookies have assessable attributes. A failure to retrieve the separate information-detection results does not prevent cookie scoring. Results during page loading may be incomplete.

Potentially Collected Information remains a separate, unscored section. Recognized request field names suggest possible information categories. Their contents are not verified and do not prove collection or tracking. Detected information, receiving domains, and third-party cookie counts add no risk points.

Work in progress, subject to change: Each stored cookie also receives an attribute score using the same low/moderate/high thresholds: no Secure flag +25, no HttpOnly flag +5, SameSite=None +5, and expiration more than 365 days away +10 (or more than 90 days +5). Unspecified SameSite and domain scope including subdomains are informational and add no points. Session cookies receive no expiration penalty. These rules describe potential exposure.JavaScript access, cross-site use, and subdomain sharing may be intentional. Path is displayed for context and receives no penalty because it is not a security boundary. Remaining lifetime is measured at inspection time.

Work in progress, subject to change: The overall score is the highest individual cookie attribute score. Scores are not averaged, so many low-risk cookies cannot dilute a concerning cookie, and duplicate cookies cannot inflate the attribute contribution. The popup explains the score and shows counts by rating. Cookies with different paths, stores, or partition keys remain distinct.

Unknown attributes receive no points. Unconfirmed observations without readable attributes show Unknown instead of Low. Partial ratings identify the attributes not assessed. Each stored cookie displays its available settings and reasons for its rating. Only metadata is retained for these findings. Cookie values are excluded.

## Install

1. Open your Chromium-based browser's extension settings.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `The-Cookie-Auditor` folder.
5. Open a normal HTTP or HTTPS page and reload it.
6. Select the extension icon to view the cookie lists.
