# The Cookie Auditor

A Chromium-based extension that inspects cookies for the current page.

- **First-party cookies** come from Chrome's Cookies API for the active page.
- **Confirmed stored third-party cookies** were observed in a third-party `Cookie` or `Set-Cookie` header and currently have a matching cookie in the browser's cookie store.
- **Unconfirmed third-party cookies** were observed in one of those headers but have no current cookie-store match. They may have been blocked, expired, deleted, or rejected.

The extension does not decide whether a cookie is used for tracking. Cookie values are not displayed or stored.

## Privacy risk estimate

The Risk Level meter scores cookie attributes from 0 to 100: green/Low (0–29), orange/Moderate (30–59), and red/High (60–100). It refreshes with cookie results and shows Unavailable if cookie inspection fails or no observed cookies have assessable attributes. Failing to retrieve the separate information-detection results does not prevent cookie scoring. Results during page loading may be incomplete.

Potentially Collected Information remains a separate, unscored section. Recognized request field names suggest possible information categories. Their contents are not verified and do not prove collection or tracking. Detected information, receiving domains, and third-party cookie counts add no risk points.

Each stored cookie receives an attribute score using the same Low/Moderate/High thresholds. Points are added for the following conditions, with each cookie's score capped at 100:

| Condition | Points |
| --- | --- |
| No Secure flag | +25 |
| No HttpOnly flag | +3 |
| SameSite=None | +3 |
| Remaining lifetime more than 365 days | +5 |
| Remaining lifetime more than 90 days, up to and including 365 days | +2 |
| Name suggests authentication/session use and Secure is absent | +35 |
| Name suggests authentication/session use and HttpOnly is absent | +27 |

Authentication/session names are identified by the case-insensitive tokens `session`, `sessionid`, `sess`, `sid`, `auth`, `jwt`, `access_token`, and `refresh_token`, bounded by the start or end of the name, a period, an underscore, or a hyphen. A name match suggests possible purpose; it does not verify what the cookie contains or how it is used.

Unspecified SameSite and domain scope including subdomains are informational and add no points. Scores estimate attribute concerns; they are not probabilities of harm or proof of tracking.

The overall score is the highest individual cookie attribute score. Scores are not averaged, so many low-risk cookies cannot dilute a concerning cookie, and duplicate cookies cannot inflate the attribute contribution. If inspection succeeds and no cookies are found, the overall score is 0 (Low). The popup explains the score and shows counts by rating. Cookies with different paths, stores, or partition keys remain distinct.

Unknown attributes receive no points. Unconfirmed observations without readable attributes show Unknown instead of Low. Partial ratings identify the attributes not assessed. Each stored cookie displays its available settings and reasons for its rating. Only metadata is retained for these findings. Cookie values are excluded.

## Install

1. Open your Chromium-based browser's extension settings.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `The-Cookie-Auditor` folder.
5. Open a normal HTTP or HTTPS page and reload it.
6. Select the extension icon to view the cookie lists.
