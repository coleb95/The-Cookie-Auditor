# The Cookie Auditor

A basic Chromeium-based extension that lists cookie names and domains for the current page.

- **First-party cookies** come from Chrome's Cookies API for the active page.
- **Confirmed stored third-party cookies** were observed in a third-party `Cookie` or `Set-Cookie` header and currently have a matching cookie in the browser's cookie store.
- **Unconfirmed third-party cookies** were observed in one of those headers but have no current cookie-store match. They may have been blocked, expired, deleted, or rejected.

The extension does not decide whether a cookie is used for tracking. Cookie values are not displayed or stored.

## Install

1. Open your Chromium-based browser's extension settings.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `The-Cookie-Auditor` folder.
5. Open a normal HTTP or HTTPS page and reload it.
6. Select the extension icon to view the cookie lists.

Reload the extension from your Chromium-based browser's extension settings after changing its files.

## Current Known Issues
- Clicking on the extension to perform the scan can be done before the website fully loads. Not all cookies may be initialized while the website is loading, resulting in cookies being missed in the scan.
  - Potential solution: Try to implement a system that lets the extension wait for the website to fully load before performing the scan.