# Cookie Auditor

Cookie Auditor is a small Manifest V3 Chromium extension that lists safe metadata
for cookies matching the page currently open in the active tab.

Currently, this is just a basic demonstration. It does not assign risk levels, identify trackers, or make reports. Work in progress.

## Install locally in Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `The-Cookie-Auditor` folder.
5. Open a normal `http` or `https` webpage and select the Cookie Auditor icon.

The popup reports an unsupported-page message for browser pages, new tabs,
extension pages, and other non-web URLs. Reopen the popup to run a fresh scan.
