# Aegis Browser Guard prototype

Desktop Chrome/Edge only; installation is separate from opening Aegis.
Extract this folder. Open chrome://extensions or edge://extensions, enable
Developer mode, choose Load unpacked and select the folder containing manifest.json.
The popup reports whether its static ruleset is enabled and can pause it.
Disable/remove the extension in your browser if a site breaks.

Three hand-authored domain rules block third-party requests to doubleclick.net,
googlesyndication.com and google-analytics.com. This tiny starter set is not
a maintained comprehensive filter list or malware feed. No request-content
inspection, browsing-history collection, AI calls or dashboard connection.
No blocked-request counts are collected. Rule status is not proof every ad was blocked.
No native-app filtering, Safari/iOS/Android support or Instagram sponsored-post removal.

API reference: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
