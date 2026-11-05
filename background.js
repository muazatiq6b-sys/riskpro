// background.js: the service worker.
//
// Its one job is to capture real HTTP response headers, because page JavaScript
// and content scripts cannot read the headers of the document they are in.
//
// Chrome shuts this worker down after about 30 seconds idle, which wipes every
// variable. So captures go to chrome.storage.session (in memory, survives the
// worker restarting, cleared when the browser closes), not to a global variable.

function storageKey(tabId) {
  return `headers:${tabId}`;
}

function cacheKey(tabId) {
  return `fromCache:${tabId}`;
}

function captureHeaders(details) {
  // tabId is -1 for requests that do not belong to a tab.
  if (details.tabId < 0) return;

  // Set-Cookie carries cookie values, which we have no reason to hold on to.
  // Cookie flags are read separately through chrome.cookies.
  const headers = (details.responseHeaders || [])
    .filter((header) => header.name.toLowerCase() !== "set-cookie")
    .map((header) => ({ name: header.name, value: header.value || "" }));

  chrome.storage.session.set({
    [storageKey(details.tabId)]: {
      url: details.url,
      statusCode: details.statusCode,
      headers,
    },
  });
}

// Listeners must be registered at the top level, synchronously. When Chrome
// wakes this worker for an event, it only delivers the event to listeners that
// exist by the end of the first run of this file.
chrome.webRequest.onHeadersReceived.addListener(
  captureHeaders,
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders"]
);

// Chrome's HTTP cache does not keep Strict-Transport-Security, so a page served
// from cache looks like it never sent that header. Only this later event says
// whether the response came from cache, so the popup can avoid a false finding.
chrome.webRequest.onResponseStarted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    chrome.storage.session.set({ [cacheKey(details.tabId)]: details.fromCache });
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([storageKey(tabId), cacheKey(tabId)]);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "GET_HEADERS") return false;

  const headersKey = storageKey(message.tabId);
  const fromCacheKey = cacheKey(message.tabId);
  chrome.storage.session.get([headersKey, fromCacheKey]).then((stored) => {
    const capture = stored[headersKey];
    sendResponse(capture ? { ...capture, fromCache: stored[fromCacheKey] === true } : null);
  });

  // Returning true keeps the message channel open until sendResponse runs.
  // Without it the popup receives undefined, because the storage read above
  // finishes after this function has already returned.
  return true;
});
