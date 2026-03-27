// Initialize database on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["blacklist", "whitelist", "keywords"], (res) => {
    if (!res.blacklist) {
      chrome.storage.local.set({
        blacklist: ["malicious.com", "phishing-site.net", "bad-actor.org"],
        whitelist: ["google.com", "github.com"],
        keywords: ["secure", "verify", "login", "update", "account"]
      });
    }
  });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "UPDATE_STATUS") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    if (tabId) {
      // Set badge based on status
      let text = "";
      let color = "";
      switch (request.status) {
        case "SAFE":
          text = "✓";
          color = "#4CAF50"; // Green
          break;
        case "WARN":
          text = "!";
          color = "#FFEB3B"; // Yellow
          break;
        case "DANGER":
          text = "X";
          color = "#F44336"; // Red
          break;
      }
      chrome.action.setBadgeText({ text: text, tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    }
  }
});
