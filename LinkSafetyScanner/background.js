// Import scripts for large database modularity
importScripts('database.js');

// Initialize local database on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["blacklist", "whitelist", "keywords"], (res) => {
    // Only pre-fill if the database is currently empty
    if (!res.blacklist || res.blacklist.length === 0) {
      chrome.storage.local.set({
        blacklist: INITIAL_DATABASE.blacklist,
        whitelist: INITIAL_DATABASE.whitelist,
        keywords: INITIAL_DATABASE.keywords,
        isScanningEnabled: true
      });
      console.log("Sentinel One Intelligence Database synchronized.");
    }
  });
});

// Manage Extension Badge UI based on current safety metrics
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "UPDATE_STATUS") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    if (tabId) {
      let text = "";
      let color = "";
      switch (request.status) {
        case "SAFE":
          text = "✓";
          color = "#22c55e"; // Success Green
          break;
        case "WARN":
          text = "!";
          color = "#f59e0b"; // Warning Orange
          break;
        case "DANGER":
          text = "X";
          color = "#ef4444"; // Danger Red
          break;
      }
      chrome.action.setBadgeText({ text: text, tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    }
  }
});
