// Import scripts for large database modularity
importScripts('database.js');

// 1. Initial Intelligence Database Flash-Sync
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["blacklist", "whitelist", "keywords", "suspiciousTlds", "dangerousExtensions", "urlShorteners"], (res) => {
    // Only pre-fill if the database is currently empty
    if (!res.blacklist || res.blacklist.length === 0) {
      chrome.storage.local.set({
        blacklist: INITIAL_DATABASE.blacklist,
        whitelist: INITIAL_DATABASE.whitelist,
        keywords: INITIAL_DATABASE.keywords,
        suspiciousTlds: INITIAL_DATABASE.suspiciousTlds,
        dangerousExtensions: INITIAL_DATABASE.dangerousExtensions,
        urlShorteners: INITIAL_DATABASE.urlShorteners,
        isScanningEnabled: true
      }, () => {
        syncDatabaseToNetworkShield();
      });
      console.log("Sentinel One Intelligence Database synchronized.");
    } else {
      syncDatabaseToNetworkShield();
    }
  });
});

// 2. High-Fidelity Network-Level Pre-Navigation Shielding
// Now redirects to blocked.html with the URL context instead of showing a generic error page
async function syncDatabaseToNetworkShield() {
  chrome.storage.local.get(["blacklist", "isScanningEnabled"], (res) => {
    if (res.isScanningEnabled === false) {
      chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] }); 
      return;
    }

    const blacklist = res.blacklist || [];
    
    // Create redirection rules (showing our custom blocked.html UI)
    const newRules = blacklist.slice(0, 50).map((domain, index) => ({
      id: index + 1,
      priority: 1,
      action: { 
        type: "redirect", 
        redirect: { extensionPath: `/blocked.html?url=${encodeURIComponent(domain)}` } 
      },
      condition: {
        urlFilter: domain,
        resourceTypes: ["main_frame"]
      }
    }));

    chrome.declarativeNetRequest.getDynamicRules(existing => {
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existing.map(r => r.id),
        addRules: newRules
      });
    });
  });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") {
     syncDatabaseToNetworkShield(); 
  }
});

// 3. Status Management
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "UPDATE_STATUS") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    if (tabId) {
      let text = "";
      let color = "";
      switch (request.status) {
        case "SAFE":
          text = "✓";
          color = "#22c55e"; 
          break;
        case "WARN":
          text = "!";
          color = "#f59e0b"; 
          break;
        case "DANGER":
          text = "X";
          color = "#ef4444"; 
          break;
        case "OFF":
          text = "";
          color = "#64748b"; 
          break;
      }
      chrome.action.setBadgeText({ text: text, tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    }
  }
});
