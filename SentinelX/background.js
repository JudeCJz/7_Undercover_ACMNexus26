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
      console.log("LinPatrol One Intelligence Database synchronized.");
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
      chrome.declarativeNetRequest.getDynamicRules(rules => {
        const ruleIds = rules.map(r => r.id);
        if (ruleIds.length > 0) {
          chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ruleIds });
        }
      });
      return;
    }

    const blacklist = res.blacklist || [];
    
    // Create redirection rules (showing our custom blocked.html UI)
    const newRules = blacklist.slice(0, 50).map((domain, index) => ({
      id: 1000 + index, // Dedicated high-id range for user rules
      priority: 100,    // Extreme priority to override everything
      action: { 
        type: "redirect", 
        redirect: { extensionPath: `/blocked.html?url=${encodeURIComponent(domain)}` } 
      },
      condition: {
        urlFilter: domain, // DNR handles partial domain matches elegantly
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
      let badgeText = "✓"; // Default to tick
      let color = "#64748b"; // Default grey
      
      const scoreNum = parseFloat(request.score || "0");
      
      if (request.status === "OFF" || !request.score) {
        badgeText = "";
        color = "#64748b";
      } else if (scoreNum > 6.0 || request.status === "DANGER") {
        badgeText = "X"; // New High-Risk Icon
        color = "#ef4444"; // Red Scale
      } else if (scoreNum >= 1.0) {
        badgeText = "✓";
        color = "#f59e0b"; // Yellow Scale
      } else {
        badgeText = "✓";
        color = "#22c55e"; // Green Scale (Safe)
      }

      chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    }
  }
});

// 4. Side Panel Control: Anchoring the UI to the border
// Ensures LinPatrol opens as a professional sidebar on the right
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch((error) => console.error(error));

chrome.action.onClicked.addListener((tab) => {
  chrome.sidePanel.open({ tabId: tab.id });
});
// 5. Global Command Support: Fast Toggling
chrome.commands.onCommand.addListener((command) => {
  if (command === "toggle-scanning") {
    chrome.storage.local.get(["isScanningEnabled"], (res) => {
      const nextState = res.isScanningEnabled === false;
      chrome.storage.local.set({ isScanningEnabled: nextState }, () => {
        // Update Network-Level Rules
        syncDatabaseToNetworkShield();
        
        // Refresh the active tab to apply the state change immediately
        chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
          if (tabs[0]?.id) {
             chrome.tabs.reload(tabs[0].id);
          }
        });
        
        console.log(`LinPatrol Shield: ${nextState ? "ACTIVE" : "DISABLED"}`);
      });
    });
  }
});
