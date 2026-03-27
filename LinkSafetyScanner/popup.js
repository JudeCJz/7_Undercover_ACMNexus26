document.addEventListener("DOMContentLoaded", () => {
  const blacklistContainer = document.getElementById("blacklist-view");
  const scanToggle = document.getElementById("scan-toggle");
  
  // 1. Initial Data Fetch
  chrome.storage.local.get(["blacklist", "whitelist", "keywords", "isScanningEnabled"], (res) => {
    scanToggle.checked = res.isScanningEnabled !== false;
    renderBlacklist(res.blacklist || []);
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      let currentTab = tabs[0];
      if (currentTab && currentTab.url) {
        try {
          const url = new URL(currentTab.url);
          document.getElementById("custom-url").value = url.hostname;
          fetchTabStats(currentTab.id);
        } catch(e) {}
      }
    });
  });

  // 2. Fetch Stats from Content Script
  function fetchTabStats(tabId) {
    chrome.tabs.sendMessage(tabId, { type: "GET_STATS" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        document.getElementById("site-status").textContent = "OFFLINE";
        document.getElementById("site-status").className = "stat-val safe-site";
        return;
      }
      
      document.getElementById("total-links").textContent = response.totalLinks;
      document.getElementById("unsafe-links").textContent = response.unsafeLinks;
      
      if (response.isCurrentSiteDangerous) {
        document.getElementById("site-status").textContent = "THREAT DETECTED";
        document.getElementById("site-status").className = "stat-val dangerous-site";
      } else {
        document.getElementById("site-status").textContent = "SECURED";
        document.getElementById("site-status").className = "stat-val safe-site";
      }
    });
  }

  // 3. UI Event Listeners
  scanToggle.addEventListener("change", (e) => {
    chrome.storage.local.set({ isScanningEnabled: e.target.checked }, () => {
        // Stats in popup need a moment to re-sync after content script finishes its scan result update
        setTimeout(() => {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if(tabs[0]) fetchTabStats(tabs[0].id);
          });
        }, 300);
    });
  });

  document.getElementById("add-blacklist").addEventListener("click", () => {
    const val = document.getElementById("custom-url").value.trim().toLowerCase();
    if (val) addToStorageList("blacklist", val);
  });

  document.getElementById("add-whitelist").addEventListener("click", () => {
    const val = document.getElementById("custom-url").value.trim().toLowerCase();
    if (val) addToStorageList("whitelist", val);
  });

  document.getElementById("add-current-blacklist").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      let currentTab = tabs[0];
      if (currentTab && currentTab.url) {
        try {
          const hostname = new URL(currentTab.url).hostname.toLowerCase();
          addToStorageList("blacklist", hostname);
        } catch(e) {}
      }
    });
  });

  // 4. Database Rendering and Management
  function renderBlacklist(list) {
    blacklistContainer.innerHTML = "";
    if (list.length === 0) {
      blacklistContainer.innerHTML = "<div class='list-item' style='color:#64748b'>No restrictions set.</div>";
      return;
    }
    list.forEach(item => {
      const div = document.createElement("div");
      div.className = "list-item";
      div.innerHTML = `<span>${item}</span><span class="remove-item" data-item="${item}">×</span>`;
      blacklistContainer.appendChild(div);
    });

    const removers = document.querySelectorAll(".remove-item");
    removers.forEach(btn => {
      btn.onclick = (e) => {
        removeFromStorageList("blacklist", e.target.dataset.item);
      };
    });
  }

  function addToStorageList(listName, item) {
    chrome.storage.local.get([listName], (res) => {
      let list = res[listName] || [];
      if (!list.includes(item)) {
        list.push(item);
        let setObj = {};
        setObj[listName] = list;
        chrome.storage.local.set(setObj, () => {
          if (listName === "blacklist") renderBlacklist(list);
        });
      }
    });
  }

  function removeFromStorageList(listName, item) {
    chrome.storage.local.get([listName], (res) => {
      let list = res[listName] || [];
      const newList = list.filter(i => i !== item);
      let setObj = {};
      setObj[listName] = newList;
      chrome.storage.local.set(setObj, () => {
        if (listName === "blacklist") renderBlacklist(newList);
      });
    });
  }
});
