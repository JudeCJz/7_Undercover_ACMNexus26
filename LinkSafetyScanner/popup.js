document.addEventListener("DOMContentLoaded", () => {
  // Query active tab to pull stats and URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    let currentTab = tabs[0];
    if (currentTab) {
      if(currentTab.url) {
        try {
          const url = new URL(currentTab.url);
          document.getElementById("custom-url").value = url.hostname;
        } catch(e) {}
      }

      chrome.tabs.sendMessage(currentTab.id, { type: "GET_STATS" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          document.getElementById("site-status").textContent = "Not scannable";
        } else {
          document.getElementById("total-links").textContent = response.totalLinks;
          document.getElementById("unsafe-links").textContent = response.unsafeLinks;
          
          if (response.unsafeLinks > 0) {
            document.getElementById("unsafe-links").className = "danger-text";
          }
          
          if (response.isCurrentSiteDangerous) {
            document.getElementById("site-status").textContent = "DANGEROUS";
            document.getElementById("site-status").className = "danger-text";
            document.getElementById("header").style.color = "#F44336";
          } else {
            document.getElementById("site-status").textContent = "SAFE";
            document.getElementById("site-status").className = "safe-text";
          }
        }
      });
    }
  });

  // Action buttons
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

  function addToStorageList(listName, item) {
    chrome.storage.local.get([listName], (res) => {
      let list = res[listName] || [];
      if (!list.includes(item)) {
        list.push(item);
        let setObj = {};
        setObj[listName] = list;
        chrome.storage.local.set(setObj, () => {
          alert(`Added ${item} to ${listName}. Refresh the browser page to take effect.`);
        });
      } else {
        alert(`${item} is already in ${listName}.`);
      }
    });
  }
});
