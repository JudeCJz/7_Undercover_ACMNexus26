document.addEventListener("DOMContentLoaded", () => {
  const elements = {
    blacklistContainer: document.getElementById("blacklist-view"),
    whitelistContainer: document.getElementById("whitelist-view"),
    scanToggle: document.getElementById("scan-toggle"),
    customUrl: document.getElementById("custom-url"),
    feedback: document.getElementById("popup-feedback"),
    siteStatus: document.getElementById("site-status"),
    totalLinks: document.getElementById("total-links"),
    unsafeLinks: document.getElementById("unsafe-links")
  };

  initializePopup();
  bindEvents();

  function initializePopup() {
    chrome.storage.local.get(
      ["blacklist", "whitelist", "isScanningEnabled"],
      (res) => {
        elements.scanToggle.checked = res.isScanningEnabled !== false;
        renderList("blacklist", res.blacklist || []);
        renderList("whitelist", res.whitelist || []);
        syncWithActiveTab();
      }
    );
  }

  function bindEvents() {
    elements.scanToggle.addEventListener("change", (event) => {
      const isEnabled = event.target.checked;
      chrome.storage.local.set({ isScanningEnabled: isEnabled }, () => {
        setFeedback(
          isEnabled ? "Scanning enabled for the active tab." : "Scanning disabled for the active tab.",
          isEnabled ? "success" : ""
        );
        syncWithActiveTab({ forceRescan: true });
      });
    });

    document.getElementById("add-blacklist").addEventListener("click", () => {
      updateDomainList("blacklist");
    });

    document.getElementById("add-whitelist").addEventListener("click", () => {
      updateDomainList("whitelist");
    });

    document.getElementById("add-current-blacklist").addEventListener("click", () => {
      withActiveHostname((hostname) => updateStorageLists("blacklist", hostname));
    });

    // Accordion Toggle Logic
    document.querySelectorAll(".accordion-header").forEach(header => {
      header.addEventListener("click", () => {
        const parent = header.parentElement;
        parent.classList.toggle("open");
      });
    });

    elements.customUrl.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        updateDomainList("blacklist");
      }
    });
  }

  function updateDomainList(targetList) {
    const hostname = normalizeHostname(elements.customUrl.value);
    if (!hostname) {
      setFeedback("Enter a valid domain such as example.com.", "error");
      return;
    }
    updateStorageLists(targetList, hostname);
  }

  function updateStorageLists(targetList, hostname) {
    const oppositeList = targetList === "blacklist" ? "whitelist" : "blacklist";
    chrome.storage.local.get([targetList, oppositeList], (res) => {
      const nextTargetList = dedupeList([...(res[targetList] || []), hostname]);
      const nextOppositeList = (res[oppositeList] || []).filter((item) => item !== hostname);

      chrome.storage.local.set(
        {
          [targetList]: nextTargetList,
          [oppositeList]: nextOppositeList
        },
        () => {
          renderList(targetList, nextTargetList);
          renderList(oppositeList, nextOppositeList);
          elements.customUrl.value = hostname;
          setFeedback(
            targetList === "blacklist"
              ? `Blocked ${hostname}.`
              : `Trusted ${hostname}.`,
            "success"
          );
          syncWithActiveTab({ forceRescan: true });
        }
      );
    });
  }

  function removeFromStorageList(listName, hostname) {
    chrome.storage.local.get([listName], (res) => {
      const nextList = (res[listName] || []).filter((item) => item !== hostname);
      chrome.storage.local.set({ [listName]: nextList }, () => {
        renderList(listName, nextList);
        setFeedback(`Removed ${hostname} from ${listName}.`, "success");
        syncWithActiveTab({ forceRescan: true });
      });
    });
  }

  function renderList(listName, list) {
    const container = listName === "blacklist" ? elements.blacklistContainer : elements.whitelistContainer;
    container.innerHTML = "";

    if (list.length === 0) {
      container.innerHTML = "<div class='list-item' style='color:#64748b'>No domains stored.</div>";
      return;
    }

    list
      .slice()
      .sort((a, b) => a.localeCompare(b))
      .forEach((item) => {
        const row = document.createElement("div");
        row.className = "list-item";
        row.innerHTML = `<span>${item}</span><span class="remove-item" data-list="${listName}" data-item="${item}" title="Remove">x</span>`;
        container.appendChild(row);
      });

    container.querySelectorAll(".remove-item").forEach((button) => {
      button.addEventListener("click", (event) => {
        removeFromStorageList(event.currentTarget.dataset.list, event.currentTarget.dataset.item);
      });
    });
  }

  function syncWithActiveTab(options = {}) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentTab = tabs[0];
      if (!currentTab?.id) {
        updateStatsUI({ status: "OFFLINE", totalLinks: 0, unsafeLinks: 0 });
        return;
      }

      if (currentTab.url) {
        const hostname = normalizeHostname(currentTab.url);
        if (hostname) {
          elements.customUrl.value = hostname;
        }
      }

      if (options.forceRescan) {
        chrome.tabs.sendMessage(currentTab.id, { type: "FORCE_RESCAN" }, () => {
          fetchTabStats(currentTab.id);
        });
        return;
      }

      fetchTabStats(currentTab.id);
    });
  }

  function fetchTabStats(tabId) {
    chrome.tabs.sendMessage(tabId, { type: "GET_STATS" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        updateStatsUI({ status: "OFFLINE", totalLinks: 0, unsafeLinks: 0 });
        return;
      }

      let status = "SECURED";
      if (response.isScanningEnabled === false) {
        status = "DISABLED";
      } else if (response.isCurrentSiteDangerous) {
        status = "THREAT DETECTED";
      } else if (response.unsafeLinks > 0) {
        status = "WARNING";
      }

      updateStatsUI({
        status,
        totalLinks: response.totalLinks || 0,
        unsafeLinks: response.unsafeLinks || 0
      });
    });
  }

  function updateStatsUI({ status, totalLinks, unsafeLinks }) {
    elements.totalLinks.textContent = String(totalLinks);
    elements.unsafeLinks.textContent = String(unsafeLinks);
    elements.siteStatus.textContent = status;

    if (status === "THREAT DETECTED") {
      elements.siteStatus.className = "stat-val dangerous-site";
    } else if (status === "WARNING") {
      elements.siteStatus.className = "stat-val warn-site";
    } else {
      elements.siteStatus.className = "stat-val safe-site";
    }
  }

  function withActiveHostname(callback) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const hostname = normalizeHostname(tabs[0]?.url || "");
      if (!hostname) {
        setFeedback("The current tab does not expose a normal web domain.", "error");
        return;
      }
      callback(hostname);
    });
  }

  function normalizeHostname(input) {
    const trimmed = (input || "").trim().toLowerCase();
    if (!trimmed) return "";

    try {
      if (trimmed.includes("://")) {
        return new URL(trimmed).hostname.toLowerCase();
      }
      return new URL(`https://${trimmed}`).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }

  function dedupeList(list) {
    return [...new Set(list.filter(Boolean))];
  }

  function setFeedback(message, type = "") {
    elements.feedback.textContent = message;
    elements.feedback.className = `feedback ${type}`.trim();
  }
});
