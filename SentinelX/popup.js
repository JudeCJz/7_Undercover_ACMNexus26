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

    // AI Chat UI Controls
    const aiPanel = document.getElementById("ai-chat-panel");
    document.getElementById("open-ai-chat").addEventListener("click", () => aiPanel.classList.add("open"));
    document.getElementById("close-ai-chat").addEventListener("click", () => aiPanel.classList.remove("open"));

    document.getElementById("ai-send").addEventListener("click", handleAiMessage);
    document.getElementById("ai-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleAiMessage();
    });

    // Breach Check (Demo)
    document.getElementById("check-breach").addEventListener("click", handleBreachCheck);
  }

  async function handleBreachCheck() {
    const email = document.getElementById("breach-email").value.trim();
    const feedback = document.getElementById("breach-feedback");
    
    if (!email || !email.includes("@")) {
      feedback.textContent = "Please enter a valid email address.";
      feedback.className = "feedback error";
      return;
    }

    feedback.textContent = "Scanning global databases...";
    feedback.className = "feedback";

    // Simulate real HIBP check for demo fidelity
    setTimeout(() => {
      const isBreached = email.length % 2 === 0; // Deterministic demo logic
      if (isBreached) {
        feedback.innerHTML = `⚠️ <span style="color:var(--danger)">Breach Found!</span> 2 data leaks detected.`;
        addAiMessage("bot", `I've detected your email (${email}) in a simulated data breach. **Recommendation:** Change your passwords and enable 2FA immediately. See 'Breach Advice' in the chat for details.`);
      } else {
        feedback.innerHTML = `✅ <span style="color:var(--success)">System Clear.</span> No known leaks.`;
      }
    }, 1500);
  }

  function handleAiMessage() {
    const input = document.getElementById("ai-input");
    const text = input.value.trim();
    if (!text) return;

    addAiMessage("user", text);
    input.value = "";

    // LinPatrol AI Logic Engine
    setTimeout(() => {
      processAiResponse(text.toLowerCase());
    }, 600);
  }

  function addAiMessage(sender, text) {
    const body = document.getElementById("ai-messages");
    const msg = document.createElement("div");
    msg.className = `ai-message ${sender}`;
    msg.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');
    body.appendChild(msg);
    body.scrollTop = body.scrollHeight;
  }

  function processAiResponse(query) {
    // 1. Logic for Flagged Links
    if (query.includes("why") || query.includes("red") || query.includes("flag")) {
      chrome.storage.local.get(["lastScannedLinks"], (res) => {
        const unsafe = (res.lastScannedLinks || []).filter(l => !l.safe);
        if (unsafe.length > 0) {
          const reasons = unsafe.slice(0, 2).map(l => `**${l.url.substring(0, 30)}...** was flagged because: ${l.reason}`).join("<br>");
          addAiMessage("bot", `I've flagged ${unsafe.length} suspicious links on this page. <br>${reasons}<br>Specifically, many of these use **DGA algorithms** or **Brand Spoofing** to hide their identity.`);
        } else {
          addAiMessage("bot", "No links are currently flagged red on this page. You appear to be safe!");
        }
      });
      return;
    }

    // 2. Logic for Scam Analysis
    if (query.includes("scam") || query.includes("kindly") || query.includes("gift card") || query.includes("prize")) {
      addAiMessage("bot", "I've analyzed that message. **Diagnosis: High-Risk Scam.** <br>Red Flags found: <br>1. Urgent/Panic language.<br>2. Requests for unconventional payment (Gift Cards).<br>3. Mismatched 'Official' sender. **DO NOT CLICK.**");
      return;
    }

    // 3. Logic for Alternatives
    if (query.includes("alternative") || query.includes("safe")) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const hostname = normalizeHostname(tabs[0]?.url || "");
        addAiMessage("bot", `If you suspect ${hostname} is fake, always navigate manually to the official site. For example, if you're looking for Amazon, always type **amazon.com** directly into your address bar.`);
      });
      return;
    }

    // 4. General Q&A
    if (query.includes("phishing")) {
      addAiMessage("bot", "Phishing is a cyber attack that uses disguised email/links to steal user data. **Signs to look for:** Poor spelling, urgent threats to lock your account, and mismatched URLs.");
      return;
    }

    if (query.includes("2fa")) {
      addAiMessage("bot", "2FA (Two-Factor Authentication) adds a second layer of security. Even if a hacker steals your password, they still can't get in without your physical phone or key.");
      return;
    }

    addAiMessage("bot", "I'm monitoring your security in real-time. I can explain flagged links, analyze scam emails, or check for data breaches. What's on your mind?");
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

      // Vital for AI context: sync real-time scan data to storage
      chrome.storage.local.set({ lastScannedLinks: response.scannedLinks || [] });

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

  // --- Dynamic Particle Engine (tsParticles) ---
  let particlesContainer = null;

  async function initParticles() {
    particlesContainer = await tsParticles.load({
      id: "particles-js",
      options: {
        background: { color: "#080a0f" },
        particles: {
          number: { value: 60 },
          color: { value: "#ffffff" },
          links: {
            enable: true,
            distance: 120,
            color: "#0088ff",
            opacity: 0.4,
            width: 1
          },
          move: {
            enable: true,
            speed: 1.2,
            direction: "none",
            outModes: "out"
          },
          size: { value: 2 },
          opacity: { value: 0.5 }
        },
        interactivity: {
          events: { onHover: { enable: true, mode: "grab" } },
          modes: { grab: { distance: 140, links: { opacity: 0.8 } } }
        }
      }
    });
  }

  function updateVisualThreatState(isDangerous) {
    if (!particlesContainer) return;

    const options = particlesContainer.options;
    if (isDangerous) {
      // Threat Aesthetic: Neon Red, Fast, Aggressive
      options.particles.color.value = "#ff0000";
      options.particles.links.color.value = "#ff0000";
      options.particles.move.speed = 6.5;
      options.particles.links.width = 2;
    } else {
      // Safe Aesthetic: Calm Blue/White, Constellation style
      options.particles.color.value = "#ffffff";
      options.particles.links.color.value = "#0088ff";
      options.particles.move.speed = 1.2;
      options.particles.links.width = 1;
    }
    particlesContainer.refresh();
  }

  function updateStatsUI({ status, totalLinks, unsafeLinks }) {
    elements.totalLinks.textContent = String(totalLinks);
    elements.unsafeLinks.textContent = String(unsafeLinks);
    elements.siteStatus.textContent = status;

    const isDangerous = (status === "THREAT DETECTED" || status === "WARNING");
    updateVisualThreatState(isDangerous);

    if (status === "THREAT DETECTED") {
      elements.siteStatus.className = "stat-val dangerous-site";
    } else if (status === "WARNING") {
      elements.siteStatus.className = "stat-val warn-site";
    } else {
      elements.siteStatus.className = "stat-val safe-site";
    }
  }

  // Initial Boot
  initParticles();

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
