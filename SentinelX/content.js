let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;
let scannedLinks = [];
let isScanningEnabled = true;
let tooltipElement = null;
let sidebarListenersAttached = false;
let scanTimeout = null;

const extractDomain = (urlStr) => {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch (error) {
    return "";
  }
};

function checkUrlSafe(urlStr, blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands = [], linkText = "", dangerousExtensions = [], urlShorteners = []) {
  if (
    !urlStr ||
    urlStr.startsWith("javascript:") ||
    urlStr.startsWith("mailto:") ||
    urlStr.startsWith("tel:") ||
    urlStr.startsWith("#")
  ) {
    return { safe: true };
  }

  const domain = extractDomain(urlStr);
  if (!domain) return { safe: true };

  // 1. Smart Protocol Security Check
  if (urlStr.startsWith("http://")) {
    const isLocal = domain === "localhost" || 
                    domain === "127.0.0.1" || 
                    domain.startsWith("192.168.") || 
                    domain.startsWith("10.");
    
    if (!isLocal) {
      return {
        safe: false,
        reason: "Insecure Protocol (HTTP)",
        details: "This site uses an unencrypted connection. Your data can be intercepted by hackers on your network."
      };
    }
  }

  // 2. Homograph / IDN Shield
  if (domain.startsWith("xn--")) {
    return {
      safe: false,
      reason: "Character Spoofing (IDN)",
      details: "This domain uses special characters to mimic a legitimate site (Homograph attack)."
    };
  }

  // 3. Whitelist Authority Check
  const isOnWhitelist = whitelist.some((item) => domain === item || domain.endsWith(`.${item}`));
  if (isOnWhitelist) {
    return { safe: true };
  }

  // 4. Subdomain Squatting / Typosquatting
  // Detects: google.com.secure-login.net / apple-support.verify-device.live
  const isSquatting = sensitiveBrands.some(brand => {
    const parts = domain.split('.');
    // If brand is in the subdomain but the last two parts are NOT the brand
    const isBrandInDomain = domain.includes(brand);
    const isBrandPrimary = parts.slice(-2).some(p => p.includes(brand));
    return isBrandInDomain && !isBrandPrimary;
  });

  if (isSquatting) {
    return {
      safe: false,
      reason: "Typosquatting Detected",
      details: "This domain contains a trusted brand name in its prefix but is hosted on an unrelated server. This is a targeted phishing technique."
    };
  }

  // 5. Mismatched Brand / Spoofing Detection
  const normalizedText = linkText.toLowerCase().trim();
  const mismatchedBrand = sensitiveBrands.find(brand => 
    normalizedText.includes(brand) && !domain.includes(brand)
  );

  if (mismatchedBrand) {
    return {
      safe: false,
      reason: "Visual Brand Mismatch",
      details: `The link text mentions "${mismatchedBrand.toUpperCase()}" but points to a completely different domain (${domain}).`
    };
  }

  // 6. Dangerous File Download Protection
  const fileExt = urlStr.split('?')[0].split('.').pop().toLowerCase();
  if (dangerousExtensions.includes(`.${fileExt}`)) {
    return {
      safe: false,
      reason: "Malicious File Type",
      details: `This link triggers a download for a high-risk file type (.${fileExt}) which could contain malware or viruses.`
    };
  }

  // 7. URL Shortener Masking
  if (urlShorteners.includes(domain)) {
    return {
      safe: false,
      reason: "Shortened URL (Masked)",
      details: "This link uses a URL shortener to hide its true destination. Proceed with extreme caution as masked links are common in spear-phishing."
    };
  }

  // 8. Plain-Text Token/Exfiltration Audit
  const sensitiveParams = ["token=", "sid=", "session=", "pass=", "pwd=", "key="];
  if (sensitiveParams.some(p => urlStr.toLowerCase().includes(p))) {
    return {
      safe: false,
      reason: "Data Leakage Threat",
      details: "The link contains sensitive session tokens or password fragments in the URL itself, making it a prime target for credential harvesting."
    };
  }

  // 9. Implicit Redirect Analysis
  const redirectParams = ["url=", "redirect=", "next=", "destination=", "target="];
  if (redirectParams.some(param => urlStr.toLowerCase().includes(param) && urlStr.includes("http"))) {
    return {
      safe: false,
      reason: "Hidden Redirect",
      details: "This URL bounces you to a secondary destination, a common tactic for bypassing security filters."
    };
  }

  // 10. Blacklist Intelligence Check
  if (blacklist.some((item) => domain === item || domain.endsWith(`.${item}`))) {
    return {
      safe: false,
      reason: "Confirmed Blacklist Match",
      details: `Intelligence data confirms this domain ("${domain}") is associated with cyber threats.`
    };
  }

  // 11. Entropy / Nonsense Domain Detection
  const mainPart = domain.split('.')[0];
  const consonants = (mainPart.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
  const numbers = (mainPart.match(/[0-9]/g) || []).length;
  if (mainPart.length > 10 && (consonants / mainPart.length > 0.8 || (consonants + numbers) / mainPart.length > 0.9)) {
    return {
      safe: false,
      reason: "Automated Domain (DGA)",
      details: "The hostname appears randomly generated, typical of disposable hacking infrastructure."
    };
  }

  // 12. Heuristic Pattern Intelligence
  const matchedKeywords = keywords.filter((kw) => {
    const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`(?:[^a-zA-Z0-9]|^)${escaped}(?:[^a-zA-Z0-9]|$)`, "i");
    return regex.test(urlStr);
  });

  if (matchedKeywords.length > 0) {
    return {
      safe: false,
      reason: "Heuristic Pattern Alert",
      details: `Detected high-risk keywords [${matchedKeywords.join(", ")}] on an unverified domain.`
    };
  }

  // 13. Infrastructure Risk Analysis
  if (suspiciousTlds.some((tld) => domain.endsWith(tld))) {
    return {
      safe: false,
      reason: "Untrusted Infrastructure",
      details: `This site uses a TLD frequently associated with cybercrime.`
    };
  }

  return { safe: true };
}

function createSidebarElements() {
  if (document.getElementById("lss-sidebar-container")) return;

  const container = document.createElement("div");
  container.id = "lss-sidebar-container";
  container.innerHTML = `
    <div class="lss-trigger" id="lss-sidebar-trigger">SENTINEL</div>
    <div class="lss-sidebar" id="lss-sidebar-main">
      <div class="lss-sidebar-header">
        <h2>Sentinel Intelligence</h2>
        <button class="lss-close-btn" id="lss-sidebar-close" type="button" aria-label="Close panel">x</button>
      </div>
      <div class="lss-sidebar-content">
        <div class="lss-sidebar-section-title">Security State</div>
        <div id="lss-sidebar-status">Initializing...</div>

        <div class="lss-sidebar-section-title">Link Trace Audit</div>
        <div id="lss-link-audit-list">Scanning in progress...</div>
      </div>
    </div>
  `;

  document.body.appendChild(container);

  const trigger = document.getElementById("lss-sidebar-trigger");
  const sidebar = document.getElementById("lss-sidebar-main");
  const closeButton = document.getElementById("lss-sidebar-close");

  if (trigger && sidebar && closeButton) {
    trigger.addEventListener("click", () => sidebar.classList.toggle("open"));
    closeButton.addEventListener("click", () => sidebar.classList.remove("open"));
  }
}

function updateSidebarUI() {
  const statusDiv = document.getElementById("lss-sidebar-status");
  const listDiv = document.getElementById("lss-link-audit-list");
  if (!statusDiv || !listDiv) return;

  statusDiv.innerHTML = `
    <div style="font-weight:700; color:${isCurrentSiteDangerous ? "#ef4444" : "#22c55e"}">
      STATUS: ${isCurrentSiteDangerous ? "THREAT DETECTED" : "SECURED"}
    </div>
    <div style="font-size:11px; margin-top:5px; color:#94a3b8">
      Audited: ${scannedLinks.length} | Flags: ${unsafeLinks}
    </div>
  `;

  listDiv.innerHTML = "";
  if (scannedLinks.length === 0) {
    listDiv.textContent = "No links detected.";
    return;
  }

  scannedLinks.slice(0, 150).forEach((link) => {
    const item = document.createElement("div");
    item.className = `lss-link-item ${link.safe ? "" : "unsafe"}`.trim();
    item.innerHTML = `
      <span class="lss-item-url">${link.url}</span>
      <span class="lss-item-reason">${link.safe ? "Clean match" : link.reason}</span>
    `;
    listDiv.appendChild(item);
  });
}

function removeTooltip() {
  if (tooltipElement) {
    tooltipElement.remove();
    tooltipElement = null;
  }
}

function ensureTooltipListeners() {
  if (sidebarListenersAttached) return;
  sidebarListenersAttached = true;

  document.addEventListener("mouseover", (event) => {
    const link = event.target.closest("a.lss-unsafe-link");
    if (!link) return;

    removeTooltip();
    const tooltip = document.createElement("div");
    tooltip.className = "lss-tooltip";
    tooltip.innerHTML = `
      <strong>${link.dataset.lssReason || "Unsafe link"}</strong>
      <div>${link.dataset.lssDetails || ""}</div>
      <span class="lss-url">URL: ${link.href}</span>
    `;
    document.body.appendChild(tooltip);

    const rect = link.getBoundingClientRect();
    tooltip.style.left = `${Math.max(12, rect.left + window.scrollX)}px`;
    tooltip.style.top = `${rect.bottom + window.scrollY + 10}px`;
    tooltipElement = tooltip;
  });

  document.addEventListener("mouseout", (event) => {
    if (event.target.closest("a.lss-unsafe-link")) {
      removeTooltip();
    }
  });

  window.addEventListener("scroll", removeTooltip, true);
}

function cleanupUI() {
  document.querySelectorAll(".lss-unsafe-link").forEach((link) => {
    link.classList.remove("lss-unsafe-link");
    delete link.dataset.lssReason;
    delete link.dataset.lssDetails;
  });

  document.querySelectorAll(".lss-banner, .lss-interstitial").forEach((element) => {
    element.remove();
  });

  removeTooltip();
}

function resetScanState() {
  totalLinks = 0;
  unsafeLinks = 0;
  isCurrentSiteDangerous = false;
  scannedLinks = [];
}

function showInterstitial(reason) {
  if (sessionStorage.getItem(`lss-dismissed-threat-${window.location.hostname}`)) return;

  const overlay = document.createElement("div");
  overlay.className = "lss-interstitial";
  overlay.innerHTML = `
    <h1>ACCESS DENIED</h1>
    <p>Sentinel One has identified this site as dangerous.</p>
    <p class="lss-interstitial-reason">Reason: ${reason}</p>
    <div class="btn-group">
      <button class="btn btn-danger" id="lss-go-back" type="button">Return to Safety</button>
      <button class="btn btn-outline" id="lss-proceed" type="button">Proceed Anyway</button>
    </div>
  `;

  document.body.appendChild(overlay);
  document.getElementById("lss-go-back").addEventListener("click", () => window.history.back());
  document.getElementById("lss-proceed").addEventListener("click", () => {
    sessionStorage.setItem(`lss-dismissed-threat-${window.location.hostname}`, "true");
    overlay.remove();
  });
}

function notifyStatus(status) {
  chrome.runtime.sendMessage({ type: "UPDATE_STATUS", status });
}

function runSentinelScan() {
  chrome.storage.local.get(
    ["blacklist", "whitelist", "keywords", "suspiciousTlds", "sensitiveBrands", "dangerousExtensions", "urlShorteners", "isScanningEnabled"],
    (res) => {
      isScanningEnabled = res.isScanningEnabled !== false;

      if (!isScanningEnabled) {
        cleanupUI();
        notifyStatus("OFF");
        return;
      }

      document.querySelectorAll(".lss-unsafe-link").forEach((link) => {
        link.classList.remove("lss-unsafe-link");
      });

      resetScanState();
      ensureTooltipListeners();
      createSidebarElements();

      const blacklist = res.blacklist || [];
      const whitelist = res.whitelist || [];
      const keywords = res.keywords || [];
      const suspiciousTlds = res.suspiciousTlds || [];
      const sensitiveBrands = res.sensitiveBrands || [];
      const dangerousExtensions = res.dangerousExtensions || [];
      const urlShorteners = res.urlShorteners || [];

      const siteCheck = checkUrlSafe(
        window.location.href,
        blacklist,
        whitelist,
        keywords,
        suspiciousTlds,
        sensitiveBrands,
        "", // current site has no anchor text
        dangerousExtensions,
        urlShorteners
      );

      if (!siteCheck.safe) {
        isCurrentSiteDangerous = true;
        showInterstitial(siteCheck.reason);
      }

      const links = document.querySelectorAll("a[href]");
      totalLinks = links.length;

      links.forEach((link) => {
        if (link.closest("#lss-sidebar-container")) return;

        // Passing link.innerText to detect BRAND SPOOFING
        const result = checkUrlSafe(
          link.href, 
          blacklist, 
          whitelist, 
          keywords, 
          suspiciousTlds, 
          sensitiveBrands, 
          link.innerText,
          dangerousExtensions,
          urlShorteners
        );

        scannedLinks.push({
          url: link.href,
          safe: result.safe,
          reason: result.reason || "Safe"
        });

        if (!result.safe) {
          unsafeLinks += 1;
          link.classList.add("lss-unsafe-link");
          link.dataset.lssReason = result.reason || "Unsafe link";
          link.dataset.lssDetails = result.details || "This link was flagged by the local scanner.";
        }
      });

      updateSidebarUI();
      notifyStatus(isCurrentSiteDangerous ? "DANGER" : unsafeLinks > 0 ? "WARN" : "SAFE");
    }
  );
}

function debouncedScan() {
  if (scanTimeout) clearTimeout(scanTimeout);
  scanTimeout = setTimeout(runSentinelScan, 500); 
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runSentinelScan);
} else {
  runSentinelScan();
}

const observer = new MutationObserver((mutations) => {
  if (!isScanningEnabled) return;
  let shouldScan = false;
  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 0) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1) { 
          if (node.tagName === 'A' || node.querySelector('a')) {
            shouldScan = true;
            break;
          }
        }
      }
    }
    if (shouldScan) break;
  }
  if (shouldScan) debouncedScan();
});

observer.observe(document.body, { childList: true, subtree: true });

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local") {
    runSentinelScan();
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATS") {
    sendResponse({ totalLinks, unsafeLinks, isCurrentSiteDangerous, isScanningEnabled });
  }

  if (request.type === "FORCE_RESCAN") {
    runSentinelScan();
    sendResponse({ ok: true });
  }
});
