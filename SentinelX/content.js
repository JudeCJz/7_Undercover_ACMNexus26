let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;
let scannedLinks = [];
let isScanningEnabled = null; // Default to null until storage is checked

// [Expert Security Shield] - Immediate Execution
// This runs synchronously to catch the page BEFORE anything is parsed.
const currentUrl = window.location.href;
const isHttp = currentUrl.startsWith("http://");
const hostname = window.location.hostname.toLowerCase();
const isLocal = hostname === "localhost" || hostname === "127.0.0.1" || hostname.startsWith("192.168.") || hostname.startsWith("10.");

// If it's a known simple threat (HTTP), we can prep the flag immediately
let fastFlagReason = (isHttp && !isLocal) ? "Insecure Protocol (HTTP)" : null;

// Aggressively hide the document the micro-second it becomes available
const applyShield = (el) => {
  if (document.getElementById("LinPatrol-shield")) return;
  const shield = document.createElement("style");
  shield.id = "LinPatrol-shield";
  shield.textContent = "html { display: none !important; }";
  el.appendChild(shield);
};

if (document.documentElement) {
  applyShield(document.documentElement);
} else {
  const observer = new MutationObserver(() => {
    if (document.documentElement) {
      applyShield(document.documentElement);
      observer.disconnect();
    }
  });
  observer.observe(document, { childList: true });
}

function restoreVisibility() {
  const shield = document.getElementById("LinPatrol-shield");
  if (shield) shield.remove();
}

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

  const isContextValid = () => !!(chrome && chrome.runtime && chrome.runtime.id);
  if (!isContextValid()) return { safe: true };

  const domain = extractDomain(urlStr);
  if (!domain) return { safe: true };

  // 1. Protocol Security Check
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
  const isSquatting = sensitiveBrands.some(brand => {
    const parts = domain.split('.');
    const isBrandInDomain = domain.includes(brand);
    const isBrandPrimary = parts.slice(-2).some(p => p.includes(brand));
    return isBrandInDomain && !isBrandPrimary;
  });

  if (isSquatting) {
    return {
      safe: false,
      reason: "Typosquatting Detected",
      details: "This domain contains a trusted brand name in its prefix but is hosted on an unrelated server."
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
      details: `This link triggers a download for a high-risk file type (.${fileExt}) which could contain malware.`
    };
  }

  // 7. URL Shortener Masking
  if (urlShorteners.includes(domain)) {
    return {
      safe: false,
      reason: "Shortened URL (Masked)",
      details: "This link uses a URL shortener to hide its true destination."
    };
  }

  // 8. Plain-Text Token/Exfiltration Audit
  const sensitiveParams = ["token=", "sid=", "session=", "pass=", "pwd=", "key="];
  if (sensitiveParams.some(p => urlStr.toLowerCase().includes(p))) {
    return {
      safe: false,
      reason: "Data Leakage Threat",
      details: "The link contains sensitive session tokens or password fragments in the URL itself."
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
      details: `Intelligence data confirms this domain ("${domain}") is malicious.`
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

function showInterstitial(reason) {
  if (sessionStorage.getItem(`lss-dismissed-threat-${window.location.hostname}`)) {
    restoreVisibility();
    return;
  }

  // Wait for body to be available if needed
  if (!document.body) {
    setTimeout(() => showInterstitial(reason), 30);
    return;
  }

  const overlay = document.createElement("div");
  overlay.className = "lss-interstitial";
  overlay.innerHTML = `
    <h1>ACCESS DENIED</h1>
    <p>LinPatrol has identified this site as dangerous.</p>
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
    restoreVisibility();
    overlay.remove();
  });
}

let isScanningInProgress = false;
function runPatrolScan() {
  if (isScanningInProgress) return;

  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    if (typeof chrome !== "undefined" && !chrome.runtime?.id) {
       restoreVisibility();
    }
    return;
  }

  isScanningInProgress = true;
  chrome.storage.local.get(
    ["blacklist", "whitelist", "keywords", "suspiciousTlds", "sensitiveBrands", "dangerousExtensions", "urlShorteners", "isScanningEnabled"],
    (res) => {
      isScanningInProgress = false;
      if (chrome.runtime.lastError) {
        restoreVisibility();
        return;
      }
      isScanningEnabled = res.isScanningEnabled !== false;

      // [CRITICAL] If disabled, revert EVERYTHING instantly
      if (!isScanningEnabled) {
        notifyStatus("OFF");
        restoreVisibility();
        const existingOverlay = document.querySelector(".lss-interstitial");
        if (existingOverlay) existingOverlay.remove();

        // Clear all highlighted links on the page
        document.querySelectorAll(".lss-unsafe-link").forEach(link => {
          link.classList.remove("lss-unsafe-link");
          delete link.dataset.lssReason;
          delete link.dataset.lssId;
        });
        return;
      }

      // If we already detected a fast-flag threat (like HTTP), jump to alert
      if (fastFlagReason) {
        isCurrentSiteDangerous = true;
        showInterstitial(fastFlagReason);
        notifyStatus("DANGER");
        return;
      }

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
        "",
        dangerousExtensions,
        urlShorteners
      );

      if (!siteCheck.safe) {
        // [FIX] No longer hard-blocking with an interstitial overlay for heuristics.
        // We only mark it as dangerous to trigger badge alerts and notifications.
        isCurrentSiteDangerous = true;
        notifyStatus("DANGER");
        restoreVisibility(); // Unblank the page immediately for a smooth experience
        return;
      } else {
        restoreVisibility();
      }

      // Proceed to link scanning if idle
      const performFullScan = () => {
        const auditedLinks = scanAllLinks(blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, dangerousExtensions, urlShorteners);
        const flagCount = auditedLinks.filter(l => !l.safe).length;
        if (flagCount > 0) {
          notifyStatus("WARN", auditedLinks);
        } else {
          notifyStatus("SAFE", auditedLinks);
        }
      };

      if (document.readyState === "complete" || document.readyState === "interactive") {
        performFullScan();
      } else {
        document.addEventListener("DOMContentLoaded", performFullScan);
      }
    }
  );
}

function scanAllLinks(blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, dangerousExtensions, urlShorteners) {
  const links = getAllLinksRecursively(document);
  const auditedLinks = [];
  
  links.forEach((link, idx) => {
    // Tag the link in the DOM for potential scrolling
    link.dataset.lssId = `lss-link-${idx}`;

    const result = checkUrlSafe(link.href, blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, link.innerText, dangerousExtensions, urlShorteners);
    
    // [FIX 2] ONLY apply red boxes if protection is ENABLED
    if (!result.safe && isScanningEnabled) {
      link.classList.add("lss-unsafe-link");
      link.dataset.lssReason = result.reason;
      
      // Bind hover events for the security tooltip
      link.onmouseenter = (e) => showTooltip(link, result.reason, e);
      link.onmouseleave = () => hideTooltip();
    } else {
      // Clean up if it was previously flagged but now safe or disabled
      link.classList.remove("lss-unsafe-link");
      link.onmouseenter = null;
      link.onmouseleave = null;
    }
    auditedLinks.push({
      id: link.dataset.lssId,
      url: link.href,
      safe: result.safe,
      reason: result.reason || "Verified Safe"
    });
  });
  return auditedLinks;
}

/**
 * Deep-Search Link Discovery
 * Pierces through Shadow DOM to find links in modern SPAs (Spotify, etc.)
 */
function getAllLinksRecursively(root) {
  let allLinks = [];
  const findLinks = (node) => {
    if (node.tagName === "A" && node.href) {
      allLinks.push(node);
    }
    
    // Pierce Shadow DOM
    if (node.shadowRoot) {
      findLinks(node.shadowRoot);
    }
    
    // Traverse children
    let child = node.firstChild;
    while (child) {
      findLinks(child);
      child = child.nextSibling;
    }
  };
  
  findLinks(root);
  return allLinks;
}

let activeTooltip = null;
function showTooltip(link, reason, e) {
  if (!isScanningEnabled) return;
  hideTooltip();
  
  activeTooltip = document.createElement("div");
  activeTooltip.className = "lss-tooltip";
  activeTooltip.innerHTML = `<strong>LinPatrol Threat Analysis</strong>${reason}<br><span class="lss-url">${link.href}</span>`;
  document.body.appendChild(activeTooltip);
  
  const rect = link.getBoundingClientRect();
  activeTooltip.style.top = `${window.scrollY + rect.bottom + 8}px`;
  activeTooltip.style.left = `${window.scrollX + rect.left}px`;
}

function hideTooltip() {
  if (activeTooltip) {
    activeTooltip.remove();
    activeTooltip = null;
  }
}

function notifyStatus(status, links = []) {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
    let scoreText = "";
    const unsafeCount = links.filter(l => !l.safe).length;
    
    if (status === "OFF") {
      scoreText = "";
    } else if (isCurrentSiteDangerous) {
      scoreText = "10"; // Max danger if site is intercepted
    } else if (links.length > 0) {
      const score = (unsafeCount / links.length) * 10;
      scoreText = score.toFixed(1);
      if (scoreText === "0.0") scoreText = "0";
    }

    chrome.runtime.sendMessage({ 
      type: "UPDATE_STATUS", 
      status, 
      score: scoreText 
    }).catch(() => {});
  }
}

// 4. Communication Hub
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATS") {
    // Perform a fresh scan to get the latest link states
    chrome.storage.local.get(
      ["blacklist", "whitelist", "keywords", "suspiciousTlds", "sensitiveBrands", "dangerousExtensions", "urlShorteners"],
      (res) => {
        const links = scanAllLinks(
          res.blacklist || [], 
          res.whitelist || [], 
          res.keywords || [], 
          res.suspiciousTlds || [], 
          res.sensitiveBrands || [], 
          res.dangerousExtensions || [], 
          res.urlShorteners || []
        );
        sendResponse({
          totalLinks: links.length,
          unsafeLinks: links.filter(l => !l.safe).length,
          scannedLinks: links,
          isCurrentSiteDangerous: isCurrentSiteDangerous,
          isScanningEnabled: isScanningEnabled
        });
      }
    );
    return true; // Keep channel open for async response
  }

  if (request.type === "SCROLL_TO_LINK") {
    const link = document.querySelector(`a[data-lss-id="${request.linkId}"]`);
    if (link) {
      link.scrollIntoView({ behavior: "smooth", block: "center" });
      link.style.outline = "4px solid var(--danger)";
      setTimeout(() => link.style.outline = "", 1500);
    }
  }
});

// Initial Kickstart
runPatrolScan();

// Monitor for dynamic content
const mutationObserver = new MutationObserver(() => {
  if (isScanningEnabled === true && !isCurrentSiteDangerous) {
    runPatrolScan();
  }
});

if (document.body) {
  mutationObserver.observe(document.body, { childList: true, subtree: true });
} else {
  document.addEventListener("DOMContentLoaded", () => {
    mutationObserver.observe(document.body, { childList: true, subtree: true });
  });
}

// [FIX 1] Instant Cleanup Listener
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.isScanningEnabled) {
    isScanningEnabled = changes.isScanningEnabled.newValue !== false;
    
    if (!isScanningEnabled) {
      // 1. Remove all red highlights
      document.querySelectorAll(".lss-unsafe-link").forEach(link => {
        link.classList.remove("lss-unsafe-link");
        delete link.dataset.lssReason;
        link.onmouseenter = null;
        link.onmouseleave = null;
      });
      
      // 2. Clear any active tooltips
      hideTooltip();
      
      // 3. Remove interstitial overlay if it exists
      const existingOverlay = document.querySelector(".lss-interstitial");
      if (existingOverlay) existingOverlay.remove();
      
      // 4. Reset visibility (un-blank the page)
      restoreVisibility();
    }
  }
});
