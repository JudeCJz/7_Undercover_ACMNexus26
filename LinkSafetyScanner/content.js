// Logical state tracking
let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;
let isBannerDismissed = false;

// Shared utility
function extractDomain(urlStr) {
  try {
    const url = new URL(urlStr);
    return url.hostname;
  } catch (e) {
    return "";
  }
}

function toLowerCaseSafe(str) {
    return str ? str.toLowerCase() : "";
}

// 1. Core Threat Detection
function checkUrlSafe(urlStr, blacklist, keywords) {
  if (!urlStr) return { safe: true };
  if (urlStr.startsWith("javascript:") || urlStr.startsWith("mailto:") || urlStr.startsWith("tel:") || urlStr.startsWith("#")) {
    return { safe: true };
  }
  
  const domain = extractDomain(urlStr);
  const lowerUrl = urlStr.toLowerCase();

  // Exact or Partial Blacklist match
  if (blacklist.some(b => domain.includes(toLowerCaseSafe(b)) || lowerUrl.includes(toLowerCaseSafe(b)))) {
    return { 
        safe: false, 
        reason: "Blacklisted Threat Source",
        details: "This domain has been manually designated as a malicious or untrusted entity in your Sentinel One local database."
    };
  }

  // Keyword-based heuristic
  let matchedKeywords = [];
  for (let kw of keywords) {
    if (lowerUrl.includes(toLowerCaseSafe(kw))) matchedKeywords.push(kw);
  }
  
  if (matchedKeywords.length >= 1 && domain !== "" && domain !== window.location.hostname) {
    return { 
        safe: false, 
        reason: "Suspicious Obfuscation Detector",
        details: `Identified high-risk keywords: [${matchedKeywords.join(", ")}]. This external link mimics a sensitive institutional portal.`
    };
  }

  return { safe: true };
}

// 2. UI Elements (Banner, Interstitial, Tooltips)
function cleanupUI() {
  document.querySelectorAll(".lss-unsafe-link").forEach(l => l.classList.remove("lss-unsafe-link"));
  document.querySelectorAll(".lss-banner, .lss-interstitial, .lss-tooltip").forEach(el => el.remove());
}

function showInterstitial() {
  if (sessionStorage.getItem("lss-dismissed-threat")) return;

  const overlay = document.createElement("div");
  overlay.className = "lss-interstitial";
  overlay.innerHTML = `
    <h1>⚠️ ACCESS DENIED</h1>
    <p>Sentinel One has identified this site as a <strong>DANGEROUS ENTITY</strong>. Access has been restricted to prevent data exfiltration or system infection.</p>
    <p style="font-size: 14px; margin-top:20px;">Domain: <code>${window.location.hostname}</code></p>
    <div class="btn-group">
      <button class="btn btn-danger" id="lss-go-back">Return to Safety</button>
      <button class="btn btn-outline" id="lss-proceed">Proceed Anyway (Risk)</button>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("lss-go-back").onclick = () => {
    window.history.back();
    if (window.history.length <= 1) window.close();
  };

  document.getElementById("lss-proceed").onclick = () => {
    sessionStorage.setItem("lss-dismissed-threat", "true");
    overlay.remove();
    showDangerousBanner();
  };
}

function showDangerousBanner() {
  const banner = document.createElement("div");
  banner.className = "lss-banner";
  banner.innerHTML = `
    ⚠️ SENTINEL ALERT: Continuous Monitoring Active for Dangerous Domain. Proceed with caution!
    <span class="lss-banner-close">X</span>
  `;
  
  banner.querySelector(".lss-banner-close").onclick = () => banner.remove();
  document.body.insertBefore(banner, document.body.firstChild);
}

// 3. Main Scanning Engine
function runSentinelScan() {
  cleanupUI();

  chrome.storage.local.get(["blacklist", "whitelist", "keywords", "isScanningEnabled"], (res) => {
    if (res.isScanningEnabled === false) return;

    const blacklist = res.blacklist || [];
    const whitelist = res.whitelist || [];
    const keywords = res.keywords || [];

    // Check current page
    const currentDomain = window.location.hostname;
    if (!whitelist.includes(currentDomain)) {
      if (blacklist.some(b => currentDomain.includes(toLowerCaseSafe(b)))) {
        isCurrentSiteDangerous = true;
        showInterstitial();
      }
    }

    // Scan all links
    const links = document.querySelectorAll("a");
    totalLinks = links.length;
    unsafeLinks = 0;

    links.forEach(link => {
      const url = link.href;
      const check = checkUrlSafe(url, blacklist, keywords);

      if (!check.safe) {
        unsafeLinks++;
        link.classList.add("lss-unsafe-link");
        
        link.onmouseenter = (e) => {
          const tooltip = document.createElement("div");
          tooltip.className = "lss-tooltip";
          tooltip.innerHTML = `
            <strong>${check.reason}</strong>
            ${check.details}
            <span class="lss-url">Flagged: ${url}</span>
          `;
          tooltip.id = "lss-temp-tooltip";
          document.body.appendChild(tooltip);
          
          const rect = link.getBoundingClientRect();
          tooltip.style.left = `${rect.left + window.scrollX}px`;
          tooltip.style.top = `${rect.bottom + window.scrollY + 10}px`;
        };

        link.onmouseleave = () => {
          const tooltip = document.getElementById("lss-temp-tooltip");
          if (tooltip) tooltip.remove();
        };
      }
    });

    // Update Extension Badge Info
    let status = "SAFE";
    if (isCurrentSiteDangerous) status = "DANGER";
    else if (unsafeLinks > 0) status = unsafeLinks > Math.floor(totalLinks * 0.1) ? "DANGER" : "WARN";
    
    chrome.runtime.sendMessage({ type: "UPDATE_STATUS", status: status });
  });
}

// 4. Initialization and Dynamic Listeners
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runSentinelScan);
} else {
    runSentinelScan();
}

// Watch for manual toggle/database changes in real-time
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") {
     runSentinelScan(); 
  }
});

// Communication with popup for real-time stats
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATS") {
    sendResponse({
      totalLinks: totalLinks,
      unsafeLinks: unsafeLinks,
      isCurrentSiteDangerous: isCurrentSiteDangerous
    });
  }
});
