// Logical state tracking
let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;

// Shared utilities
const toLower = (str) => (str ? str.toLowerCase() : "");
const extractDomain = (urlStr) => {
  try { return new URL(urlStr).hostname.toLowerCase(); } catch (e) { return ""; }
};

// 1. Core Threat Detection (Smarter matching logic)
function checkUrlSafe(urlStr, blacklist, whitelist, keywords, suspiciousTlds) {
  if (!urlStr || urlStr.startsWith("javascript:") || urlStr.startsWith("mailto:") || urlStr.startsWith("tel:") || urlStr.startsWith("#")) {
    return { safe: true };
  }

  const domain = extractDomain(urlStr);
  if (!domain) return { safe: true };
  
  // Whitelist check first (Total immunity for trusted platforms)
  if (whitelist.some(w => domain === w || domain.endsWith("." + w))) {
    return { safe: true };
  }

  // Exact or Subdomain Blacklist match
  if (blacklist.some(b => domain === b || domain.endsWith("." + b))) {
    return { 
        safe: false, 
        reason: "Sentinel Alert: Blacklisted Threat",
        details: `The domain "${domain}" is an exact match for a known malicious entity in your local intelligence database.`
    };
  }

  // Suspicious TLD check (Only if it's the actual domain ending)
  if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
    return {
        safe: false,
        reason: "Sentinel Alert: Malicious Infrastructure",
        details: `This link utilizes a high-risk TLD (${domain.split('.').pop()}) frequently associated with phishing or malware delivery.`
    };
  }

  // Keyword-based heuristic (Smarter with whole-word matching)
  const lowerUrl = urlStr.toLowerCase();
  let matchedKeywords = [];
  for (let kw of keywords) {
    const regex = new RegExp(`\\b${kw}\\b`, 'i'); // Whole-word match
    if (regex.test(lowerUrl)) matchedKeywords.push(kw);
  }
  
  // Only trigger keyword threat if it's an external domain
  if (matchedKeywords.length >= 1 && domain !== window.location.hostname) {
    return { 
        safe: false, 
        reason: "Sentinel Alert: Phishing Heuristics",
        details: `Found security keywords [${matchedKeywords.join(", ")}] on an untrusted external domain. This mimics secure portals.`
    };
  }

  return { safe: true };
}

// 2. UI Elements
function cleanupUI() {
  document.querySelectorAll(".lss-unsafe-link").forEach(l => l.classList.remove("lss-unsafe-link"));
  document.querySelectorAll(".lss-banner, .lss-interstitial, .lss-tooltip").forEach(el => el.remove());
}

function showInterstitial(reason) {
  if (sessionStorage.getItem("lss-dismissed-threat-" + window.location.hostname)) return;

  const overlay = document.createElement("div");
  overlay.className = "lss-interstitial";
  overlay.innerHTML = `
    <h1>⚠️ ACCESS DENIED</h1>
    <p>Sentinel One has identified this site as a <strong>DANGEROUS ENTITY</strong>.</p>
    <p style="font-size: 14px; margin: 20px 0;">Reason: ${reason}</p>
    <div class="btn-group">
      <button class="btn btn-danger" id="lss-go-back">Return to Safety</button>
      <button class="btn btn-outline" id="lss-proceed">Proceed Anyway (Risk)</button>
    </div>
  `;

  document.body.appendChild(overlay);
  document.getElementById("lss-go-back").onclick = () => window.history.back();
  document.getElementById("lss-proceed").onclick = () => {
    sessionStorage.setItem("lss-dismissed-threat-" + window.location.hostname, "true");
    overlay.remove();
    showDangerousBanner();
  };
}

function showDangerousBanner() {
  const banner = document.createElement("div");
  banner.className = "lss-banner";
  banner.innerHTML = `⚠️ SENTINEL ALERT: Monitoring Dangerous Domain [${window.location.hostname}]. <span class="lss-banner-close">✕</span>`;
  banner.querySelector(".lss-banner-close").onclick = () => banner.remove();
  document.body.insertBefore(banner, document.body.firstChild);
}

// 3. Main Scanning Engine
function runSentinelScan() {
  cleanupUI();

  chrome.storage.local.get(["blacklist", "whitelist", "keywords", "suspiciousTlds", "isScanningEnabled"], (res) => {
    if (res.isScanningEnabled === false) return;

    const blacklist = res.blacklist || [];
    const whitelist = res.whitelist || [];
    const keywords = res.keywords || [];
    const tlds = res.suspiciousTlds || [];

    // Check current site safety
    const check = checkUrlSafe(window.location.href, blacklist, whitelist, keywords, tlds);
    if (!check.safe) {
      isCurrentSiteDangerous = true;
      showInterstitial(check.reason);
    }

    // Scan links
    const links = document.querySelectorAll("a");
    totalLinks = links.length;
    unsafeLinks = 0;

    links.forEach(link => {
      const url = link.href;
      const linkCheck = checkUrlSafe(url, blacklist, whitelist, keywords, tlds);

      if (!linkCheck.safe) {
        unsafeLinks++;
        link.classList.add("lss-unsafe-link");
        
        link.onmouseenter = () => {
          const tooltip = document.createElement("div");
          tooltip.className = "lss-tooltip";
          tooltip.innerHTML = `<strong>${linkCheck.reason}</strong>${linkCheck.details}<span class="lss-url">URL: ${url}</span>`;
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

    let status = isCurrentSiteDangerous ? "DANGER" : (unsafeLinks > 0 ? "WARN" : "SAFE");
    chrome.runtime.sendMessage({ type: "UPDATE_STATUS", status: status });
  });
}

// 4. Initialization
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runSentinelScan);
else runSentinelScan();

chrome.storage.onChanged.addListener((changes, area) => { if (area === "local") runSentinelScan(); });
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATS") sendResponse({ totalLinks, unsafeLinks, isCurrentSiteDangerous });
});
