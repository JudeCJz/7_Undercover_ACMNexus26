/**
 * SentinelX - Adaptive Security Guard Content Script
 * Combines Link Trace (v2.0) with Identity/Form Monitoring.
 */
let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;
let scannedLinks = []; 

// Shared utilities
const extractDomain = (urlStr) => {
  try { return new URL(urlStr).hostname.toLowerCase(); } catch (e) { return ""; }
};

// 1. Link Logic (Enhanced)
function checkUrlSafe(urlStr, blacklist, whitelist, keywords, suspiciousTlds) {
  if (!urlStr || urlStr.startsWith("javascript:") || urlStr.startsWith("mailto:") || urlStr.startsWith("tel:") || urlStr.startsWith("#")) {
    return { safe: true };
  }

  const domain = extractDomain(urlStr);
  if (!domain) return { safe: true };
  
  if (whitelist.some(w => domain === w || domain.endsWith("." + w))) return { safe: true };

  const isBlacklisted = blacklist.some(b => domain === b || domain.endsWith("." + b));
  if (isBlacklisted) {
    return { safe: false, reason: "Blacklisted Threat", details: `The domain "${domain}" matches a known malicious node.` };
  }

  const isSuspiciousTLD = suspiciousTlds.some(tld => domain.endsWith(tld));
  if (isSuspiciousTLD) {
    return { safe: false, reason: "Infrastructure Risk", details: `Suspicious Top-Level Domain detected (${domain.split('.').pop()}).` };
  }

  const lowerUrl = urlStr.toLowerCase();
  let matchedKeywords = keywords.filter(kw => {
     const regex = new RegExp(`\\b${kw}\\b`, 'i');
     return regex.test(lowerUrl);
  });
  
  if (matchedKeywords.length >= 1 && domain !== window.location.hostname) {
    return { safe: false, reason: "Phishing Heuristic", details: `Found security keywords [${matchedKeywords.join(", ")}] on untrusted domain.` };
  }

  return { safe: true };
}

// 2. Identity & Form Monitoring (SentinelX Feature)
function initIdentityMonitor() {
  const inputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[id*="email"]');
  inputs.forEach(input => {
    input.addEventListener('blur', (e) => {
      const email = e.target.value;
      if (email && email.includes('@')) {
        chrome.runtime.sendMessage({ type: "EMAIL_DETECTED", email: email });
      }
    });
  });
}

// 3. UI/Sidebar Components
function createSidebarElements() {
  if (document.getElementById("lss-sidebar-container")) return;

  const container = document.createElement("div");
  container.id = "lss-sidebar-container";
  container.innerHTML = `
    <div class="lss-trigger" id="lss-sidebar-trigger">SENTINEL-X INTEL</div>
    <div class="lss-sidebar" id="lss-sidebar-main">
      <div class="lss-sidebar-header">
        <h2>SENTINEL-X SECURITY</h2>
        <span style="cursor:pointer; font-weight:bold;" id="lss-sidebar-close">×</span>
      </div>
      <div class="lss-sidebar-content" id="lss-sidebar-content">
        <div class="lss-sidebar-section-title">Identity & Access</div>
        <div id="lss-identity-status">Awaiting Input...</div>
        
        <div class="lss-sidebar-section-title">Adaptive Link Audit</div>
        <div id="lss-link-audit-list">Scanning...</div>
      </div>
    </div>
  `;
  document.body.appendChild(container);

  const trigger = document.getElementById("lss-sidebar-trigger");
  const sidebar = document.getElementById("lss-sidebar-main");
  const close = document.getElementById("lss-sidebar-close");

  trigger.onclick = () => sidebar.classList.toggle("open");
  close.onclick = () => sidebar.classList.remove("open");
}

function updateSidebarUI() {
  const listDiv = document.getElementById("lss-link-audit-list");
  const identDiv = document.getElementById("lss-identity-status");
  if (!listDiv || !identDiv) return;

  identDiv.innerHTML = `<p style="font-size:11px; color:#94a3b8">Scanning forms for identity leaks... Active monitoring enabled.</p>`;

  listDiv.innerHTML = "";
  scannedLinks.slice(0, 50).forEach(link => {
    const item = document.createElement("div");
    item.className = `lss-link-item ${link.safe ? "" : "unsafe"}`;
    item.innerHTML = `<span class="lss-item-url">${link.url}</span><span class="lss-item-reason">${link.safe ? "Clean Trace" : link.reason}</span>`;
    listDiv.appendChild(item);
  });
}

// 4. Initialization
async function runSentinelScan() {
  chrome.storage.local.get(["blacklist", "whitelist", "keywords", "suspiciousTlds", "isScanningEnabled"], (res) => {
    if (res.isScanningEnabled === false) return;
    
    createSidebarElements();
    initIdentityMonitor();

    const blacklist = res.blacklist || [];
    const whitelist = res.whitelist || [];
    const keywords = res.keywords || [];
    const tlds = res.suspiciousTlds || [];

    const siteCheck = checkUrlSafe(window.location.href, blacklist, whitelist, keywords, tlds);
    if (!siteCheck.safe) {
      isCurrentSiteDangerous = true;
      showInterstitial(siteCheck.reason);
    }

    const links = document.querySelectorAll("a");
    unsafeLinks = 0;
    scannedLinks = [];

    links.forEach(link => {
      const url = link.href;
      const linkCheck = checkUrlSafe(url, blacklist, whitelist, keywords, tlds);
      scannedLinks.push({ url, safe: linkCheck.safe, reason: linkCheck.reason || "Safe" });

      if (!linkCheck.safe) {
        unsafeLinks++;
        link.classList.add("lss-unsafe-link");
      }
    });

    updateSidebarUI();
    let status = isCurrentSiteDangerous ? "DANGER" : (unsafeLinks > 0 ? "WARN" : "SAFE");
    chrome.runtime.sendMessage({ type: "UPDATE_STATUS", status: status });
  });
}

function showInterstitial(reason) {
  if (sessionStorage.getItem("lss-dismissed-threat-" + window.location.hostname)) return;

  const overlay = document.createElement("div");
  overlay.className = "lss-interstitial";
  overlay.innerHTML = `
    <h1>🛡️ SENTINEL-X: ACCESS DENIED</h1>
    <p>High-risk domain detected in your current browsing context.</p>
    <p style="font-size: 14px; margin: 20px 0; color:#ef4444">Reason: ${reason}</p>
    <div>
      <button class="btn btn-danger" id="lss-go-back">Return to Safety</button>
      <button class="btn btn-outline" style="margin-top:10px" id="lss-proceed">Override & Proceed</button>
    </div>
  `;

  document.body.appendChild(overlay);
  document.getElementById("lss-go-back").onclick = () => window.history.back();
  document.getElementById("lss-proceed").onclick = () => {
    sessionStorage.setItem("lss-dismissed-threat-" + window.location.hostname, "true");
    overlay.remove();
  };
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runSentinelScan);
else runSentinelScan();

chrome.storage.onChanged.addListener((changes, area) => { if (area === "local") runSentinelScan(); });
