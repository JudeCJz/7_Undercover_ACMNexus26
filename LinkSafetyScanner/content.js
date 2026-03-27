// Scan logical state
let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;

// Helpers
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

function checkUrlSafe(urlStr, blacklist, keywords) {
  if (!urlStr) return { safe: true };
  if (urlStr.startsWith("javascript:") || urlStr.startsWith("mailto:") || urlStr.startsWith("tel:") || urlStr.startsWith("#")) {
    return { safe: true }; // Ignore these
  }
  
  const domain = extractDomain(urlStr);
  const lowerUrl = urlStr.toLowerCase();

  // Check blacklist
  if (blacklist.some(b => domain.includes(toLowerCaseSafe(b)) || lowerUrl.includes(toLowerCaseSafe(b)))) {
    return { safe: false, reason: "Threat: Blacklisted Domain" };
  }

  // Check suspicious keywords
  let keywordCount = 0;
  for (let kw of keywords) {
    if (lowerUrl.includes(toLowerCaseSafe(kw))) keywordCount++;
  }
  
  if (keywordCount >= 1 && domain !== "" && domain !== window.location.hostname) {
    return { safe: false, reason: "Threat: Obfuscated Phishing Keywords" };
  }

  return { safe: true };
}

function showDangerousBanner() {
  const banner = document.createElement("div");
  banner.className = "lss-banner";
  
  const text = document.createElement("span");
  text.textContent = "⚠️ SENTINEL ALERT: This website is a known security hazard. Proceeding is high-risk! ";
  
  const closeBtn = document.createElement("span");
  closeBtn.className = "lss-banner-close";
  closeBtn.textContent = "X";
  closeBtn.addEventListener("click", () => banner.remove());

  banner.appendChild(text);
  banner.appendChild(closeBtn);
  document.body.insertBefore(banner, document.body.firstChild);
}

function scanPage(blacklist, whitelist, keywords) {
  const currentDomain = window.location.hostname;
  if (!whitelist.includes(currentDomain)) {
    if (blacklist.some(b => currentDomain.includes(toLowerCaseSafe(b)))) {
      isCurrentSiteDangerous = true;
      showDangerousBanner();
    }
  }

  const links = document.querySelectorAll("a");
  totalLinks = links.length;

  links.forEach(link => {
    const url = link.href;
    const check = checkUrlSafe(url, blacklist, keywords);

    if (!check.safe) {
      unsafeLinks++;
      link.classList.add("lss-unsafe-link");
      
      link.addEventListener("mouseenter", (e) => {
        const tooltip = document.createElement("div");
        tooltip.className = "lss-tooltip";
        tooltip.textContent = check.reason;
        tooltip.id = "lss-temp-tooltip";
        document.body.appendChild(tooltip);
        
        const rect = link.getBoundingClientRect();
        tooltip.style.left = `${rect.left + window.scrollX}px`;
        tooltip.style.top = `${rect.bottom + window.scrollY + 5}px`;
      });

      link.addEventListener("mouseleave", () => {
        const tooltip = document.getElementById("lss-temp-tooltip");
        if (tooltip) tooltip.remove();
      });
    }
  });

  let status = "SAFE";
  if (isCurrentSiteDangerous) {
    status = "DANGER";
  } else if (unsafeLinks > 0) {
    status = unsafeLinks > Math.floor(totalLinks * 0.1) ? "DANGER" : "WARN";
  }

  chrome.runtime.sendMessage({ type: "UPDATE_STATUS", status: status });
}

// Global initialization
chrome.storage.local.get(["blacklist", "whitelist", "keywords", "isScanningEnabled"], (res) => {
  if (res.isScanningEnabled === false) return; // Scanning is disabled

  const blacklist = res.blacklist || [];
  const whitelist = res.whitelist || [];
  const keywords = res.keywords || [];
  
  if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => scanPage(blacklist, whitelist, keywords));
  } else {
      scanPage(blacklist, whitelist, keywords);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATS") {
    sendResponse({
      totalLinks: totalLinks,
      unsafeLinks: unsafeLinks,
      isCurrentSiteDangerous: isCurrentSiteDangerous
    });
  }
});
