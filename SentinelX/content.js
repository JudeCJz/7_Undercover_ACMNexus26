let totalLinks = 0;
let unsafeLinks = 0;
let isCurrentSiteDangerous = false;
let scannedLinks = [];
let isScanningEnabled = true;

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
  if (document.getElementById("sentinel-shield")) return;
  const shield = document.createElement("style");
  shield.id = "sentinel-shield";
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
  const shield = document.getElementById("sentinel-shield");
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

function runPatrolScan() {
  // If we already detected a fast-flag threat (like HTTP), jump to alert
  if (fastFlagReason) {
    isCurrentSiteDangerous = true;
    showInterstitial(fastFlagReason);
    notifyStatus("DANGER");
    return;
  }

  chrome.storage.local.get(
    ["blacklist", "whitelist", "keywords", "suspiciousTlds", "sensitiveBrands", "dangerousExtensions", "urlShorteners", "isScanningEnabled"],
    (res) => {
      isScanningEnabled = res.isScanningEnabled !== false;

      if (!isScanningEnabled) {
        notifyStatus("OFF");
        restoreVisibility();
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
        isCurrentSiteDangerous = true;
        showInterstitial(siteCheck.reason);
        notifyStatus("DANGER");
      } else {
        restoreVisibility();
      }

      // Proceed to link scanning if idle
      if (document.readyState === "complete" || document.readyState === "interactive") {
        scanAllLinks(blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, dangerousExtensions, urlShorteners);
      } else {
        document.addEventListener("DOMContentLoaded", () => {
           scanAllLinks(blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, dangerousExtensions, urlShorteners);
        });
      }
    }
  );
}

function scanAllLinks(blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, dangerousExtensions, urlShorteners) {
  const links = document.querySelectorAll("a[href]");
  links.forEach((link) => {
    const result = checkUrlSafe(link.href, blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, link.innerText, dangerousExtensions, urlShorteners);
    if (!result.safe) {
      link.classList.add("lss-unsafe-link");
      link.dataset.lssReason = result.reason;
    }
  });
}

function notifyStatus(status) {
  chrome.runtime.sendMessage({ type: "UPDATE_STATUS", status });
}

// Initial Kickstart
runPatrolScan();

// Monitor for dynamic content
const observer = new MutationObserver(() => {
  if (isScanningEnabled && !isCurrentSiteDangerous) {
    runPatrolScan();
  }
});

if (document.body) {
  observer.observe(document.body, { childList: true, subtree: true });
} else {
  document.addEventListener("DOMContentLoaded", () => {
    observer.observe(document.body, { childList: true, subtree: true });
  });
}
