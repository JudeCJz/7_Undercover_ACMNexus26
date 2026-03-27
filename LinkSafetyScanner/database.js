const INITIAL_DATABASE = {
  blacklist: [
    // High-Risk Malicious Domains (Exact matches needed)
    "malicious-phish.biz", "secure-bank-login.net", "verify-your-identity.org",
    "urgent-account-update.info", "free-giftcard-generator.xyz", "claim-your-prize.click",
    "locked-account-service.tk", "re-authenticate-now.fun", "unauthorized-access-warning.co",
    "official-support-portal.bid", "system-security-check.gq", "identity-theft-protection.ml",
    "download-malware-tool.cc", "crack-software-free.pw", "fake-crypto-wallet.top",
    "air-drop-claim.live", "metamask-auth-fix.link", "bank-of-america-verify.com",
    "wellsfargo-update-portal.net", "chase-online-service.info", "paypal-resolution-center.com",
    "netflix-billing-issue.org", "amazon-order-delivery.click", "ups-parcel-tracking-fix.biz",
    "fedex-shipping-notice.icu", "dhl-clearance-fee.xyz", "apple-id-suspended.top",
    "microsoft-account-critical.co", "google-security-alert-verification.net"
  ],
  whitelist: [
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com", "netflix.com",
    "wikipedia.org", "youtube.com", "stackoverflow.com", "reddit.com"
  ],
  keywords: [
    // Heuristic trigger words (Must match whole words in URL)
    "verify", "secure", "login", "locked", "suspended", "identity", "breach", 
    "compromised", "lottery", "urgent", "bypass", "unauthorized"
  ],
  suspiciousTlds: [
    // TLDs only flagged if they appear at the end of a domain
    ".tk", ".ml", ".ga", ".gq", ".cf", ".xyz", ".top", ".bid", ".click", ".pw",
    ".icu", ".fun", ".live", ".link", ".online", ".website"
  ]
};

try {
  module.exports = { INITIAL_DATABASE };
} catch(e) {
  window.INITIAL_DATABASE = INITIAL_DATABASE;
}
