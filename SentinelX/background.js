/**
 * SentinelX - Adaptive Security Guard Background Worker
 * Orchestrates API interactions and unified risk scoring.
 */
import { RiskEngine } from './riskEngine.js';
importScripts('database.js'); // Shared link list remains accessible

let currentRiskState = {
  score: 0,
  level: "LOW",
  threatsLogged: 0,
  lastFingerprint: null,
  detectedEmail: null
};

// 1. Install & Initialization
chrome.runtime.onInstalled.addListener(async () => {
  const deviceID = await RiskEngine.generateDeviceID();
  chrome.storage.local.get(["knownDevices", "isScanningEnabled"], (res) => {
    let known = res.knownDevices || [];
    let isNew = !known.includes(deviceID);
    if (isNew) known.push(deviceID);
    
    chrome.storage.local.set({
      knownDevices: known,
      lastFingerprint: deviceID,
      isScanningEnabled: res.isScanningEnabled !== false,
      threatHistory: []
    });
  });
});

// 2. Security Signal Handlers (Simulated for demo, ready for API keys)
const SecurityAPIs = {
  async checkUrl(url) {
    // 🧪 Simulated Google Safe Browsing / VirusTotal
    // In production: fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, { ... })
    const isLocalBlacklist = INITIAL_DATABASE.blacklist.some(b => url.includes(b));
    return !isLocalBlacklist;
  },

  async checkEmail(email) {
    // 🧪 Simulated EmailRep.io
    // In production: fetch(`https://emailrep.io/${email}`, { headers: { 'Key': API_KEY } })
    const suspicious = ["tempmail.com", "test.com", "fake.net"];
    return suspicious.some(s => email.endsWith(s)) ? 0.8 : 0.1;
  },

  async checkLeaks(email) {
    // 🧪 Simulated Webz.io / HaveIBeenPwned
    return Math.random() > 0.8; // Randomly simulate 20% exposure rate for demo
  }
};

// 3. Central Alert System
function pushAlert(title, message) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: `🛡️ SentinelX: ${title}`,
    message: message,
    priority: 2
  });
}

// 4. Message Router
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "EMAIL_DETECTED") {
    handleEmailAudit(request.email);
    return true;
  }

  if (request.type === "GET_SENTINEL_DASHBOARD") {
    sendResponse(currentRiskState);
    return true;
  }

  if (request.type === "UPDATE_STATUS") {
     // Forward from link safety content script to icon/badge
     handleBadgeUpdate(request.status, sender.tab.id);
  }
});

async function handleEmailAudit(email) {
  const risk = await SecurityAPIs.checkEmail(email);
  const leaked = await SecurityAPIs.checkLeaks(email);
  
  // Re-calculate risk score
  const signals = {
    isUrlSafe: true, // Placeholder for specific URL events
    isNewDevice: false,
    emailRisk: risk,
    leakedInWebz: leaked
  };

  const assessment = RiskEngine.calculate(signals);
  currentRiskState = { ...currentRiskState, ...assessment, detectedEmail: email };

  if (assessment.level !== "LOW") {
    pushAlert(`${assessment.level} Risk Identity Alert`, `Calculated Risk Score: ${assessment.score}. ${assessment.explanation}`);
  }
  
  // Log threat history
  chrome.storage.local.get(["threatHistory"], (res) => {
     let history = res.threatHistory || [];
     history.unshift({ ...assessment, email: email, id: Date.now() });
     chrome.storage.local.set({ threatHistory: history.slice(0, 50) });
  });
}

function handleBadgeUpdate(status, tabId) {
    const map = { SAFE: "✓", WARN: "!", DANGER: "X" };
    const color = { SAFE: "#22c55e", WARN: "#f59e0b", DANGER: "#ef4444" };
    chrome.action.setBadgeText({ text: map[status] || "", tabId });
    if (color[status]) chrome.action.setBadgeBackgroundColor({ color: color[status], tabId });
}
