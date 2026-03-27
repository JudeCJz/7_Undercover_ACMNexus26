/**
 * SentinelX Dashboard Logic (v2.0)
 * Handles visual synchronization with the Background Risk Engine.
 */

document.addEventListener("DOMContentLoaded", () => {
    const riskGauge = document.getElementById("risk-gauge");
    const riskNumber = document.getElementById("risk-number");
    const threatList = document.getElementById("threat-list");
    const scanToggle = document.getElementById("scan-toggle");

    // 1. Initial State Sync
    chrome.storage.local.get(["isScanningEnabled", "lastFingerprint", "threatHistory"], (res) => {
        scanToggle.checked = res.isScanningEnabled !== false;
        document.getElementById("val-device").textContent = res.lastFingerprint ? res.lastFingerprint.substring(0, 8).toUpperCase() : "AUDITING...";
        renderThreatHistory(res.threatHistory || []);
    });

    // 2. Fetch Live Dashboard Data from Background
    function refreshDashboard() {
        chrome.runtime.sendMessage({ type: "GET_SENTINEL_DASHBOARD" }, (riskState) => {
            if (riskState) {
                updateGauge(riskState.score, riskState.level);
                document.getElementById("risk-explanation").textContent = riskState.explanation;
                
                // Update specific signal cards
                if (riskState.detectedEmail) {
                    document.getElementById("val-email").textContent = riskState.score > 30 ? "SUSPICIOUS" : "STABLE";
                    document.getElementById("val-email").style.color = riskState.score > 30 ? "#ef4444" : "#22c55e";
                }
            }
        });
    }

    // 3. UI Animations
    function updateGauge(score, level) {
        riskNumber.textContent = score;
        const colorMap = {
            "LOW": "#22c55e",
            "MEDIUM": "#f59e0b",
            "HIGH": "#ef4444"
        };
        const color = colorMap[level] || "#38bdf8";
        riskNumber.style.color = color;
        
        // Calculate degree (100% = 360deg)
        const deg = (score / 100) * 360;
        riskGauge.style.background = `conic-gradient(${color} ${deg}deg, #1e293b 0deg)`;
    }

    function renderThreatHistory(history) {
        if (history.length === 0) return;
        threatList.innerHTML = "";
        
        history.slice(0, 3).forEach(item => {
            const div = document.createElement("div");
            div.className = "threat-item";
            div.innerHTML = `
                <div class="threat-info">
                    <div class="threat-title">${item.level} Risk Identity Audit</div>
                    <div class="threat-meta">${item.email || "System Level"} | ${new Date(item.timestamp).toLocaleTimeString()}</div>
                </div>
                <div class="threat-badge" style="background: ${item.level === 'HIGH' ? '#ef4444' : (item.level === 'MEDIUM' ? '#f59e0b' : '#22c55e')}">${item.level}</div>
            `;
            threatList.appendChild(div);
        });
    }

    // 4. Interaction Handlers
    scanToggle.addEventListener("change", (e) => {
        chrome.storage.local.set({ isScanningEnabled: e.target.checked });
    });

    // Refresh every 1 sec while open
    refreshDashboard();
    setInterval(refreshDashboard, 1500);
});
