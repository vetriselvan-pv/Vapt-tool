const els = {
  statusBadge: document.getElementById("statusBadge"),
  targetTabLabel: document.getElementById("targetTabLabel"),
  targetTabUrl: document.getElementById("targetTabUrl"),
  toggleProxyBtn: document.getElementById("toggleProxyBtn"),
  errorBanner: document.getElementById("errorBanner"),
  captureTargetGroup: document.getElementById("captureTargetGroup"),
  headerMode: document.getElementById("headerMode"),
  swapEnabled: document.getElementById("swapEnabled"),
  urlFilter: document.getElementById("urlFilter"),
  stripBothAuthHeaders: document.getElementById("stripBothAuthHeaders"),
  userAToken: document.getElementById("userAToken"),
  userABadge: document.getElementById("userABadge"),
  clearUserABtn: document.getElementById("clearUserABtn"),
  userBToken: document.getElementById("userBToken"),
  userBBadge: document.getElementById("userBBadge"),
  swapTokensBtn: document.getElementById("swapTokensBtn"),
  clearUserBBtn: document.getElementById("clearUserBBtn"),
  trafficLog: document.getElementById("trafficLog"),
  clearLogsBtn: document.getElementById("clearLogsBtn")
};

let currentState = null;
let activeTab = null;
let pendingPatch = {};
let debounceTimer = null;

function formatTabUrl(rawUrl) {
  if (!rawUrl) return "—";
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.host}${parsed.pathname === "/" ? "" : parsed.pathname}`;
  } catch {
    return rawUrl;
  }
}

function showError(message) {
  if (!message) {
    els.errorBanner.textContent = "";
    els.errorBanner.classList.add("hidden");
    return;
  }
  els.errorBanner.textContent = message;
  els.errorBanner.classList.remove("hidden");
}

function updateTokenBadge(badgeEl, tokenValue, headerType) {
  const hasValue = Boolean(tokenValue && tokenValue.trim());
  if (!hasValue) {
    badgeEl.textContent = "Empty";
    badgeEl.classList.remove("detected");
    return;
  }
  badgeEl.textContent = headerType || "Set";
  badgeEl.classList.add("detected");
}

function renderTrafficLogs(logs) {
  els.trafficLog.textContent = "";

  if (!Array.isArray(logs) || logs.length === 0) {
    const emptyItem = document.createElement("li");
    emptyItem.className = "log-empty";
    emptyItem.textContent = "Enable proxy and trigger /api/ traffic to inspect swaps.";
    els.trafficLog.appendChild(emptyItem);
    return;
  }

  for (const entry of logs) {
    const li = document.createElement("li");
    li.className = "log-item";

    const tag = document.createElement("span");
    tag.className = entry.swapped ? "log-tag swapped" : "log-tag";
    tag.textContent = entry.swapped ? "SWAP" : "PASS";

    const method = document.createElement("span");
    method.className = "log-method";
    method.textContent = entry.method || "GET";

    const path = document.createElement("span");
    path.className = "log-path";
    path.title = entry.path || "";
    path.textContent = entry.path || "/";

    const status = document.createElement("span");
    status.className = "log-status";
    if (typeof entry.status === "number") {
      status.textContent = String(entry.status);
      if (entry.status >= 200 && entry.status < 300) {
        status.classList.add("ok");
      } else if (entry.status === 401 || entry.status === 403) {
        status.classList.add("blocked");
      }
    } else {
      status.textContent = "…";
    }

    li.append(tag, method, path, status);
    els.trafficLog.appendChild(li);
  }
}

function renderState(state) {
  if (!state) return;
  currentState = state;

  const isAttached = Boolean(state.interceptionEnabled && state.attachedTabId !== null);

  if (isAttached) {
    els.statusBadge.textContent = `ACTIVE · #${state.attachedTabId}`;
    els.statusBadge.classList.add("active");
    els.toggleProxyBtn.textContent = "Disable Interception Proxy";
    els.toggleProxyBtn.classList.add("attached");
    els.targetTabLabel.textContent = `Attached Tab: #${state.attachedTabId}`;
    els.targetTabUrl.textContent = formatTabUrl(state.attachedTabUrl);
    els.targetTabUrl.title = state.attachedTabUrl || "";
  } else {
    els.statusBadge.textContent = "IDLE";
    els.statusBadge.classList.remove("active");
    els.toggleProxyBtn.textContent = "Enable Interception Proxy";
    els.toggleProxyBtn.classList.remove("attached");
    els.targetTabLabel.textContent = activeTab ? `Active Tab: #${activeTab.id}` : "Active Tab: —";
    els.targetTabUrl.textContent = formatTabUrl(activeTab?.url);
    els.targetTabUrl.title = activeTab?.url || "";
  }

  for (const btn of els.captureTargetGroup.querySelectorAll("button")) {
    btn.classList.toggle("selected", btn.dataset.target === state.captureTarget);
  }

  els.headerMode.value = state.headerMode || "auto";
  els.swapEnabled.checked = Boolean(state.swapEnabled);
  els.stripBothAuthHeaders.checked = Boolean(state.stripBothAuthHeaders);

  if (document.activeElement !== els.urlFilter) {
    els.urlFilter.value = state.urlFilter ?? "/api/";
  }
  if (document.activeElement !== els.userAToken) {
    els.userAToken.value = state.userAToken || "";
  }
  if (document.activeElement !== els.userBToken) {
    els.userBToken.value = state.userBToken || "";
  }

  updateTokenBadge(els.userABadge, state.userAToken, state.userAHeaderType);
  updateTokenBadge(els.userBBadge, state.userBToken, state.userBHeaderType);
  renderTrafficLogs(state.logs);
}

async function sendMessage(payload) {
  return chrome.runtime.sendMessage(payload);
}

async function updateConfigImmediate(patch) {
  const res = await sendMessage({ type: "UPDATE_CONFIG", patch });
  if (res?.state) {
    renderState(res.state);
  }
}

function flushPendingPatch() {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
    debounceTimer = null;
  }
  if (Object.keys(pendingPatch).length === 0) return;
  const patch = { ...pendingPatch };
  pendingPatch = {};
  updateConfigImmediate(patch).catch(() => {});
}

function schedulePatch(patch) {
  pendingPatch = { ...pendingPatch, ...patch };
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(flushPendingPatch, 80);
}

async function getCurrentActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || null;
  return activeTab;
}

els.toggleProxyBtn.addEventListener("click", async () => {
  showError("");
  flushPendingPatch();
  els.toggleProxyBtn.disabled = true;

  try {
    if (currentState?.interceptionEnabled) {
      const res = await sendMessage({
        type: "DISABLE_PROXY",
        tabId: currentState.attachedTabId
      });
      if (res?.state) renderState(res.state);
    } else {
      const tab = await getCurrentActiveTab();
      if (!tab?.id) {
        showError("No active browser tab found.");
        return;
      }
      const res = await sendMessage({
        type: "ENABLE_PROXY",
        tabId: tab.id,
        tabUrl: tab.url || ""
      });
      if (!res?.ok) {
        showError(res?.error || "Failed to attach Chrome debugger.");
      }
      if (res?.state) renderState(res.state);
    }
  } catch (err) {
    showError(String(err?.message || err));
  } finally {
    els.toggleProxyBtn.disabled = false;
  }
});

els.captureTargetGroup.addEventListener("click", (event) => {
  const btn = event.target.closest("button[data-target]");
  if (!btn) return;
  updateConfigImmediate({ captureTarget: btn.dataset.target });
});

els.headerMode.addEventListener("change", () => {
  updateConfigImmediate({ headerMode: els.headerMode.value });
});

els.swapEnabled.addEventListener("change", () => {
  updateConfigImmediate({ swapEnabled: els.swapEnabled.checked });
});

els.stripBothAuthHeaders.addEventListener("change", () => {
  updateConfigImmediate({ stripBothAuthHeaders: els.stripBothAuthHeaders.checked });
});

els.userAToken.addEventListener("input", () => {
  schedulePatch({ userAToken: els.userAToken.value });
});
els.userAToken.addEventListener("change", flushPendingPatch);
els.userAToken.addEventListener("blur", flushPendingPatch);

els.userBToken.addEventListener("input", () => {
  schedulePatch({ userBToken: els.userBToken.value });
});
els.userBToken.addEventListener("change", flushPendingPatch);
els.userBToken.addEventListener("blur", flushPendingPatch);

els.urlFilter.addEventListener("input", () => {
  schedulePatch({ urlFilter: els.urlFilter.value });
});
els.urlFilter.addEventListener("change", flushPendingPatch);
els.urlFilter.addEventListener("blur", flushPendingPatch);

els.clearUserABtn.addEventListener("click", () => {
  els.userAToken.value = "";
  delete pendingPatch.userAToken;
  updateConfigImmediate({ userAToken: "" });
});

els.clearUserBBtn.addEventListener("click", () => {
  els.userBToken.value = "";
  delete pendingPatch.userBToken;
  updateConfigImmediate({ userBToken: "" });
});

els.swapTokensBtn.addEventListener("click", async () => {
  flushPendingPatch();
  const res = await sendMessage({ type: "SWAP_USER_TOKENS" });
  if (res?.state) renderState(res.state);
});

els.clearLogsBtn.addEventListener("click", async () => {
  const res = await sendMessage({ type: "CLEAR_LOGS" });
  if (res?.state) renderState(res.state);
});

window.addEventListener("pagehide", flushPendingPatch);

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "STATE_UPDATED" && message.state) {
    renderState(message.state);
  }
});

document.addEventListener("DOMContentLoaded", async () => {
  await getCurrentActiveTab();
  const res = await sendMessage({ type: "GET_STATE" });
  if (res?.state) {
    renderState(res.state);
  }
});
