const CDP_VERSION = "1.3";
const STORAGE_KEY = "vaptSessionProxyState";
const ACCENT_COLOR = "#466557";
const MAX_LOGS = 25;
const MAX_TRACKED_NETWORK_IDS = 500;

const DEFAULT_STATE = {
  interceptionEnabled: false,
  attachedTabId: null,
  attachedTabUrl: "",
  userAToken: "",
  userAHeaderType: "",
  userBToken: "",
  userBHeaderType: "",
  captureTarget: "userA", // "off" | "userA" | "userB"
  headerMode: "auto", // "auto" | "Authorization" | "Cookie"
  urlFilter: "/api/",
  swapEnabled: true,
  stripBothAuthHeaders: false,
  logs: []
};

let state = { ...DEFAULT_STATE, logs: [] };
let initPromise = null;
let writeQueue = Promise.resolve();

// Ephemeral per-request correlation maps (bounded to avoid leaks during long sessions)
const requestUrlByNetworkId = new Map();
const swappedNetworkIds = new Set();

function trackBoundedMap(map, key, value) {
  if (map.size >= MAX_TRACKED_NETWORK_IDS) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
  map.set(key, value);
}

function trackBoundedSet(set, key) {
  if (set.size >= MAX_TRACKED_NETWORK_IDS) {
    const oldestKey = set.values().next().value;
    set.delete(oldestKey);
  }
  set.add(key);
}

function getHeaderCaseInsensitive(headers, targetName) {
  if (!headers || typeof headers !== "object") return null;
  const targetLower = targetName.toLowerCase();
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === targetLower && value !== undefined && value !== null) {
      const trimmed = String(value).trim();
      if (trimmed) {
        return { name, value: trimmed };
      }
    }
  }
  return null;
}

function detectHeaderType(value) {
  if (/^(bearer|basic|token|digest|apikey|oauth|jwt)\s+/i.test(value)) {
    return "Authorization";
  }
  // Standard 3-part JWT without explicit scheme prefix
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    return "Authorization";
  }
  // Base64-encoded credentials with trailing '=' padding (not a key=value cookie)
  if (/^[A-Za-z0-9+/_-]+={1,2}$/.test(value)) {
    return "Authorization";
  }
  // Cookie pairs (e.g., "session=abc; csrf=123")
  if (/^[A-Za-z0-9_!#$%&'*+.^`|~-]+=/.test(value)) {
    return "Cookie";
  }
  return "Authorization";
}

function parseCredentialInput(rawInput, modeOverride = "auto") {
  if (typeof rawInput !== "string") return null;
  const normalized = rawInput.replace(/[\r\n]+/g, " ").trim();
  if (!normalized) return null;

  const authPrefixMatch = normalized.match(/^authorization\s*:\s*(.+)$/i);
  if (authPrefixMatch) {
    const val = authPrefixMatch[1].trim();
    return val ? { headerName: "Authorization", value: val } : null;
  }

  const cookiePrefixMatch = normalized.match(/^cookie\s*:\s*(.+)$/i);
  if (cookiePrefixMatch) {
    const val = cookiePrefixMatch[1].trim();
    return val ? { headerName: "Cookie", value: val } : null;
  }

  if (modeOverride === "Authorization" || modeOverride === "Cookie") {
    return { headerName: modeOverride, value: normalized };
  }

  return { headerName: detectHeaderType(normalized), value: normalized };
}

function parseUrlPatterns(urlFilter) {
  if (typeof urlFilter !== "string") return [];
  return urlFilter
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function matchesUrlFilter(url, urlFilter) {
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    return false;
  }
  const patterns = parseUrlPatterns(urlFilter);
  if (patterns.length === 0) return false;
  const lowerUrl = url.toLowerCase();
  return patterns.some((pattern) => pattern === "*" || lowerUrl.includes(pattern.toLowerCase()));
}

function isSameOrigin(requestUrl, tabUrl) {
  if (!requestUrl || !tabUrl) return false;
  try {
    return new URL(requestUrl).origin === new URL(tabUrl).origin;
  } catch {
    return false;
  }
}

function formatShortUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return rawUrl;
  }
}

function extractCapturedCredential(headers, headerMode) {
  const authHeader = getHeaderCaseInsensitive(headers, "Authorization");
  const cookieHeader = getHeaderCaseInsensitive(headers, "Cookie");

  if (headerMode === "Authorization") {
    return authHeader ? { headerName: "Authorization", value: authHeader.value } : null;
  }
  if (headerMode === "Cookie") {
    return cookieHeader ? { headerName: "Cookie", value: cookieHeader.value } : null;
  }

  // In Auto mode, prefer Authorization over Cookie so analytics cookies do not mask Bearer tokens.
  if (authHeader) {
    return { headerName: "Authorization", value: authHeader.value };
  }
  if (cookieHeader) {
    return { headerName: "Cookie", value: cookieHeader.value };
  }
  return null;
}

function buildSwappedHeaders(originalHeaders, userBCredential, stripBothAuthHeaders) {
  const result = [];
  const targetLower = userBCredential.headerName.toLowerCase();
  let effectiveValue = userBCredential.value;

  // Preserve "Bearer " scheme if the original request used Bearer and User B pasted a bare token
  if (userBCredential.headerName === "Authorization" && !/\s/.test(effectiveValue)) {
    const origAuth = getHeaderCaseInsensitive(originalHeaders, "Authorization");
    if (origAuth && /^bearer\s+/i.test(origAuth.value)) {
      effectiveValue = `Bearer ${effectiveValue}`;
    }
  }

  if (originalHeaders && typeof originalHeaders === "object") {
    for (const [name, value] of Object.entries(originalHeaders)) {
      if (!name || name.startsWith(":")) continue;
      const lower = name.toLowerCase();
      if (stripBothAuthHeaders && (lower === "authorization" || lower === "cookie")) {
        continue;
      }
      if (!stripBothAuthHeaders && lower === targetLower) {
        continue;
      }
      result.push({ name, value: String(value ?? "") });
    }
  }

  result.push({ name: userBCredential.headerName, value: effectiveValue });
  return result;
}

function recomputeHeaderTypes() {
  const mode = state.headerMode;
  const parsedA = parseCredentialInput(state.userAToken, mode);
  state.userAHeaderType = parsedA ? parsedA.headerName : "";

  const parsedB = parseCredentialInput(state.userBToken, mode);
  state.userBHeaderType = parsedB ? parsedB.headerName : "";
}

function getPublicState() {
  return {
    ...state,
    logs: [...state.logs]
  };
}

function persistState() {
  const snapshot = getPublicState();
  writeQueue = writeQueue
    .then(() => chrome.storage.local.set({ [STORAGE_KEY]: snapshot }))
    .catch((err) => {
      console.warn("[VAPT Proxy] Failed to persist state:", err);
    });
  return writeQueue;
}

function broadcastState() {
  chrome.runtime
    .sendMessage({ type: "STATE_UPDATED", state: getPublicState() })
    .catch(() => {
      // Expected when popup is closed
    });
}

async function updateBadge() {
  try {
    if (!state.interceptionEnabled) {
      await chrome.action.setBadgeText({ text: "" });
      return;
    }
    const isSwapping = Boolean(state.swapEnabled && parseCredentialInput(state.userBToken, resolveUserBMode()));
    await chrome.action.setBadgeText({ text: isSwapping ? "SWAP" : "ON" });
    await chrome.action.setBadgeBackgroundColor({ color: ACCENT_COLOR });
    if (typeof chrome.action.setBadgeTextColor === "function") {
      await chrome.action.setBadgeTextColor({ color: "#FFFFFF" });
    }
  } catch {
    // Ignore badge errors on unsupported contexts
  }
}

function resolveUserBMode() {
  if (state.headerMode === "Authorization" || state.headerMode === "Cookie") {
    return state.headerMode;
  }
  return state.userBHeaderType || "auto";
}

async function ensureStateLoaded() {
  if (!initPromise) {
    initPromise = (async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      if (stored && stored[STORAGE_KEY]) {
        state = {
          ...DEFAULT_STATE,
          ...stored[STORAGE_KEY],
          logs: Array.isArray(stored[STORAGE_KEY].logs) ? stored[STORAGE_KEY].logs : []
        };
      }

      // Reconcile persisted debugger attachment with live Chrome debugger targets after SW restart
      if (state.interceptionEnabled && state.attachedTabId !== null) {
        const targets = await chrome.debugger.getTargets().catch(() => []);
        const stillAttached = targets.some(
          (target) => target.tabId === state.attachedTabId && target.attached
        );
        if (!stillAttached) {
          state.interceptionEnabled = false;
          state.attachedTabId = null;
          state.attachedTabUrl = "";
          await persistState();
        } else {
          try {
            const tab = await chrome.tabs.get(state.attachedTabId);
            if (tab?.url) state.attachedTabUrl = tab.url;
          } catch {
            // Tab may no longer exist; onDetach handles final cleanup
          }
        }
      }

      await updateBadge();
    })();
  }
  return initPromise;
}

function isRestrictedUrl(url) {
  if (!url) return false;
  return /^(chrome|chrome-extension|devtools|edge|about):/i.test(url);
}

async function attachDebugger(tabId, providedUrl = "") {
  if (typeof tabId !== "number" || Number.isNaN(tabId)) {
    throw new Error("No valid active tab selected.");
  }

  let tabUrl = providedUrl;
  if (!tabUrl) {
    const tab = await chrome.tabs.get(tabId);
    tabUrl = tab?.url || "";
  }

  if (isRestrictedUrl(tabUrl)) {
    throw new Error("Cannot attach to restricted browser pages (chrome://). Open an HTTP/HTTPS tab.");
  }

  if (state.interceptionEnabled && state.attachedTabId === tabId) {
    return getPublicState();
  }

  if (state.interceptionEnabled && state.attachedTabId !== null && state.attachedTabId !== tabId) {
    await detachDebugger();
  }

  await chrome.debugger.attach({ tabId }, CDP_VERSION);

  try {
    await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
    await chrome.debugger.sendCommand({ tabId }, "Fetch.enable", {
      patterns: [
        {
          urlPattern: "*",
          requestStage: "Request"
        }
      ]
    });
  } catch (err) {
    await chrome.debugger.detach({ tabId }).catch(() => {});
    throw err;
  }

  requestUrlByNetworkId.clear();
  swappedNetworkIds.clear();

  state.interceptionEnabled = true;
  state.attachedTabId = tabId;
  state.attachedTabUrl = tabUrl;

  // Prevent User A traffic from overwriting an already-loaded User B token when hot-swap starts
  if (state.swapEnabled && state.captureTarget === "userB" && state.userBToken.trim()) {
    state.captureTarget = "off";
  }

  await persistState();
  await updateBadge();
  broadcastState();
  return getPublicState();
}

async function detachDebugger() {
  const previousTabId = state.attachedTabId;

  state.interceptionEnabled = false;
  state.attachedTabId = null;
  state.attachedTabUrl = "";
  requestUrlByNetworkId.clear();
  swappedNetworkIds.clear();

  if (previousTabId !== null) {
    await chrome.debugger.sendCommand({ tabId: previousTabId }, "Fetch.disable", {}).catch(() => {});
    await chrome.debugger.detach({ tabId: previousTabId }).catch(() => {});
  }

  await persistState();
  await updateBadge();
  broadcastState();
  return getPublicState();
}

function maybeCaptureFromHeaders(headers, requestUrl, networkId, options = {}) {
  const { allowUserB = true } = options;
  const targetSlot = state.captureTarget;
  if (targetSlot !== "userA" && targetSlot !== "userB") return;
  if (targetSlot === "userB" && !allowUserB) return;
  if (networkId && swappedNetworkIds.has(networkId)) return;

  const currentSlotEmpty =
    targetSlot === "userA" ? !state.userAToken.trim() : !state.userBToken.trim();
  const matchesFilter = matchesUrlFilter(requestUrl, state.urlFilter);
  const sameOrigin = isSameOrigin(requestUrl, state.attachedTabUrl);

  // Prioritize filter-matched API requests; fall back to same-origin requests only while slot is empty
  if (!matchesFilter && !(sameOrigin && currentSlotEmpty)) {
    return;
  }

  const captured = extractCapturedCredential(headers, state.headerMode);
  if (!captured) return;

  let changed = false;
  if (targetSlot === "userA") {
    if (state.userAToken !== captured.value || state.userAHeaderType !== captured.headerName) {
      state.userAToken = captured.value;
      state.userAHeaderType = captured.headerName;
      changed = true;
    }
  } else if (targetSlot === "userB") {
    if (state.userBToken !== captured.value || state.userBHeaderType !== captured.headerName) {
      state.userBToken = captured.value;
      state.userBHeaderType = captured.headerName;
      changed = true;
    }
  }

  if (changed) {
    persistState();
    updateBadge();
    broadcastState();
  }
}

function recordTrafficLog(entry) {
  state.logs = [entry, ...state.logs].slice(0, MAX_LOGS);
  persistState();
  broadcastState();
}

async function safeContinueRequest(tabId, commandParams) {
  try {
    await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", commandParams);
  } catch (err) {
    const msg = String(err?.message || err);
    if (
      !msg.includes("Invalid InterceptionId") &&
      !msg.includes("Debugger is not attached") &&
      !msg.includes("Cannot find context")
    ) {
      console.warn("[VAPT Proxy] Fetch.continueRequest failed:", msg);
    }
  }
}

async function handleFetchRequestPaused(tabId, params) {
  const { requestId, request, networkId } = params;
  const url = request?.url || "";
  const method = (request?.method || "GET").toUpperCase();
  const headers = request?.headers || {};

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    await safeContinueRequest(tabId, { requestId });
    return;
  }

  const userBCredential = parseCredentialInput(state.userBToken, resolveUserBMode());
  const isSwappingActive = Boolean(state.swapEnabled && userBCredential);

  // Capture pre-tamper headers (never overwrite User B while actively hot-swapping with User B's token)
  maybeCaptureFromHeaders(headers, url, networkId, { allowUserB: !isSwappingActive });

  const isTargetApi = matchesUrlFilter(url, state.urlFilter);
  const canSwapRequest = isSwappingActive && isTargetApi && method !== "OPTIONS";

  if (canSwapRequest) {
    if (networkId) {
      trackBoundedSet(swappedNetworkIds, networkId);
    }
    const swappedHeaders = buildSwappedHeaders(
      headers,
      userBCredential,
      state.stripBothAuthHeaders
    );

    recordTrafficLog({
      id: requestId,
      networkId: networkId || null,
      method,
      path: formatShortUrl(url),
      swapped: true,
      headerName: userBCredential.headerName,
      status: null,
      timestamp: Date.now()
    });

    await safeContinueRequest(tabId, {
      requestId,
      headers: swappedHeaders
    });
    return;
  }

  if (isTargetApi && method !== "OPTIONS") {
    recordTrafficLog({
      id: requestId,
      networkId: networkId || null,
      method,
      path: formatShortUrl(url),
      swapped: false,
      headerName: "",
      status: null,
      timestamp: Date.now()
    });
  }

  await safeContinueRequest(tabId, { requestId });
}

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  await ensureStateLoaded();
  if (!state.interceptionEnabled || source.tabId !== state.attachedTabId) {
    return;
  }

  if (method === "Network.requestWillBeSent") {
    const reqUrl = params.request?.url || "";
    if (params.requestId && reqUrl) {
      trackBoundedMap(requestUrlByNetworkId, params.requestId, reqUrl);
    }
    if (params.type === "Document" && params.documentURL) {
      state.attachedTabUrl = params.documentURL;
    }
    maybeCaptureFromHeaders(params.request?.headers, reqUrl, params.requestId, {
      allowUserB: !(state.swapEnabled && state.userBToken.trim())
    });
    return;
  }

  if (method === "Network.requestWillBeSentExtraInfo") {
    const reqUrl = requestUrlByNetworkId.get(params.requestId) || "";
    maybeCaptureFromHeaders(params.headers, reqUrl, params.requestId, {
      allowUserB: !(state.swapEnabled && state.userBToken.trim())
    });
    return;
  }

  if (method === "Fetch.requestPaused") {
    await handleFetchRequestPaused(source.tabId, params);
    return;
  }

  if (method === "Network.responseReceived") {
    const status = params.response?.status;
    if (params.requestId && typeof status === "number") {
      const idx = state.logs.findIndex((entry) => entry.networkId === params.requestId);
      if (idx !== -1) {
        const updatedLogs = [...state.logs];
        updatedLogs[idx] = { ...updatedLogs[idx], status };
        state.logs = updatedLogs;
        persistState();
        broadcastState();
      }
    }
    return;
  }

  if (method === "Network.loadingFinished" || method === "Network.loadingFailed") {
    if (params.requestId) {
      requestUrlByNetworkId.delete(params.requestId);
      swappedNetworkIds.delete(params.requestId);
    }
  }
});

chrome.debugger.onDetach.addListener(async (source) => {
  await ensureStateLoaded();
  if (source.tabId === state.attachedTabId) {
    state.interceptionEnabled = false;
    state.attachedTabId = null;
    state.attachedTabUrl = "";
    requestUrlByNetworkId.clear();
    swappedNetworkIds.clear();
    await persistState();
    await updateBadge();
    broadcastState();
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await ensureStateLoaded();
  if (tabId === state.attachedTabId) {
    await detachDebugger();
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  await ensureStateLoaded();
  if (tabId === state.attachedTabId && changeInfo.url) {
    state.attachedTabUrl = changeInfo.url;
    await persistState();
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    await ensureStateLoaded();

    switch (message?.type) {
      case "GET_STATE": {
        sendResponse({ ok: true, state: getPublicState() });
        break;
      }

      case "ENABLE_PROXY": {
        try {
          const nextState = await attachDebugger(message.tabId, message.tabUrl);
          sendResponse({ ok: true, state: nextState });
        } catch (err) {
          sendResponse({
            ok: false,
            error: String(err?.message || err),
            state: getPublicState()
          });
        }
        break;
      }

      case "DISABLE_PROXY": {
        const nextState = await detachDebugger();
        sendResponse({ ok: true, state: nextState });
        break;
      }

      case "UPDATE_CONFIG": {
        const patch = message.patch || {};
        const allowedKeys = [
          "userAToken",
          "userBToken",
          "captureTarget",
          "headerMode",
          "urlFilter",
          "swapEnabled",
          "stripBothAuthHeaders"
        ];
        for (const key of allowedKeys) {
          if (Object.prototype.hasOwnProperty.call(patch, key)) {
            state[key] = patch[key];
          }
        }

        // Guard against User A's live traffic overwriting User B when enabling swap
        if (patch.swapEnabled === true && state.captureTarget === "userB" && state.userBToken.trim()) {
          state.captureTarget = "off";
        }

        recomputeHeaderTypes();
        await persistState();
        await updateBadge();
        broadcastState();
        sendResponse({ ok: true, state: getPublicState() });
        break;
      }

      case "SWAP_USER_TOKENS": {
        const prevAToken = state.userAToken;
        const prevAType = state.userAHeaderType;
        state.userAToken = state.userBToken;
        state.userAHeaderType = state.userBHeaderType;
        state.userBToken = prevAToken;
        state.userBHeaderType = prevAType;
        await persistState();
        await updateBadge();
        broadcastState();
        sendResponse({ ok: true, state: getPublicState() });
        break;
      }

      case "CLEAR_LOGS": {
        state.logs = [];
        await persistState();
        broadcastState();
        sendResponse({ ok: true, state: getPublicState() });
        break;
      }

      default:
        sendResponse({ ok: false, error: "Unknown message type." });
    }
  })();

  return true; // Keep message channel open for async response
});
