const BRIDGE_URL = "http://127.0.0.1:47635";
let bridgeSession = null;
const BRIDGE_SESSION_KEY = "secretsafe-bridge-session";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message?.type) return false;

  if (message.type === "set-bridge-token") {
    const { token, expiresAtUnix } = message;
    if (!token || !expiresAtUnix) {
      sendResponse({ ok: false, error: "Faltan datos de sesión." });
      return false;
    }

    bridgeSession = {
      token,
      expiresAt: Number(expiresAtUnix) * 1000
    };
    saveBridgeSession(bridgeSession, () => {
      sendResponse({ ok: true, expiresAt: bridgeSession.expiresAt });
    });
    return false;
  }

  if (message.type === "bridge-session-status") {
    withActiveSession((session) => {
      sendResponse({
        ok: true,
        connected: !!session,
        expiresAt: session?.expiresAt || null
      });
    });
    return true;
  }

  if (message.type === "bridge-search") {
    withActiveSession((session) => {
      if (!session) {
        sendResponse({ ok: false, error: "Sesión no activa. Abre el popup y autentica." });
        return;
      }

      fetch(`${BRIDGE_URL}/vault/search`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: session.token,
          domain: message.domain || ""
        })
      })
        .then(async (response) => {
          const data = await response.json();
          if (!response.ok) {
            sendResponse({ ok: false, error: data.error || "No se pudo buscar." });
            return;
          }
          sendResponse({ ok: true, entries: data.entries || [] });
        })
        .catch((error) => sendResponse({ ok: false, error: String(error) }));
    });
    return true;
  }

  if (message.type === "bridge-fill") {
    withActiveSession((session) => {
      if (!session) {
        sendResponse({ ok: false, error: "Sesión no activa. Abre el popup y autentica." });
        return;
      }

      fetch(`${BRIDGE_URL}/vault/fill`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: session.token,
          entryId: message.entryId || ""
        })
      })
        .then(async (response) => {
          const data = await response.json();
          if (!response.ok) {
            sendResponse({ ok: false, error: data.error || "No se pudo cargar secreto." });
            return;
          }
          sendResponse({
            ok: true,
            username: data.username || "",
            password: data.password || ""
          });
        })
        .catch((error) => sendResponse({ ok: false, error: String(error) }));
    });
    return true;
  }

  if (message.type === "fill-active-tab") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (!activeTab?.id) {
        sendResponse({ ok: false, error: "No se encontró pestaña activa." });
        return;
      }

      chrome.tabs.sendMessage(
        activeTab.id,
        {
          type: "fill-credentials",
          username: message.username || "",
          password: message.password || ""
        },
        (response) => {
          if (chrome.runtime.lastError) {
            sendResponse({ ok: false, error: chrome.runtime.lastError.message });
            return;
          }
          sendResponse(response || { ok: true });
        }
      );
    });
    return true;
  }

  return false;
});

function getActiveSession() {
  if (!bridgeSession) return null;
  if (Date.now() > bridgeSession.expiresAt) {
    bridgeSession = null;
    clearBridgeSession();
    return null;
  }
  return bridgeSession;
}

function withActiveSession(callback) {
  const memorySession = getActiveSession();
  if (memorySession) {
    callback(memorySession);
    return;
  }

  chrome.storage.local.get(BRIDGE_SESSION_KEY, (result) => {
    const stored = result?.[BRIDGE_SESSION_KEY];
    if (!stored?.token || !stored?.expiresAt) {
      callback(null);
      return;
    }

    if (Date.now() > Number(stored.expiresAt)) {
      clearBridgeSession(() => callback(null));
      return;
    }

    bridgeSession = {
      token: stored.token,
      expiresAt: Number(stored.expiresAt)
    };
    callback(bridgeSession);
  });
}

function saveBridgeSession(session, onDone) {
  chrome.storage.local.set(
    {
      [BRIDGE_SESSION_KEY]: {
        token: session.token,
        expiresAt: session.expiresAt
      }
    },
    () => onDone?.()
  );
}

function clearBridgeSession(onDone) {
  chrome.storage.local.remove(BRIDGE_SESSION_KEY, () => onDone?.());
}
