const BRIDGE_URL = "http://127.0.0.1:47635";

const pairPinInput = document.getElementById("pairPin");
const connectBtn = document.getElementById("connectBtn");
const searchBtn = document.getElementById("searchBtn");
const detectBtn = document.getElementById("detectBtn");
const saveBtn = document.getElementById("saveBtn");
const saveTitleInput = document.getElementById("saveTitle");
const saveUsernameInput = document.getElementById("saveUsername");
const savePasswordInput = document.getElementById("savePassword");
const saveUrlInput = document.getElementById("saveUrl");
const saveGroupInput = document.getElementById("saveGroup");
const statusText = document.getElementById("status");
const sessionInfo = document.getElementById("sessionInfo");
const entriesRoot = document.getElementById("entries");

let sessionTicker = null;

init();

function init() {
  connectBtn.addEventListener("click", onConnectClick);
  searchBtn.addEventListener("click", onSearchClick);
  detectBtn.addEventListener("click", onDetectClick);
  saveBtn.addEventListener("click", onSaveClick);
  preloadActiveUrl();
  checkBridgeHealth();
  setGroupOptions(["General"]);
}

async function onConnectClick() {
  const pin = normalizePin(pairPinInput.value);
  if (!pin) {
    setStatus("Ingresa el PIN temporal de SecretSafe.", true);
    return;
  }

  setStatus("Conectando con SecretSafe...", false);
  try {
    const response = await fetch(`${BRIDGE_URL}/pair/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin })
    });
    const data = await response.json();
    if (!response.ok) {
      setStatus(data.error || "No se pudo conectar.", true);
      return;
    }

    safeSendMessage(
      {
        type: "set-bridge-token",
        token: data.token,
        expiresAtUnix: data.expiresAtUnix
      },
      (result) => {
        if (!result?.ok) {
          setStatus(result?.error || "No se pudo guardar sesión.", true);
          return;
        }
        pairPinInput.value = "";
        startSessionCountdown(result.expiresAt);
        setStatus("Extensión conectada. Ya puedes buscar/autocompletar.", false);
        loadGroups();
      }
    );
  } catch (error) {
    setStatus(`No se pudo conectar al bridge: ${String(error)}`, true);
  }
}

async function onSearchClick() {
  const domain = await getActiveDomain();
  if (!domain) {
    setStatus("No se pudo obtener el dominio activo.", true);
    return;
  }

  setStatus("Buscando secretos...", false);
  entriesRoot.innerHTML = "";

  chrome.runtime.sendMessage({ type: "bridge-search", domain }, (result) => {
    if (!result?.ok) {
      setStatus(result?.error || "No se pudo buscar en SecretSafe.", true);
      return;
    }

    const entries = result.entries || [];
    if (!entries.length) {
      setStatus(`No hay coincidencias para ${domain}.`, false);
      return;
    }
    setStatus(`${entries.length} coincidencia(s) en ${domain}.`, false);
    renderEntries(entries);
  });
}

function onSaveClick() {
  const title = saveTitleInput.value.trim();
  const username = saveUsernameInput.value.trim();
  const password = savePasswordInput.value;
  const url = saveUrlInput.value.trim();
  const group = saveGroupInput.value || "General";
  if (!title) {
    setStatus("Ingresa un título para guardar el secreto.", true);
    return;
  }
  if (!password) {
    setStatus("Ingresa la contraseña que quieres guardar.", true);
    return;
  }

  setStatus("Guardando credenciales en SecretSafe...", false);
  safeSendMessage(
    {
      type: "bridge-save",
      title,
      username,
      password,
      url,
      group
    },
    (result) => {
      if (!result?.ok) {
        setStatus(result?.error || "No se pudo guardar el secreto.", true);
        return;
      }
      setStatus("Credenciales guardadas en SecretSafe.", false);
    }
  );
}

function onDetectClick() {
  setStatus("Detectando credenciales de la página...", false);
  safeSendMessage({ type: "collect-active-tab-credentials" }, (snapshot) => {
    if (!snapshot?.ok) {
      setStatus(snapshot?.error || "No se detectaron credenciales.", true);
      return;
    }
    if (!saveTitleInput.value.trim()) {
      saveTitleInput.value = buildEntryTitle(snapshot.title, snapshot.url);
    }
    if (!saveUsernameInput.value.trim()) {
      saveUsernameInput.value = snapshot.username || "";
    }
    if (!savePasswordInput.value) {
      savePasswordInput.value = snapshot.password || "";
    }
    if (!saveUrlInput.value.trim()) {
      saveUrlInput.value = snapshot.url || "";
    }
    setStatus("Datos detectados. Revisa y pulsa Guardar en SecretSafe.", false);
  });
}

async function checkBridgeHealth() {
  try {
    const response = await fetch(`${BRIDGE_URL}/health`);
    if (!response.ok) {
      setStatus("Bridge local no disponible.", true);
      return;
    }
    safeSendMessage({ type: "bridge-session-status" }, (sessionStatus) => {
      if (sessionStatus?.connected) {
        startSessionCountdown(sessionStatus.expiresAt);
        setStatus("Bridge conectado. Sesión activa.", false);
        loadGroups();
      } else {
        clearSessionCountdown("Sin sesión activa.");
        setStatus("Bridge local conectado. Falta conectar con PIN.", false);
      }
    });
  } catch {
    clearSessionCountdown("Sin sesión activa.");
    setStatus("Bridge local no disponible. Abre SecretSafe.", true);
  }
}

function renderEntries(entries) {
  entriesRoot.innerHTML = "";
  entries.forEach((entry) => {
    const card = document.createElement("div");
    card.className = "entry";

    const title = document.createElement("div");
    title.className = "entry-title";
    title.textContent = entry.title;

    const meta = document.createElement("div");
    meta.className = "entry-meta";
    meta.textContent = `${entry.username || "(sin usuario)"} · ${entry.group || "General"}`;

    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Autocompletar";
    button.addEventListener("click", async () => {
      await fillEntry(entry.id);
    });

    card.appendChild(title);
    card.appendChild(meta);
    card.appendChild(button);
    entriesRoot.appendChild(card);
  });
}

function normalizePin(value) {
  return (value || "").replace(/\s+/g, "").trim();
}

function buildEntryTitle(pageTitle, pageUrl) {
  const cleanTitle = (pageTitle || "").trim();
  if (cleanTitle) return cleanTitle;
  try {
    return new URL(pageUrl).hostname || "Nuevo secreto";
  } catch {
    return "Nuevo secreto";
  }
}

function safeSendMessage(payload, callback) {
  chrome.runtime.sendMessage(payload, (result) => {
    if (chrome.runtime.lastError) {
      callback({ ok: false, error: chrome.runtime.lastError.message });
      return;
    }
    callback(result);
  });
}

function loadGroups() {
  safeSendMessage({ type: "bridge-meta" }, (result) => {
    if (!result?.ok) return;
    const groups = Array.isArray(result.groups) ? result.groups : [];
    setGroupOptions(groups.length ? groups : ["General"]);
  });
}

function setGroupOptions(groups) {
  const previous = saveGroupInput.value;
  saveGroupInput.innerHTML = "";
  groups.forEach((group) => {
    const option = document.createElement("option");
    option.value = group;
    option.textContent = group;
    saveGroupInput.appendChild(option);
  });
  if (previous && groups.includes(previous)) {
    saveGroupInput.value = previous;
  } else if (groups.includes("General")) {
    saveGroupInput.value = "General";
  } else if (groups.length > 0) {
    saveGroupInput.value = groups[0];
  }
}

function preloadActiveUrl() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (chrome.runtime.lastError) return;
    const tabUrl = tabs?.[0]?.url;
    if (!tabUrl) return;
    if (!saveUrlInput.value.trim()) {
      saveUrlInput.value = tabUrl;
    }
    if (!saveTitleInput.value.trim()) {
      try {
        const host = new URL(tabUrl).hostname;
        saveTitleInput.value = host || "Nuevo secreto";
      } catch {
        saveTitleInput.value = "Nuevo secreto";
      }
    }
  });
}

async function fillEntry(entryId) {
  setStatus("Recuperando credenciales...", false);
  chrome.runtime.sendMessage({ type: "bridge-fill", entryId }, (bridgeResult) => {
    if (!bridgeResult?.ok) {
      setStatus(bridgeResult?.error || "No se pudo obtener la credencial.", true);
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "fill-active-tab",
        username: bridgeResult.username,
        password: bridgeResult.password
      },
      (result) => {
        if (!result?.ok) {
          setStatus(result?.error || "No se pudo completar el formulario.", true);
          return;
        }
        setStatus("Formulario completado.", false);
      }
    );
  });
}

function setStatus(message, isError) {
  statusText.textContent = message;
  statusText.style.color = isError ? "#fca5a5" : "#93c5fd";
}

function startSessionCountdown(expiresAtMs) {
  clearSessionInterval();
  if (!expiresAtMs) {
    sessionInfo.textContent = "Sin sesión activa.";
    return;
  }

  const tick = () => {
    const remainingMs = Number(expiresAtMs) - Date.now();
    if (remainingMs <= 0) {
      clearSessionCountdown("Sesión expirada. Conecta con PIN nuevamente.");
      return;
    }
    sessionInfo.textContent = `Sesión activa: expira en ${formatRemaining(remainingMs)}`;
  };

  tick();
  sessionTicker = setInterval(tick, 1000);
}

function clearSessionCountdown(message) {
  clearSessionInterval();
  sessionInfo.textContent = message || "";
}

function clearSessionInterval() {
  if (!sessionTicker) return;
  clearInterval(sessionTicker);
  sessionTicker = null;
}

function formatRemaining(remainingMs) {
  const totalSeconds = Math.max(0, Math.floor(remainingMs / 1000));
  const minutes = Math.floor(totalSeconds / 60)
    .toString()
    .padStart(2, "0");
  const seconds = (totalSeconds % 60).toString().padStart(2, "0");
  return `${minutes}:${seconds}`;
}

function getActiveDomain() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) {
        resolve("");
        return;
      }

      const tab = tabs?.[0];
      if (!tab?.url) {
        resolve("");
        return;
      }

      try {
        const url = new URL(tab.url);
        resolve(url.hostname);
      } catch {
        resolve("");
      }
    });
  });
}
