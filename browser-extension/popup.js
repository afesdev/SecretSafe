const BRIDGE_URL = "http://127.0.0.1:47635";

const pairPinInput = document.getElementById("pairPin");
const connectBtn = document.getElementById("connectBtn");
const searchBtn = document.getElementById("searchBtn");
const statusText = document.getElementById("status");
const sessionInfo = document.getElementById("sessionInfo");
const entriesRoot = document.getElementById("entries");

let sessionTicker = null;

init();

function init() {
  connectBtn.addEventListener("click", onConnectClick);
  searchBtn.addEventListener("click", onSearchClick);
  checkBridgeHealth();
}

async function onConnectClick() {
  const pin = pairPinInput.value.trim();
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

    chrome.runtime.sendMessage(
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

async function checkBridgeHealth() {
  try {
    const response = await fetch(`${BRIDGE_URL}/health`);
    if (!response.ok) {
      setStatus("Bridge local no disponible.", true);
      return;
    }
    chrome.runtime.sendMessage({ type: "bridge-session-status" }, (sessionStatus) => {
      if (sessionStatus?.connected) {
        startSessionCountdown(sessionStatus.expiresAt);
        setStatus("Bridge conectado. Sesión activa.", false);
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
