function findUsernameInput() {
  const candidates = Array.from(
    document.querySelectorAll("input[type='text'], input[type='email'], input:not([type])")
  );

  return candidates.find((input) => {
    const label = `${input.name || ""} ${input.id || ""} ${input.autocomplete || ""}`.toLowerCase();
    return (
      label.includes("user") ||
      label.includes("mail") ||
      label.includes("login") ||
      input.autocomplete === "username"
    );
  });
}

function findPasswordInput() {
  return document.querySelector("input[type='password']");
}

function findUsernameInputFor(passwordInput) {
  const scope = passwordInput?.form || document;
  const candidates = Array.from(
    scope.querySelectorAll("input[type='text'], input[type='email'], input:not([type])")
  );
  return candidates.find((input) => {
    const label = `${input.name || ""} ${input.id || ""} ${input.autocomplete || ""}`.toLowerCase();
    return (
      label.includes("user") ||
      label.includes("mail") ||
      label.includes("login") ||
      input.autocomplete === "username"
    );
  });
}

let suggestionBox = null;
let currentPasswordInput = null;

document.addEventListener("focusin", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || target.type !== "password") return;
  currentPasswordInput = target;
  requestSuggestions(target);
});

document.addEventListener("click", (event) => {
  if (!suggestionBox) return;
  if (event.target instanceof Node && suggestionBox.contains(event.target)) return;
  removeSuggestionBox();
});

function requestSuggestions(passwordInput) {
  safeSendMessage(
    {
      type: "bridge-search",
      domain: window.location.hostname
    },
    (response) => {
      if (!response?.ok || !Array.isArray(response.entries) || !response.entries.length) {
        removeSuggestionBox();
        return;
      }
      showSuggestionBox(passwordInput, response.entries.slice(0, 5));
    }
  );
}

function showSuggestionBox(passwordInput, entries) {
  removeSuggestionBox();
  const rect = passwordInput.getBoundingClientRect();
  const box = document.createElement("div");
  box.style.position = "fixed";
  box.style.zIndex = "2147483647";
  box.style.left = `${rect.left}px`;
  box.style.top = `${rect.bottom + 6}px`;
  box.style.minWidth = `${Math.max(rect.width, 240)}px`;
  box.style.maxWidth = "420px";
  box.style.border = "1px solid #334155";
  box.style.background = "#0f172a";
  box.style.color = "#e2e8f0";
  box.style.boxShadow = "0 8px 22px rgba(0,0,0,.35)";
  box.style.fontFamily = "Inter, Segoe UI, sans-serif";
  box.style.fontSize = "12px";

  const title = document.createElement("div");
  title.textContent = "SecretSafe sugerencias";
  title.style.padding = "8px 10px";
  title.style.borderBottom = "1px solid #334155";
  title.style.color = "#93c5fd";
  title.style.fontWeight = "700";
  box.appendChild(title);

  entries.forEach((entry) => {
    const item = document.createElement("button");
    item.type = "button";
    item.style.display = "block";
    item.style.width = "100%";
    item.style.textAlign = "left";
    item.style.border = "0";
    item.style.background = "transparent";
    item.style.color = "inherit";
    item.style.padding = "8px 10px";
    item.style.cursor = "pointer";
    item.onmouseenter = () => (item.style.background = "#1e293b");
    item.onmouseleave = () => (item.style.background = "transparent");
    item.textContent = `${entry.title} - ${entry.username || "(sin usuario)"}`;
    item.addEventListener("click", () => fillFromEntry(entry.id));
    box.appendChild(item);
  });

  document.documentElement.appendChild(box);
  suggestionBox = box;
}

function fillFromEntry(entryId) {
  safeSendMessage({ type: "bridge-fill", entryId }, (response) => {
    if (!response?.ok || !currentPasswordInput) return;
    const usernameInput = findUsernameInputFor(currentPasswordInput);
    if (usernameInput) {
      usernameInput.focus();
      usernameInput.value = response.username || "";
      usernameInput.dispatchEvent(new Event("input", { bubbles: true }));
      usernameInput.dispatchEvent(new Event("change", { bubbles: true }));
    }
    currentPasswordInput.focus();
    currentPasswordInput.value = response.password || "";
    currentPasswordInput.dispatchEvent(new Event("input", { bubbles: true }));
    currentPasswordInput.dispatchEvent(new Event("change", { bubbles: true }));
    removeSuggestionBox();
  });
}

function safeSendMessage(payload, onSuccess) {
  if (!chrome?.runtime?.sendMessage) return;
  try {
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) return;
      onSuccess(response);
    });
  } catch (_error) {
    // Ignoramos errores de páginas en navegación/cierre de sesión.
  }
}

function removeSuggestionBox() {
  if (!suggestionBox) return;
  suggestionBox.remove();
  suggestionBox = null;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "fill-credentials") {
    return false;
  }

  const usernameInput = findUsernameInput();
  const passwordInput = findPasswordInput();

  if (!usernameInput && !passwordInput) {
    sendResponse({ ok: false, error: "No se detectaron campos para completar." });
    return false;
  }

  if (usernameInput) {
    usernameInput.focus();
    usernameInput.value = message.username || "";
    usernameInput.dispatchEvent(new Event("input", { bubbles: true }));
    usernameInput.dispatchEvent(new Event("change", { bubbles: true }));
  }

  if (passwordInput) {
    passwordInput.focus();
    passwordInput.value = message.password || "";
    passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
    passwordInput.dispatchEvent(new Event("change", { bubbles: true }));
  }

  sendResponse({ ok: true });
  return false;
});
