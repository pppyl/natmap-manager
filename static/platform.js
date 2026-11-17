const loginButton = document.querySelector("[data-login-button]");
const loginMessage = document.querySelector("[data-login-message]");
const loginLink = document.querySelector("[data-login-link]");
const discoverButton = document.querySelector("[data-discover-button]");
const choicesForm = document.querySelector("[data-connection-choices]");
const choicesSelect = document.querySelector("[data-connection-select]");
const profiles = document.querySelector("[data-platform-profiles]");
let profileRevision = Number(profiles?.dataset.revision || 0);
let choicesSignature = "";

async function updateLoginStatus() {
  try {
    const response = await fetch("/platform/login/status", { cache: "no-store" });
    if (!response.ok) return;
    const { login, wrangler } = await response.json();
    const busy = ["starting", "waiting", "configuring"].includes(login.phase);
    loginButton.disabled = busy;
    if (discoverButton) discoverButton.disabled = busy;
    loginButton.textContent = wrangler.status === "已登录" ? "重新登录 Cloudflare" : "登录 Cloudflare";
    loginMessage.textContent = login.message;
    loginMessage.hidden = !login.message;
    loginMessage.classList.toggle("auth-error", login.phase === "error");
    if (login.url) loginLink.href = login.url;
    loginLink.hidden = !login.url;

    if (choicesForm && choicesSelect) {
      const choices = login.choices || [];
      const signature = JSON.stringify(choices);
      if (signature !== choicesSignature) {
        const selected = choicesSelect.value;
        choicesSelect.replaceChildren(...choices.map(choice => {
          const option = document.createElement("option");
          option.value = choice.value;
          option.textContent = choice.label;
          return option;
        }));
        if (choices.some(choice => choice.value === selected)) choicesSelect.value = selected;
        choicesSignature = signature;
      }
      choicesForm.hidden = login.phase !== "choose" || choices.length === 0;
    }
    if (profiles && login.revision !== undefined && login.revision !== profileRevision) {
      const listResponse = await fetch("/platform/profiles", { cache: "no-store" });
      if (listResponse.ok) {
        profiles.innerHTML = await listResponse.text();
        profileRevision = login.revision;
      }
    }

    document.querySelector("[data-wrangler-status]").textContent = wrangler.status;
    document.querySelector("[data-wrangler-expiry]").textContent = wrangler.expires_at;
    document.querySelector("[data-expiry-row]").hidden = !wrangler.expires_at;
    const list = document.querySelector("[data-wrangler-scopes]");
    list.replaceChildren(...wrangler.scopes.map(scope => {
      const item = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = scope;
      item.append(code);
      if (wrangler.labels[scope]) {
        const label = document.createElement("span");
        label.textContent = wrangler.labels[scope];
        item.append(label);
      }
      return item;
    }));
    document.querySelector("[data-no-scopes]").hidden = wrangler.scopes.length > 0;
  } catch {
    // Keep the last status visible while the local manager is unavailable.
  } finally {
    window.setTimeout(updateLoginStatus, 2000);
  }
}

window.setTimeout(updateLoginStatus, 1000);
