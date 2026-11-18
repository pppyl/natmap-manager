const loginButton = document.querySelector("[data-login-button]");
const loginForm = loginButton.form;
const loginMessage = document.querySelector("[data-login-message]");
const loginLink = document.querySelector("[data-login-link]");
const discoverButton = document.querySelector("[data-discover-button]");
const choicesForm = document.querySelector("[data-connection-choices]");
const choicesSelect = document.querySelector("[data-connection-select]");
const profiles = document.querySelector("[data-platform-profiles]");
let profileRevision = Number(profiles?.dataset.revision || 0);
let choicesSignature = "";
let loginPoll;
let loginGeneration = 0;
let submittingLogin = false;
let loginRequestError = "";

function showLoginState(login, wranglerStatus) {
  const busy = ["starting", "waiting", "configuring"].includes(login.phase);
  if (busy) loginRequestError = "";
  const message = loginRequestError || login.message;
  loginButton.disabled = busy;
  discoverButton.disabled = busy;
  if (login.phase === "starting") loginButton.textContent = "正在准备…";
  else if (login.phase === "waiting") loginButton.textContent = "等待授权…";
  else loginButton.textContent = wranglerStatus === "已登录" ? "重新登录 Cloudflare" : "登录 Cloudflare";
  loginMessage.textContent = message;
  loginMessage.hidden = !message;
  loginMessage.classList.toggle("auth-error", Boolean(loginRequestError) || login.phase === "error");
  if (login.url) loginLink.href = login.url;
  else loginLink.removeAttribute("href");
  loginLink.hidden = !login.url;
}

async function updateLoginStatus() {
  const generation = loginGeneration;
  let delay = 2000;
  try {
    const response = await fetch("/platform/login/status", { cache: "no-store" });
    if (!response.ok) return;
    const { login, wrangler } = await response.json();
    if (generation !== loginGeneration) return;
    showLoginState(login, wrangler.status);
    if (login.phase === "starting") delay = 350;
    else if (login.phase === "waiting" || login.phase === "configuring") delay = 750;

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
        const html = await listResponse.text();
        if (generation !== loginGeneration) return;
        profiles.innerHTML = html;
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
    if (generation === loginGeneration) loginPoll = window.setTimeout(updateLoginStatus, delay);
  }
}

loginForm.addEventListener("submit", async event => {
  event.preventDefault();
  if (submittingLogin || loginButton.disabled) return;
  submittingLogin = true;
  loginGeneration++;
  window.clearTimeout(loginPoll);
  const discover = event.submitter === discoverButton;
  const currentStatus = document.querySelector("[data-wrangler-status]").textContent;
  showLoginState({
    phase: discover ? "configuring" : "starting",
    message: discover ? "正在获取 Cloudflare 账号和数据库。" : "正在准备 Wrangler，首次使用需要下载登录工具。",
  }, currentStatus);
  try {
    const response = await fetch(discover ? discoverButton.formAction : loginForm.action, {
      method: "POST", headers: { Accept: "application/json" }, body: new FormData(loginForm),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "无法开始授权，请重试。");
    showLoginState(result.login, result.wrangler.status);
  } catch (error) {
    loginRequestError = error.message || "无法开始授权，请重试。";
    showLoginState({ phase: "error", message: loginRequestError }, currentStatus);
  } finally {
    submittingLogin = false;
    loginPoll = window.setTimeout(updateLoginStatus, 350);
  }
});

loginPoll = window.setTimeout(updateLoginStatus, 350);
