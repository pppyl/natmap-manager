const statusText = document.querySelector("#status");
const command = document.querySelector("#command");
const openApp = document.querySelector("#open-app");
const appFallback = document.querySelector("#app-fallback");
const copy = document.querySelector("#copy");
const copyAddress = document.querySelector("#copy-address");
const isAndroid = /\bAndroid\b/i.test(navigator.userAgent);

function setConnectionAddress(address) {
  command.textContent = address ? (openApp ? `mstsc /v:${address}` : address) : "—";
  statusText.dataset.state = address ? "available" : "offline";
  copy.disabled = !address;
  if (openApp) {
    openApp.disabled = copyAddress.disabled = !address;
    if (!address) appFallback.hidden = true;
  }
}

function appUrl(address) {
  if (isAndroid) {
    // Android rebuilds the Microsoft RDP URI from these path segments.
    // The ignored final argument absorbs the slash required after the address segment.
    return `android-app://com.microsoft.rdc.androidx/rdp/full%20address=s:${address}&natmap=s:/`;
  }
  return `rdp://full%20address=${encodeURIComponent(`s:${address}`)}`;
}

async function getAddress() {
  if (openApp) openApp.disabled = copyAddress.disabled = true;
  else copy.disabled = true;
  try {
    const response = await fetch("/_natmap/remote", { cache: "no-store" });
    if (!response.ok) {
      statusText.textContent = openApp ? "远程桌面暂未同步或已离线。" : "TCP 服务的公网地址暂未同步或已离线。";
      setConnectionAddress("");
      return "";
    }
    const address = await response.text();
    const match = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(address);
    if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535 ||
        match[1].split(".").some(octet => Number(octet) > 255)) {
      throw new Error("Invalid address");
    }
    setConnectionAddress(address);
    statusText.textContent = "已获取当前连接地址。";
    return address;
  } catch {
    setConnectionAddress("");
    statusText.textContent = "暂时无法获取地址，刷新页面后重试。";
    return "";
  }
}

function openWindowsApp(address, fallback) {
  const link = fallback.querySelector("a");
  link.href = appUrl(address);
  fallback.hidden = false;
  if (navigator.userActivation?.isActive === false) {
    statusText.textContent = "已获取最新地址，请点击下方链接打开 Windows App。";
    return;
  }
  statusText.textContent = "正在打开 Windows App。";
  link.click();
}

openApp?.addEventListener("click", async () => {
  appFallback.hidden = true;
  statusText.textContent = "正在获取最新连接地址…";
  const address = await getAddress();
  if (address) openWindowsApp(address, appFallback);
});

async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    statusText.textContent = message;
  } catch {
    statusText.textContent = "复制失败，可以手动选中地址或命令复制。";
  }
}

copyAddress?.addEventListener("click", async () => {
  const address = await getAddress();
  if (address) await copyText(address, "连接地址已复制，请粘贴到 Windows App 的「电脑名称」。");
});

copy?.addEventListener("click", async () => {
  if (openApp) {
    await copyText(command.textContent, "连接命令已复制。");
  } else {
    const address = await getAddress();
    if (address) await copyText(address, "连接地址已复制。");
  }
});

async function fetchDevices() {
  const response = await fetch("/_natmap/tcp-devices", { cache: "no-store" });
  if (!response.ok) throw new Error("Device directory unavailable");
  return response.json();
}

function showDevice(card, device) {
  card.querySelector("[data-device-name]").textContent = device.name;
  const note = card.querySelector("[data-device-note]");
  note.textContent = device.note || "";
  note.hidden = !note.textContent;
  const state = card.querySelector("[data-device-state]");
  const label = { available: "已同步", pending: "待同步", expired: "地址已过期", invalid: "等待 TCP 地址" };
  state.dataset.state = device.address ? "available" : device.state || "pending";
  state.textContent = label[state.dataset.state] || label.pending;
  card.querySelector("[data-device-address]").textContent = device.address
    ? (device.rdp ? `mstsc /v:${device.address}` : device.address) : "—";
  for (const button of card.querySelectorAll("button[data-action]")) {
    button.disabled = !device.address || card.hasAttribute("data-working");
    button.hidden = button.dataset.action !== "copy-address" && !device.rdp;
  }
  const fallback = card.querySelector("[data-device-fallback]");
  if (!fallback.hidden) {
    if (device.address && device.rdp) fallback.querySelector("a").href = appUrl(device.address);
    else fallback.hidden = true;
  }
}

function bindDirectory(container) {
  const template = document.querySelector("#device-card");
  const refresh = document.querySelector("#refresh-devices");
  const downloads = document.querySelector("#device-app-downloads");
  const cards = new Map();
  let currentDevices = new Map();
  let loading = null;

  function render(devices) {
    currentDevices = new Map(devices.map(device => [device.id, device]));
    downloads.hidden = !devices.some(device => device.rdp);
    for (const [index, device] of devices.entries()) {
      let card = cards.get(device.id);
      if (!card) {
        card = template.content.firstElementChild.cloneNode(true);
        card.dataset.deviceId = device.id;
        cards.set(device.id, card);
      }
      showDevice(card, device);
      if (container.children[index] !== card) container.insertBefore(card, container.children[index] ?? null);
    }
    for (const [id, card] of cards) {
      if (!currentDevices.has(id)) {
        card.remove();
        cards.delete(id);
      }
    }
  }

  function refreshDirectory() {
    if (!loading) {
      refresh.disabled = true;
      loading = fetchDevices().then(render).finally(() => {
        loading = null;
        refresh.disabled = false;
      });
    }
    return loading;
  }

  async function update(silent = false) {
    try {
      await refreshDirectory();
      if (!silent) {
        statusText.textContent = currentDevices.size ? "已获取实例连接地址。" : "暂无实例，请在管理页运行 TCP 项目。";
      }
    } catch {
      if (!silent) statusText.textContent = "暂时无法获取实例，请重试。";
    }
  }

  container.addEventListener("click", async event => {
    const button = event.target.closest("button[data-action]");
    if (!button || button.disabled) return;
    const card = button.closest("[data-device-id]");
    if (card.hasAttribute("data-working")) return;
    const fallback = card.querySelector("[data-device-fallback]");
    fallback.hidden = true;
    card.setAttribute("data-working", "");
    button.disabled = true;
    try {
      await refreshDirectory();
      const device = currentDevices.get(card.dataset.deviceId);
      if (!device) {
        statusText.textContent = "该实例已移出共享入口。";
        return;
      }
      if (!device.address) {
        statusText.textContent = "该实例暂无有效的公网连接地址。";
        return;
      }
      if (button.dataset.action === "open-app" && device.rdp) {
        openWindowsApp(device.address, fallback);
      } else if (button.dataset.action === "copy-command" && device.rdp) {
        await copyText(`mstsc /v:${device.address}`, "连接命令已复制。");
      } else {
        await copyText(device.address, "连接地址已复制。");
      }
    } catch {
      statusText.textContent = "暂时无法获取连接地址，请重试。";
    } finally {
      card.removeAttribute("data-working");
      const device = currentDevices.get(card.dataset.deviceId);
      if (device) showDevice(card, device);
    }
  });

  function refreshIfVisible() {
    if (!document.hidden) update(true);
  }

  refresh.addEventListener("click", () => update());
  document.addEventListener("visibilitychange", refreshIfVisible);
  window.setInterval(refreshIfVisible, 20000);
  update();
}

const devices = document.querySelector("#devices");
if (devices) bindDirectory(devices);
else getAddress();
