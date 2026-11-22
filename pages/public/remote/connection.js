const statusText = document.querySelector("#status");
const command = document.querySelector("#command");
const openApp = document.querySelector("#open-app");
const appFallback = document.querySelector("#app-fallback");
const appLink = document.querySelector("#app-link");
const copy = document.querySelector("#copy");
const copyAddress = document.querySelector("#copy-address");
const isAndroid = /\bAndroid\b/i.test(navigator.userAgent);

function setConnectionAddress(address) {
  command.textContent = address ? `mstsc /v:${address}` : "—";
  statusText.dataset.state = address ? "available" : "offline";
  copy.disabled = openApp.disabled = copyAddress.disabled = !address;
  if (!address) appFallback.hidden = true;
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
  openApp.disabled = copyAddress.disabled = true;
  try {
    const response = await fetch("/_natmap/remote", { cache: "no-store" });
    if (!response.ok) {
      statusText.textContent = "远程桌面暂未同步或已离线。";
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

openApp.addEventListener("click", async () => {
  appFallback.hidden = true;
  statusText.textContent = "正在获取最新连接地址…";
  const address = await getAddress();
  if (!address) return;
  appLink.href = appUrl(address);
  appFallback.hidden = false;
  if (navigator.userActivation?.isActive === false) {
    statusText.textContent = "已获取最新地址，请点击下方链接打开 Windows App。";
    return;
  }
  statusText.textContent = "正在打开 Windows App。";
  appLink.click();
});

async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    statusText.textContent = message;
  } catch {
    statusText.textContent = "复制失败，可以手动选中地址或命令复制。";
  }
}

copyAddress.addEventListener("click", async () => {
  const address = await getAddress();
  if (address) await copyText(address, "连接地址已复制，请粘贴到 Windows App 的「电脑名称」。");
});

copy.addEventListener("click", () => copyText(command.textContent, "连接命令已复制。"));

getAddress();
