const statusText = document.querySelector("#status");
const connection = document.querySelector("#connection");
const command = document.querySelector("#command");
const download = document.querySelector("#download");
const copy = document.querySelector("#copy");

async function getAddress() {
  try {
    const response = await fetch("/_natmap/remote", { cache: "no-store" });
    if (!response.ok) {
      statusText.textContent = "远程桌面暂未同步或已离线。";
      connection.hidden = true;
      return "";
    }
    const address = await response.text();
    if (!/^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(address)) throw new Error("Invalid address");
    command.textContent = `mstsc /v:${address}`;
    statusText.textContent = "已获取当前连接地址。";
    connection.hidden = false;
    return address;
  } catch {
    connection.hidden = true;
    statusText.textContent = "暂时无法获取地址，刷新页面后重试。";
    return "";
  }
}

download.addEventListener("click", async () => {
  download.disabled = true;
  try {
    const address = await getAddress();
    if (!address) return;
    const file = new Blob([`full address:s:${address}\r\nprompt for credentials:i:1\r\n`], {
      type: "application/x-rdp",
    });
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = "远程桌面.rdp";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } finally {
    download.disabled = false;
  }
});

copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(command.textContent);
    statusText.textContent = "连接命令已复制。";
  } catch {
    statusText.textContent = "复制失败，可以手动选中命令复制。";
  }
});

getAddress();
