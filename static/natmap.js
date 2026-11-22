const projectsBySlug = new Map();
const createForm = document.querySelector("[data-create-form]");
const createDialog = document.querySelector("[data-create-dialog]");
const dashboard = document.querySelector("[data-project-dashboard]");
const projectTable = dashboard?.querySelector(".project-table");
const sortForm = dashboard?.querySelector("[data-project-sort]");
const sortSelect = sortForm?.elements.namedItem("mode");
const projectNames = new Intl.Collator("zh-CN", { numeric: true, sensitivity: "base" });
const projectEditor = document.querySelector("[data-project-editor]");
const editorPanel = projectEditor?.querySelector("[data-editor-panel]");
const editorMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
let submittingProject = false;
let editorToggle = null;
let editorPosition = 0;
let editorVelocity = 0;
let editorFrame = 0;
let editNoticeTimer;
let customProjectOrder = [];
let projectSortMode = sortSelect?.value || "custom";
let editingProjectOrder = false;
let savingProjectOrder = false;
let csrfRefresh = null;

async function postProjectForm(url, body, { redirect = "follow" } = {}) {
  const options = { method: "POST", headers: { Accept: "application/json" }, body, redirect };
  const response = await fetch(url, options);
  if (response.status !== 403 || response.headers.get("X-NATMap-CSRF") !== "expired") return response;

  if (!csrfRefresh) {
    csrfRefresh = fetch("/csrf", { cache: "no-store", credentials: "same-origin" }).then(async result => {
      if (!result.ok) throw new Error("无法更新页面会话，请刷新后重试。");
      const { csrf } = await result.json();
      if (typeof csrf !== "string" || !csrf) throw new Error("无法更新页面会话，请刷新后重试。");
      for (const field of document.querySelectorAll('input[type="hidden"][name="csrf"]')) field.value = csrf;
      return csrf;
    }).finally(() => { csrfRefresh = null; });
  }
  body.set("csrf", await csrfRefresh);
  return fetch(url, options);
}

async function copyAddress(value) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
  } catch {
    // Fall back to selection when the browser denies clipboard access.
  }

  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.append(input);
  try {
    input.select();
    if (!document.execCommand("copy")) throw new Error("copy failed");
  } finally {
    input.remove();
  }
}

function bindCopyButton(button) {
  let resetTimer;
  button.addEventListener("click", async () => {
    const address = button.dataset.copyAddress;
    let message;
    try {
      await copyAddress(address);
      message = "已复制";
    } catch {
      message = "复制失败";
    }
    if (button.dataset.copyAddress !== address) return;

    button.textContent = message;
    button.setAttribute("aria-label", `${button.dataset.addressLabel}${message}`);
    window.clearTimeout(resetTimer);
    resetTimer = window.setTimeout(() => {
      button.textContent = "复制";
      button.setAttribute("aria-label", `复制${button.dataset.addressLabel}`);
    }, 2000);
  });
}

function setCopyAddress(button, address, label = button.dataset.addressLabel) {
  if (button.dataset.copyAddress === address && button.dataset.addressLabel === label) return;
  button.dataset.copyAddress = address;
  button.dataset.addressLabel = label;
  button.textContent = "复制";
  button.setAttribute("aria-label", `复制${label}`);
}

function mappingStatus(text) {
  if (text.startsWith("等待本地网页服务")) return "等待网页";
  if (text.startsWith("等待本地服务")) return "等待服务";
  if (text.startsWith("本地端口")) return "检测协议";
  if (text.startsWith("NATMap 正在重连")) return "正在重连";
  if (text.startsWith("固定入口更新暂未确认")) return "入口待重试";
  if (text.startsWith("等待固定入口")) return "更新入口";
  if (!text || text.startsWith("等待公网映射")) return "等待映射";
  return "运行中";
}

function renderConnection(row, panel, text) {
  const phase = row.querySelector("[data-state]");
  const label = phase.dataset.state === "运行中" ? mappingStatus(text) : phase.dataset.state;
  if (phase.textContent !== label) phase.textContent = label;
  phase.toggleAttribute("data-waiting", label !== phase.dataset.state);
  phase.title = label === "入口待重试" ? text.split("\n", 1)[0] : "";

  const detail = panel.querySelector("[data-detail]") || row.querySelector("[data-detail]");
  const rdp = row.hasAttribute("data-rdp");
  if (detail.dataset.detailText === text && detail.dataset.rdp === String(rdp)) return;
  detail.dataset.detailText = text;
  detail.dataset.rdp = String(rdp);
  const direct = row.querySelector("[data-direct-address]");
  const lines = text.split("\n").filter(Boolean);

  if (direct) {
    const mapped = lines.find(line => /^直连地址\s+\S+$/.test(line))?.replace(/^直连地址\s+/, "") || "";
    const manager = row.hasAttribute("data-manager-target");
    const address = manager ? mapped.replace(/^https:\/\//, "") : mapped;
    direct.hidden = !address;
    row.querySelector("[data-direct-empty]").hidden = Boolean(address);
    const link = direct.querySelector("[data-direct-link]");
    const web = /^https?:\/\//.test(address);
    const command = rdp && /^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(address) ? `mstsc /v:${address}` : "";
    if (web) link.href = address;
    else link.removeAttribute("href");
    link.title = command || address;
    link.toggleAttribute("data-rdp-link", Boolean(command));
    if (command) {
      const endpoint = document.createElement("span");
      endpoint.textContent = address;
      link.replaceChildren("mstsc /v:", endpoint);
    } else link.textContent = address;
    setCopyAddress(direct.querySelector("[data-copy-address]"), command || address,
      command ? "远程桌面命令" : manager ? "公网映射地址" : "直连地址");
    const commandPanel = panel.querySelector("[data-rdp-command]");
    if (commandPanel) {
      commandPanel.hidden = !command;
      commandPanel.querySelector("[data-rdp-command-text]").textContent = command;
      setCopyAddress(commandPanel.querySelector("[data-copy-address]"), command);
    }
    detail.textContent = lines.filter(line => !/^(固定入口|直连地址)\s+\S+$/.test(line)).join("\n");
    detail.hidden = !detail.textContent;
    return;
  }

  // The running manager may still have the previous card template cached.
  detail.hidden = lines.length === 0;
  const rows = lines.map(line => {
    const lineRow = document.createElement("span");
    lineRow.className = "connection-row";
    const label = document.createElement("span");
    label.className = "connection-text";
    label.textContent = line;
    lineRow.append(label);

    const match = line.match(/^(固定入口|直连地址)\s+(https?:\/\/\S+)$/);
    if (match) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-address";
      button.textContent = "复制";
      button.dataset.addressLabel = match[1];
      button.dataset.copyAddress = match[2];
      button.setAttribute("aria-label", `复制${match[1]}`);
      button.setAttribute("aria-live", "polite");
      bindCopyButton(button);
      lineRow.append(button);
    }
    return lineRow;
  });
  detail.replaceChildren(...rows);
}

function moveEditor(target) {
  window.cancelAnimationFrame(editorFrame);
  let previousTime = performance.now();
  const damping = 13;
  const frequency = 12;
  const width = target || editorWidth();

  function render() {
    dashboard.style.setProperty("--editor-space", `${Math.max(0, editorPosition)}px`);
    dashboard.style.setProperty("--editor-return-offset", `${Math.max(0, -editorPosition) * .45}px`);
    dashboard.style.setProperty("--editor-reveal", Math.min(1, Math.max(0, editorPosition / width)));
  }

  function settle() {
    editorPosition = target;
    editorVelocity = 0;
    render();
    if (target === 0) {
      projectEditor.hidden = true;
      dashboard.removeAttribute("data-editor-open");
    }
  }

  function advance(time) {
    const elapsed = Math.max(0, (time - previousTime) / 1000);
    previousTime = time;
    // Analytic damped spring step. Retargeting keeps both position and velocity.
    const offset = editorPosition - target;
    const amplitude = (editorVelocity + damping * offset) / frequency;
    const cosine = Math.cos(frequency * elapsed);
    const sine = Math.sin(frequency * elapsed);
    const motion = offset * cosine + amplitude * sine;
    const decay = Math.exp(-damping * elapsed);
    editorPosition = target + decay * motion;
    editorVelocity = decay * (frequency * (amplitude * cosine - offset * sine) - damping * motion);

    if (Math.abs(editorPosition - target) < .25 && Math.abs(editorVelocity) < 4) {
      settle();
    } else {
      render();
      editorFrame = window.requestAnimationFrame(advance);
    }
  }

  if (editorMotion.matches) settle();
  else {
    render();
    editorFrame = window.requestAnimationFrame(advance);
  }
}

function editorWidth() {
  return editorPanel.getBoundingClientRect().width + parseFloat(getComputedStyle(editorPanel).marginInlineStart);
}

function setEditorSelected(toggle, selected) {
  toggle.setAttribute("aria-expanded", String(selected));
  toggle.textContent = selected ? "收起" : "管理";
  toggle.closest("[data-project]").toggleAttribute("data-editing", selected);
}

function openProjectEditor(toggle) {
  const panel = document.getElementById(toggle.getAttribute("aria-controls"));
  const first = !editorToggle;
  if (editorToggle) setEditorSelected(editorToggle, false);
  const previous = editorPanel.querySelector("[data-project-panel]:not([hidden])");
  if (previous) previous.hidden = true;
  editorToggle = toggle;
  setEditorSelected(toggle, true);
  panel.hidden = false;
  projectEditor.hidden = false;
  projectEditor.inert = false;
  dashboard.setAttribute("data-editor-open", "");
  editorPanel.scrollTop = 0;
  if (first) moveEditor(editorWidth());
  else if (!editorMotion.matches) {
    panel.animate(
      [{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "translateY(0)" }],
      { duration: 240, easing: "cubic-bezier(.2, .75, .25, 1)" },
    );
  }
  panel.querySelector('input[name="name"]').focus({ preventScroll: true });
}

function closeProjectEditor() {
  const toggle = editorToggle;
  if (!toggle) return;
  editorToggle = null;
  setEditorSelected(toggle, false);
  toggle.focus({ preventScroll: true });
  projectEditor.inert = true;
  moveEditor(0);
}

async function saveProjectEditor(event) {
  const form = event.target;
  if (!form.matches("[data-edit-form], [data-note-form]")) return;
  const submit = form.querySelector('button[type="submit"]');
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  const error = form.querySelector("[data-edit-error]");
  error.hidden = true;
  const body = new FormData(form);
  try {
    const response = await postProjectForm(form.action, body);
    const result = await response.json();
    if (!response.ok) {
      error.textContent = result.message || "配置未保存，请重试。";
      error.hidden = false;
      error.scrollIntoView({ block: "nearest" });
      return;
    }
    const note = form.elements.namedItem("note");
    if (note) {
      if (note.value === body.get("note")) note.value = result.note;
      showProjectNotice(result.message);
      return;
    }
    const project = projectsBySlug.get(form.elements.namedItem("slug").value);
    const name = project.row.querySelector("[data-project-name]");
    name.textContent = result.name;
    name.title = result.name;
    project.panel.querySelector("[data-editor-project]").textContent = result.name;
    const managerUsername = form.elements.namedItem("manager_username");
    if (managerUsername) managerUsername.value = managerUsername.value.trim();
    const managerPassword = form.elements.namedItem("manager_password");
    if (managerPassword) managerPassword.value = "";
    displayProjectOrder();
    showProjectNotice(result.message);
  } catch {
    error.textContent = "保存失败，请重试。";
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
}

function showProjectNotice(message) {
  const notice = dashboard.querySelector("[data-edit-notice]");
  notice.textContent = message;
  notice.hidden = false;
  window.clearTimeout(editNoticeTimer);
  editNoticeTimer = window.setTimeout(() => { notice.hidden = true; }, 5000);
}

async function submitMappingAction(event) {
  const form = event.target;
  const button = event.submitter;
  if (!form.matches(".project-actions, [data-batch-actions]") || !button) return;
  event.preventDefault();
  if (form.hasAttribute("data-submitting")) return;
  const action = button.getAttribute("formaction") || form.action;
  const body = new FormData(form, button);
  form.setAttribute("data-submitting", "");
  button.disabled = true;
  let navigating = false;
  try {
    // Keep Flask's flash messages for the dashboard navigation, not the fetch.
    const response = await postProjectForm(action, body, { redirect: "manual" });
    if (response.type === "opaqueredirect") {
      window.location.assign(dashboard.dataset.dashboardUrl);
      navigating = true;
      return;
    }
    const result = await response.json().catch(() => null);
    showProjectNotice(result?.message || "未能确认操作结果，请查看项目状态。");
  } catch (error) {
    showProjectNotice(error.message || "未能确认操作结果，请查看项目状态。");
  } finally {
    if (!navigating) {
      form.removeAttribute("data-submitting");
      button.disabled = false;
    }
  }
}

dashboard?.addEventListener("submit", submitMappingAction);

function syncProxyOrigin(form) {
  const field = form.querySelector("[data-proxy-origin]");
  if (field) field.hidden = form.elements.namedItem("web_mode").value !== "proxy";
}

async function saveWebAccess(event) {
  const form = event.target;
  if (!form.matches("[data-web-access-form]")) return;
  event.preventDefault();
  const fields = form.querySelector("fieldset");
  if (fields.disabled) return;
  const body = new FormData(form);
  const button = form.querySelector('button[type="submit"]');
  const error = form.querySelector("[data-web-access-error]");
  fields.disabled = true;
  button.textContent = "正在更新 Pages…";
  error.hidden = true;
  try {
    const response = await postProjectForm(form.action, body);
    const result = await response.json();
    if (!response.ok) throw new Error(result.message);
    showProjectNotice(result.message);
  } catch (failure) {
    error.textContent = failure.message || "固定入口更新失败，请重试。";
    error.hidden = false;
  } finally {
    fields.disabled = false;
    button.textContent = "应用入口方式";
  }
}

function displayProjectOrder() {
  if (!sortForm || editingProjectOrder) return;
  const rows = customProjectOrder.map(slug => projectsBySlug.get(slug).row);
  const heading = projectTable.querySelector("[data-name-heading]");
  if (projectSortMode === "custom") {
    heading.removeAttribute("aria-sort");
  } else {
    const ascending = projectSortMode === "name-asc";
    heading.setAttribute("aria-sort", ascending ? "ascending" : "descending");
    rows.sort((first, second) => {
      const firstName = first.querySelector("[data-project-name]").textContent;
      const secondName = second.querySelector("[data-project-name]").textContent;
      return projectNames.compare(firstName, secondName) * (ascending ? 1 : -1);
    });
  }
  const groups = rows.map(row => row.closest("tbody"));
  if (groups.some((group, index) => projectTable.tBodies[index] !== group)) {
    projectTable.append(...groups);
  }
}

function updateProjectOrderControls() {
  if (!sortForm) return;
  const groups = Array.from(projectTable.tBodies);
  sortForm.hidden = groups.length < 2;
  sortSelect.disabled = editingProjectOrder || savingProjectOrder;
  const edit = sortForm.querySelector("[data-edit-order]");
  edit.hidden = projectSortMode !== "custom" || editingProjectOrder;
  edit.disabled = savingProjectOrder;
  for (const name of ["save", "cancel"]) {
    const button = sortForm.querySelector(`[data-${name}-order]`);
    button.hidden = !editingProjectOrder;
    button.disabled = savingProjectOrder;
  }
  groups.forEach((group, index) => {
    const controls = group.querySelector("[data-order-controls]");
    controls.hidden = !editingProjectOrder;
    controls.querySelector('[data-move-project="up"]').disabled = savingProjectOrder || index === 0;
    controls.querySelector('[data-move-project="down"]').disabled = savingProjectOrder || index === groups.length - 1;
  });
}

function editProjectOrder(editing) {
  editingProjectOrder = editing;
  dashboard.querySelector("[data-sort-error]").hidden = true;
  displayProjectOrder();
  updateProjectOrderControls();
  const focus = editing
    ? projectTable.querySelector("[data-move-project]:enabled")
    : sortForm.querySelector("[data-edit-order]");
  focus?.focus({ preventScroll: true });
}

async function saveProjectOrder(mode, order) {
  if (savingProjectOrder) return;
  savingProjectOrder = true;
  const error = dashboard.querySelector("[data-sort-error]");
  error.hidden = true;
  updateProjectOrderControls();
  const body = new URLSearchParams({ csrf: sortForm.elements.namedItem("csrf").value, mode });
  order?.forEach(slug => body.append("order", slug));
  try {
    const response = await postProjectForm(sortForm.action, body);
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "无法保存排序，请重试。");
    projectSortMode = result.mode;
    if (order) {
      customProjectOrder = [...order, ...customProjectOrder.filter(slug => !order.includes(slug))];
      editingProjectOrder = false;
      showProjectNotice("项目顺序已保存。");
    }
    displayProjectOrder();
  } catch (failure) {
    error.textContent = failure.message || "无法保存排序，请重试。";
    error.hidden = false;
  } finally {
    savingProjectOrder = false;
    sortSelect.value = projectSortMode;
    updateProjectOrderControls();
    if (order && !editingProjectOrder) sortForm.querySelector("[data-edit-order]").focus({ preventScroll: true });
  }
}

function showRemoteLink(panel, link) {
  const remote = panel.querySelector("[data-remote-link]");
  if (!remote) return;
  remote.hidden = !link;
  if (link) {
    remote.querySelector("a").href = link;
    setCopyAddress(remote.querySelector("[data-copy-address]"), link);
  }
}

function showLookupStatus(element, message) {
  if (!element) return;
  const text = message || "";
  if (element.textContent !== text) element.textContent = text;
  element.hidden = !text;
}

function bindProjectRow(row) {
  const toggle = row.querySelector("[data-manage-toggle]");
  const panel = document.getElementById(toggle?.getAttribute("aria-controls") || `more-${row.dataset.project}`) || row;
  toggle?.addEventListener("click", () => {
    if (editorToggle === toggle) closeProjectEditor();
    else openProjectEditor(toggle);
  });
  projectsBySlug.set(row.dataset.project, { row, panel });
  customProjectOrder.push(row.dataset.project);
  row.querySelectorAll("[data-copy-address]").forEach(bindCopyButton);
  if (panel !== row) panel.querySelectorAll("[data-copy-address]").forEach(bindCopyButton);
  const detail = panel.querySelector("[data-detail]") || row.querySelector("[data-detail]");
  renderConnection(row, panel, detail.textContent);
}

document.querySelectorAll("[data-project]").forEach(bindProjectRow);

if (sortForm) {
  displayProjectOrder();
  updateProjectOrderControls();
  sortSelect.addEventListener("change", () => saveProjectOrder(sortSelect.value));
  sortForm.querySelector("[data-edit-order]").addEventListener("click", () => editProjectOrder(true));
  sortForm.querySelector("[data-cancel-order]").addEventListener("click", () => editProjectOrder(false));
  sortForm.addEventListener("submit", event => {
    event.preventDefault();
    if (!editingProjectOrder) return;
    const order = Array.from(projectTable.tBodies, group => group.rows[0].dataset.project);
    saveProjectOrder("custom", order);
  });
  projectTable.addEventListener("click", event => {
    const button = event.target.closest("[data-move-project]");
    if (!button || button.disabled || !editingProjectOrder || savingProjectOrder) return;
    const group = button.closest("tbody");
    if (button.dataset.moveProject === "up") projectTable.insertBefore(group, group.previousElementSibling);
    else projectTable.insertBefore(group.nextElementSibling, group);
    updateProjectOrderControls();
    const focus = button.disabled ? group.querySelector("[data-move-project]:enabled") : button;
    focus?.focus({ preventScroll: true });
  });
}

if (projectEditor) {
  projectEditor.addEventListener("click", event => {
    if (event.target.closest("[data-close-editor]")) closeProjectEditor();
  });
  projectEditor.addEventListener("submit", saveProjectEditor);
  projectEditor.addEventListener("submit", saveWebAccess);
  projectEditor.addEventListener("change", event => {
    if (event.target.name === "web_mode") syncProxyOrigin(event.target.form);
    if (event.target.name === "scheme") syncSharedEntryField(event.target.form, event.target.value === "tcp");
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && editorToggle && !createDialog?.open) {
      event.preventDefault();
      closeProjectEditor();
    }
  });
  window.addEventListener("resize", () => {
    if (editorToggle) moveEditor(editorWidth());
  });
  const initialToggle = document.querySelector("[data-show-editor]");
  if (initialToggle) openProjectEditor(initialToggle);
}

function setCreatePending(pending) {
  createForm.toggleAttribute("data-pending", pending);
  createForm.querySelector("[data-create-fields]").disabled = pending;
  const submit = createForm.querySelector("[data-create-submit]");
  submit.disabled = pending;
  submit.textContent = pending ? "创建中…" : "创建项目";
  const close = createForm.querySelector("[data-close-create]");
  if (close) close.textContent = pending ? "关闭" : "取消";
}

function clearCreateIssue() {
  for (const issue of createForm.querySelectorAll("[data-create-error]")) {
    issue.hidden = true;
    issue.textContent = "";
  }
  for (const field of createForm.querySelectorAll("[aria-invalid]")) field.removeAttribute("aria-invalid");
}

function showCreateIssue(field, message) {
  const error = document.getElementById(`create-error-${field}`) || document.getElementById("create-error-form");
  error.textContent = message;
  error.hidden = false;
  const input = createForm.elements.namedItem(field);
  if (input) {
    input.setAttribute("aria-invalid", "true");
    const details = input.closest("details");
    if (details) details.open = true;
    if (createDialog?.open) input.focus();
  }
}

function setDraftSlug(slug) {
  createForm.dataset.draft = slug;
  createForm.elements.namedItem("draft").value = slug;
}

function syncSharedEntryField(form, tcp) {
  const field = form.querySelector("[data-shared-entry-field]");
  if (!field) return "";
  field.hidden = !tcp;
  const select = field.querySelector("select");
  select.disabled = !tcp;
  return tcp ? select.value : "";
}

function syncCreateProtocol() {
  const optionalEntry = createForm.querySelector("[data-tcp-entry-optional]");
  if (!optionalEntry) return;
  const manager = createForm.elements.namedItem("target_kind")?.value === "manager";
  const tcp = !manager && createForm.elements.namedItem("scheme").value === "tcp";
  const slug = createForm.elements.namedItem("slug");
  const shared = Boolean(syncSharedEntryField(createForm, tcp));
  optionalEntry.hidden = !tcp;
  slug.required = !tcp;
  slug.disabled = shared;
  createForm.querySelector("[data-create-slug]").hidden = shared;
  const managerFields = createForm.querySelector("[data-manager-settings]");
  if (managerFields) {
    managerFields.hidden = !manager;
    managerFields.disabled = !manager;
    const serviceFields = createForm.querySelector("[data-service-settings]");
    serviceFields.hidden = manager;
    serviceFields.disabled = manager;
    createForm.querySelector("[data-create-target-port]").hidden = manager;
    createForm.elements.namedItem("target_port").disabled = manager;
  }
  const webAccess = createForm.querySelector("[data-create-web-access]");
  if (webAccess) {
    webAccess.hidden = tcp || manager;
    webAccess.disabled = tcp || manager;
    syncProxyOrigin(createForm);
  }
  createForm.elements.namedItem("target_port").placeholder = tcp ? "3389" : "5000";
}

if (createDialog) {
  syncCreateProtocol();
  createForm.elements.namedItem("scheme").addEventListener("change", syncCreateProtocol);
  createForm.elements.namedItem("shared_entry")?.addEventListener("change", syncCreateProtocol);
  createForm.elements.namedItem("target_kind")?.addEventListener("change", syncCreateProtocol);
  createForm.elements.namedItem("web_mode")?.addEventListener("change", () => syncProxyOrigin(createForm));
  const open = document.querySelector("[data-open-create]");
  open.addEventListener("click", event => {
    if (event.button || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    createDialog.showModal();
  });
  createDialog.querySelector("[data-close-create]").addEventListener("click", () => createDialog.close());
  if (createDialog.hasAttribute("data-open")) {
    createDialog.showModal();
    createDialog.addEventListener("close", () => {
      window.history.replaceState(null, "", createForm.dataset.dashboardUrl);
    }, { once: true });
  }
  createForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (createForm.hasAttribute("data-pending")) return;
    const body = new FormData(createForm);
    clearCreateIssue();
    submittingProject = true;
    setCreatePending(true);
    try {
      const response = await postProjectForm(createForm.action, body);
      const result = await response.json();
      if (response.ok && result.draft) {
        setDraftSlug(result.draft);
      } else {
        setCreatePending(false);
        showCreateIssue(result.field || "form", result.message || "创建未完成，请重试。");
      }
    } catch {
      setCreatePending(false);
      showCreateIssue("form", "无法提交项目，请刷新页面后重试。");
    } finally {
      submittingProject = false;
    }
  });
}

async function refreshProjectList(slug) {
  const response = await fetch(createForm.dataset.dashboardUrl, { cache: "no-store" });
  if (!response.ok) throw new Error("Unable to refresh project list");
  const latest = new DOMParser().parseFromString(await response.text(), "text/html");
  const drafts = document.querySelector("[data-project-drafts]");
  const latestDrafts = latest.querySelector("[data-project-drafts]");
  drafts.replaceChildren(...latestDrafts.children);
  drafts.hidden = latestDrafts.hidden;

  if (!slug || projectsBySlug.has(slug)) return;
  const row = latest.getElementById(`project-${slug}`);
  const panel = latest.getElementById(`manage-${slug}`);
  if (!row || !panel) throw new Error("Created project is missing from the list");
  const list = document.querySelector("[data-project-list]");
  list.querySelector("table").append(row.closest("tbody"));
  editorPanel.append(panel);
  list.hidden = false;
  document.querySelector("[data-empty-projects]").hidden = true;
  const batchActions = dashboard.querySelector("[data-batch-actions]");
  if (batchActions) batchActions.hidden = false;
  bindProjectRow(row);
  displayProjectOrder();
  updateProjectOrderControls();
}

async function updateCreateForm(projects) {
  if (submittingProject || !createForm?.hasAttribute("data-pending")) return;
  const draft = projects.find(project => project.slug === createForm.dataset.draft);
  if (!draft || draft.busy) return;
  if (draft.ready ?? Boolean(draft.entry)) {
    if (!createDialog) {
      if (createForm.dataset.returnUrl) window.location.replace(createForm.dataset.returnUrl);
      else window.location.reload();
      return;
    }
    await refreshProjectList(draft.slug);
    setDraftSlug("");
    for (const name of ["name", "slug", "target_port", "bind_port"]) createForm.elements.namedItem(name).value = "";
    createForm.elements.namedItem("scheme").value = "auto";
    createForm.elements.namedItem("shared_entry").value = "";
    const targetKind = createForm.elements.namedItem("target_kind");
    if (targetKind) {
      targetKind.value = "service";
      const managerUsername = createForm.elements.namedItem("manager_username");
      managerUsername.value = managerUsername.dataset.defaultValue;
      createForm.elements.namedItem("manager_password").value = "";
    }
    const webMode = createForm.elements.namedItem("web_mode");
    if (webMode) {
      webMode.value = "redirect";
      createForm.elements.namedItem("proxy_origin").value = "";
    }
    syncCreateProtocol();
    const host = createForm.elements.namedItem("target_host");
    if (host) host.value = "127.0.0.1";
    createForm.querySelector(".advanced-settings").open = false;
    setCreatePending(false);
    if (createDialog.open) {
      createDialog.close();
      projectsBySlug.get(draft.slug).row.querySelector("[data-run]").focus();
    }
    return;
  }
  setCreatePending(false);
  showCreateIssue(draft.error_field || "form", draft.detail || "创建未完成，请重新提交。");
  if (createDialog) await refreshProjectList();
}

let sharedEntryOptions = "";
function updateSharedEntryOptions(projects) {
  const entries = projects.filter(project => project.can_share_entry);
  const signature = JSON.stringify(entries.map(({ slug, name, entry }) => [slug, name, entry]));
  if (signature === sharedEntryOptions) return;
  sharedEntryOptions = signature;
  for (const select of document.querySelectorAll('select[name="shared_entry"]')) {
    const saved = select.value;
    const options = entries
      .filter(project => project.slug !== select.dataset.exclude)
      .map(project => new Option(`${project.name} · ${project.entry.replace(/^https:\/\//, "")}`, project.slug));
    select.replaceChildren(select.options[0].cloneNode(), ...options);
    if (options.some(option => option.value === saved)) select.value = saved;
  }
  if (createForm) syncCreateProtocol();
}

async function updateStatus() {
  try {
    const response = await fetch("/status", { cache: "no-store" });
    if (!response.ok) return;
    const projects = await response.json();
    updateSharedEntryOptions(projects);
    await updateCreateForm(projects);
    for (const project of projects) {
      const elements = projectsBySlug.get(project.slug);
      if (!elements) continue;
      const { row, panel } = elements;
      const state = row.querySelector("[data-state]");
      state.dataset.state = project.phase;
      row.querySelector("[data-run]").hidden = project.busy;
      row.querySelector("[data-stop]").hidden = !["运行中", "正在重启"].includes(project.phase);
      panel.querySelector("[data-delete]").disabled = project.busy;
      const targetPort = row.querySelector("[data-target-port]");
      if (targetPort) {
        const endpoint = project.display_target_endpoint ?? project.display_target_port ?? project.target_port;
        targetPort.textContent = endpoint;
        targetPort.title = endpoint;
      }
      row.querySelector("[data-local-port]").textContent = project.local_port ?? "自动分配";
      const scheme = row.querySelector("[data-scheme]");
      if (scheme) scheme.title = scheme.textContent = project.scheme_label ?? project.scheme.toUpperCase();
      row.toggleAttribute("data-rdp", Boolean(project.rdp));
      const webAccess = panel.querySelector("[data-web-access]");
      if (webAccess) webAccess.hidden = project.tcp;
      const remoteLink = project.remote_link ? new URL("/", project.remote_link).href : "";
      const fixedLink = remoteLink && project.fixed_link === project.remote_link ? remoteLink : project.fixed_link;
      const fixed = row.querySelector("[data-fixed-entry]");
      if (fixed) {
        const link = fixed.querySelector("a");
        const button = fixed.querySelector("[data-copy-address]");
        const pending = fixed.querySelector("[data-fixed-pending]");
        fixed.hidden = !project.entry;
        row.querySelector("[data-fixed-empty]").hidden = !fixed.hidden;
        const hostname = project.entry.replace(/^https:\/\//, "");
        if (link.textContent !== hostname) link.textContent = hostname;
        if (fixedLink) {
          link.href = fixedLink;
          link.title = project.supports_remote_lookup ? "打开连接地址页" : fixedLink;
          setCopyAddress(button, fixedLink);
        } else if (pending) {
          link.removeAttribute("href");
          link.removeAttribute("title");
        }
        if (pending) {
          button.hidden = !fixedLink;
          showLookupStatus(pending, project.remote_lookup_status);
        }
      }
      const lookup = panel.querySelector("[data-remote-lookup]");
      if (lookup) {
        lookup.hidden = !project.supports_remote_lookup;
        showRemoteLink(panel, remoteLink);
        showLookupStatus(lookup.querySelector("[data-remote-link-status]"), project.remote_lookup_status);
        showLookupStatus(lookup.querySelector("[data-remote-link-error]"), project.remote_lookup_error);
      }
      const pending = panel.querySelector("[data-changes-pending]") || row.querySelector("[data-changes-pending]");
      if (pending) pending.hidden = !project.changes_pending || project.phase === "正在重启";
      renderConnection(row, panel, project.detail || "");
      const log = panel.querySelector("[data-log]");
      const text = project.logs || "暂无日志。";
      if (log.textContent !== text) log.textContent = text;
    }
  } catch {
    // Keep the last status visible while the local server reconnects.
  } finally {
    if (projectsBySlug.size || createForm) window.setTimeout(updateStatus, 2000);
  }
}

if (projectsBySlug.size || createForm) window.setTimeout(updateStatus, 2000);
