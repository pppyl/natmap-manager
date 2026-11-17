const projectsBySlug = new Map();
const createForm = document.querySelector("[data-create-form]");
const createDialog = document.querySelector("[data-create-dialog]");
const dashboard = document.querySelector("[data-project-dashboard]");
const projectEditor = document.querySelector("[data-project-editor]");
const editorPanel = projectEditor?.querySelector("[data-editor-panel]");
const editorMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
let submittingProject = false;
let editorToggle = null;
let editorPosition = 0;
let editorVelocity = 0;
let editorFrame = 0;
let editNoticeTimer;

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
  const label = button.dataset.addressLabel;
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
    button.setAttribute("aria-label", `${label}${message}`);
    window.clearTimeout(resetTimer);
    resetTimer = window.setTimeout(() => {
      button.textContent = "复制";
      button.setAttribute("aria-label", `复制${label}`);
    }, 2000);
  });
}

function mappingStatus(text) {
  if (text.startsWith("等待本地网页服务")) return "等待网页";
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

  const detail = panel.querySelector("[data-detail]") || row.querySelector("[data-detail]");
  if (detail.dataset.detailText === text) return;
  detail.dataset.detailText = text;
  const direct = row.querySelector("[data-direct-address]");
  const lines = text.split("\n").filter(Boolean);

  if (direct) {
    const address = lines.find(line => /^直连地址\s+https?:\/\/\S+$/.test(line))?.replace(/^直连地址\s+/, "") || "";
    direct.hidden = !address;
    row.querySelector("[data-direct-empty]").hidden = Boolean(address);
    const link = direct.querySelector("[data-direct-link]");
    if (address) link.href = address;
    else link.removeAttribute("href");
    link.title = address;
    link.textContent = address;
    const button = direct.querySelector("[data-copy-address]");
    if (button.dataset.copyAddress !== address) {
      button.dataset.copyAddress = address;
      button.textContent = "复制";
      button.setAttribute("aria-label", "复制直连地址");
    }
    detail.textContent = lines.filter(line => !/^(固定入口|直连地址)\s+https?:\/\/\S+$/.test(line)).join("\n");
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
  if (!form.matches("[data-edit-form]")) return;
  const submit = form.querySelector('button[type="submit"]');
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  const error = form.querySelector("[data-edit-error]");
  error.hidden = true;
  try {
    const response = await fetch(form.action, {
      method: "POST", headers: { Accept: "application/json" }, body: new FormData(form),
    });
    const result = await response.json();
    if (!response.ok) {
      error.textContent = result.message || "配置未保存，请重试。";
      error.hidden = false;
      error.scrollIntoView({ block: "nearest" });
      return;
    }
    const project = projectsBySlug.get(form.elements.namedItem("slug").value);
    const name = project.row.querySelector("[data-project-name]");
    name.textContent = result.name;
    name.title = result.name;
    project.panel.querySelector("[data-editor-project]").textContent = result.name;
    const notice = document.querySelector("[data-edit-notice]");
    notice.textContent = result.message;
    notice.hidden = false;
    window.clearTimeout(editNoticeTimer);
    editNoticeTimer = window.setTimeout(() => { notice.hidden = true; }, 5000);
  } catch {
    error.textContent = "无法保存配置，请重试。";
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
}

function bindProjectRow(row) {
  const toggle = row.querySelector("[data-manage-toggle]");
  const panel = document.getElementById(toggle?.getAttribute("aria-controls") || `more-${row.dataset.project}`) || row;
  toggle?.addEventListener("click", () => {
    if (editorToggle === toggle) closeProjectEditor();
    else openProjectEditor(toggle);
  });
  projectsBySlug.set(row.dataset.project, { row, panel });
  row.querySelectorAll("[data-copy-address]").forEach(bindCopyButton);
  const detail = panel.querySelector("[data-detail]") || row.querySelector("[data-detail]");
  renderConnection(row, panel, detail.textContent);
}

document.querySelectorAll("[data-project]").forEach(bindProjectRow);

if (projectEditor) {
  projectEditor.addEventListener("click", event => {
    if (event.target.closest("[data-close-editor]")) closeProjectEditor();
  });
  projectEditor.addEventListener("submit", saveProjectEditor);
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

if (createDialog) {
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
      const response = await fetch(createForm.action, {
        method: "POST",
        headers: { Accept: "application/json" },
        body,
      });
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
  bindProjectRow(row);
}

async function updateCreateForm(projects) {
  if (submittingProject || !createForm?.hasAttribute("data-pending")) return;
  const draft = projects.find(project => project.slug === createForm.dataset.draft);
  if (!draft || draft.busy) return;
  if (draft?.entry) {
    if (!createDialog) {
      if (createForm.dataset.returnUrl) window.location.replace(createForm.dataset.returnUrl);
      else window.location.reload();
      return;
    }
    await refreshProjectList(draft.slug);
    setDraftSlug("");
    for (const name of ["name", "slug", "target_port", "bind_port"]) createForm.elements.namedItem(name).value = "";
    createForm.elements.namedItem("scheme").value = "auto";
    const host = createForm.elements.namedItem("target_host");
    if (host) host.selectedIndex = 0;
    createForm.querySelector(".advanced-settings").open = false;
    setCreatePending(false);
    if (createDialog.open) {
      createDialog.close();
      projectsBySlug.get(draft.slug).row.querySelector(".entry").focus();
    }
    return;
  }
  setCreatePending(false);
  showCreateIssue(draft.error_field || "form", draft.detail || "创建未完成，请重新提交。");
  if (createDialog) await refreshProjectList();
}

async function updateStatus() {
  try {
    const response = await fetch("/status", { cache: "no-store" });
    if (!response.ok) return;
    const projects = await response.json();
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
      if (targetPort) targetPort.textContent = project.display_target_endpoint ?? project.display_target_port ?? project.target_port;
      row.querySelector("[data-local-port]").textContent = project.local_port ?? "自动分配";
      const scheme = row.querySelector("[data-scheme]");
      if (scheme) scheme.title = scheme.textContent = project.scheme_label ?? project.scheme.toUpperCase();
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
