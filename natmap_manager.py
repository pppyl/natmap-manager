"""Local web controls for the Windows NATMap publisher."""

from argparse import ArgumentTypeError, Namespace
from collections import deque
from dataclasses import asdict, dataclass, field, replace
import hmac
from ipaddress import ip_address
import json
from pathlib import Path
from secrets import token_hex, token_urlsafe
import socket
from threading import Event, Lock, RLock, Thread
from time import monotonic
from urllib.parse import urlsplit
import webbrowser

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.serving import make_server

from data_storage import PROJECTS_FILE, ensure_data
from duckdns_natmap import DEFAULT_NATMAP, DEFAULT_TARGET_HOST, MAPPING_SCHEMES, RDP_PORT, SETTINGS_FILE, normalize_target_host, port, run_locked_mapping, save_access_address, target_endpoint
from pages_projects import CloudflareError, LOGIN_COMMAND, PAGES_HOST, PROJECT_NAME, PagesNameUnavailable, PagesProjects, WranglerLogin, cloudflare_request, discover_cloudflare_connections, project_token
from platform_settings import AUTH_LABELS, PlatformProfile, PlatformSettings, pages_config, wrangler_login_status, write_json


ADMIN_PORT = 8765
ADMIN_URL = f"http://127.0.0.1:{ADMIN_PORT}/"
REMOTE_LOOKUP_RETRY_SECONDS = 60
PROJECT_SORT_MODES = ("custom", "name-asc", "name-desc")


class ProjectInputError(ValueError):
    def __init__(self, field, message):
        super().__init__(message)
        self.field = field


def project_port(value, field):
    try:
        return port(value)
    except (ArgumentTypeError, ValueError) as error:
        raise ProjectInputError(field, "请输入 1 到 65535 之间的整数。") from error


def project_settings(values):
    bind_port = values["bind_port"].strip()
    return {
        "name": values["name"].strip(),
        "target_host": values.get("target_host", DEFAULT_TARGET_HOST),
        "target_port": project_port(values["target_port"], "target_port"),
        "bind_port": project_port(bind_port, "bind_port") if bind_port else None,
        "scheme": values["scheme"],
    }


@dataclass(frozen=True)
class Project:
    slug: str
    name: str
    target_port: int
    bind_port: int | None = None
    scheme: str = "http"
    entry: str = ""
    owner: str = ""
    target_host: str = DEFAULT_TARGET_HOST
    rdp_lookup_ready: bool = False

    def __post_init__(self):
        if not PROJECT_NAME.fullmatch(self.slug):
            raise ProjectInputError("slug", "子域名长度为 1 到 40，使用小写英文字母、数字或连字符，首尾不能为连字符。")
        if not self.name.strip() or len(self.name) > 60:
            raise ProjectInputError("name", "请填写项目名称，最多 60 个字。")
        try:
            object.__setattr__(self, "target_host", normalize_target_host(self.target_host))
        except ValueError as error:
            raise ProjectInputError("target_host", str(error)) from error
        project_port(self.target_port, "target_port")
        if self.bind_port is not None:
            project_port(self.bind_port, "bind_port")
        if self.target_is_loopback and self.target_port == ADMIN_PORT:
            raise ProjectInputError("target_port", f"端口 {ADMIN_PORT} 正由本机管理页使用。")
        if self.bind_port == ADMIN_PORT:
            raise ProjectInputError("bind_port", f"端口 {ADMIN_PORT} 正由本机管理页使用。")
        if self.target_is_loopback and self.target_port == self.bind_port:
            raise ProjectInputError("bind_port", "NATMap 本地端口必须与本机服务端口不同。")
        if self.scheme not in MAPPING_SCHEMES:
            raise ProjectInputError("scheme", "请选择自动检测、HTTP、HTTPS 或 TCP。")
        if self.entry:
            host = urlsplit(self.entry).netloc
            if not PAGES_HOST.fullmatch(host) or self.entry != f"https://{host}":
                raise ValueError("项目入口必须是有效的 HTTPS Pages 网址。")

    @property
    def target_is_loopback(self):
        return ip_address(self.target_host).is_loopback

    @property
    def ready(self):
        return bool(self.entry) or self.scheme == "tcp"

    @property
    def supports_remote_lookup(self):
        return bool(self.entry and self.owner) and self.target_port == RDP_PORT and self.scheme in ("auto", "tcp")

    @property
    def remote_link(self):
        return f"{self.entry}/" if self.supports_remote_lookup and self.rdp_lookup_ready else ""


@dataclass
class Task:
    phase: str
    project: Project
    platform: PlatformProfile | None = None
    bind_port: int | None = None
    thread: Thread | None = None
    stop: Event = field(default_factory=Event)
    logs: deque = field(default_factory=lambda: deque(maxlen=40))
    detail: str = ""
    error_field: str = ""
    detected_scheme: str = ""


@dataclass
class RemoteLookup:
    thread: Thread | None = None
    retry_at: float = 0
    error: str = ""


class Manager:
    def __init__(self, settings_file=SETTINGS_FILE, projects_file=PROJECTS_FILE):
        if settings_file == SETTINGS_FILE:
            ensure_data()
        self.settings_file = settings_file
        self.projects_file = projects_file
        self.platforms = PlatformSettings(settings_file.with_name("platforms.json"))
        settings = self.read_settings()
        self.default_slug = None
        self.default_project = None
        entry = settings["redirect"].get("url")
        if entry:
            entry = entry.rstrip("/")
            parsed = urlsplit(entry)
            if not PAGES_HOST.fullmatch(parsed.netloc) or entry != f"https://{parsed.netloc}":
                raise ValueError("settings.json 中的 Pages 固定网址无效。")
            self.default_slug = parsed.netloc.removesuffix(".pages.dev")
            self.default_project = Project(
                self.default_slug, "本地网页服务", port(settings.get("target_port", 21580)),
                port(settings.get("bind_port", 21581)), entry=entry,
                target_host=settings.get("target_host", DEFAULT_TARGET_HOST),
            )
        self.projects = {}
        self.removed_owners = {}
        self.sort_mode = "custom"
        if projects_file.is_file():
            records = json.loads(projects_file.read_text(encoding="utf-8"))
            if isinstance(records, dict):
                self.removed_owners = dict(records.get("removed_owners", {}))
                if records.get("sort_mode") in PROJECT_SORT_MODES:
                    self.sort_mode = records["sort_mode"]
                records = records["projects"]
            for data in records:
                data.pop("rdp_lookup_key", None)
                project = Project(**data)
                self.projects[project.slug] = project
        self.tasks = {}
        self.remote_lookups = {}
        self.lock = RLock()
        self.provision_lock = Lock()
        self.wrangler_login = WranglerLogin(self.configure_cloudflare)
        self.closing = Event()

    def configure_cloudflare(self, selection=None):
        token, connections = discover_cloudflare_connections()
        for connection in connections:
            connection["value"] = f'{connection["account_id"]}:{connection["database_id"]}'

        if selection is not None:
            selected = next((item for item in connections if item["value"] == selection), None)
            if selected is None:
                raise CloudflareError("账号或数据库已变化，请重新获取连接配置。")
        else:
            preferred = []
            profiles, default_id = self.platforms.snapshot()
            preferred.extend(row["database_id"] for row in profiles if row["id"] == default_id)
            preferred.extend(row.get("database_id") for row in pages_config().get("d1_databases", []))
            matching = [row for row in connections if row["database_id"] and row["database_id"] in preferred]
            if len(matching) == 1:
                selected = matching[0]
            elif len(connections) == 1:
                selected = connections[0]
            else:
                choices = [{
                    "value": row["value"],
                    "label": f'{row["account_name"]} · {row["database_name"] or "创建 NATMap 数据库"}',
                } for row in connections]
                return {"message": "已登录，请选择要使用的账号和数据库。", "choices": choices}

        if self.closing.is_set():
            raise CloudflareError("管理程序正在关闭，请重新获取连接配置。")
        if not selected["database_id"]:
            response = cloudflare_request(
                token, f'/accounts/{selected["account_id"]}/d1/database',
                method="POST", payload={"name": "natmap-redirect"},
            )
            database = response["result"]
            selected["database_id"] = database["uuid"]
            selected["database_name"] = database["name"]
        if self.closing.is_set():
            raise CloudflareError("管理程序正在关闭，请重新获取连接配置。")
        updated = self.platforms.ensure_discovered(
            selected["account_id"], selected["database_id"], selected["database_name"],
        )
        return {"message": "Cloudflare 已登录，连接配置已就绪。", "updated": updated}

    def read_settings(self):
        return json.loads(self.settings_file.read_text(encoding="utf-8-sig"))

    def publish_token(self, project):
        token = self.read_settings()["redirect"]["token"].strip()
        if not token:
            raise ValueError("settings.json 中缺少固定入口的更新令牌。")
        return project_token(token, project.slug) if project.owner else token

    def prepare_remote_lookup(self, project):
        with self.lock:
            current = self.projects.get(project.slug)
            if (self.closing.is_set() or not current or not current.supports_remote_lookup
                or (current.entry, current.owner) != (project.entry, project.owner)):
                return False
            if current.remote_link:
                return True
            lookup = self.remote_lookups.setdefault(project.slug, RemoteLookup())
            if lookup.thread is None and monotonic() >= lookup.retry_at:
                lookup.error = ""
                lookup.thread = Thread(target=self.deploy_remote_lookup, args=(project.slug, lookup),
                                       name=f"natmap-remote-{project.slug}", daemon=True)
                lookup.thread.start()
            return False

    def deploy_remote_lookup(self, slug, lookup):
        try:
            self.enable_remote_lookup(slug)
        except (CloudflareError, OSError, ValueError, TypeError, KeyError) as error:
            message = str(error) if isinstance(error, (CloudflareError, ValueError)) else "无法读取或保存外网链接配置。"
            with self.lock:
                lookup.error = message
        finally:
            with self.lock:
                lookup.retry_at = monotonic() + REMOTE_LOOKUP_RETRY_SECONDS
                lookup.thread = None

    def enable_remote_lookup(self, slug):
        with self.provision_lock:
            with self.lock:
                if self.closing.is_set():
                    raise ValueError("管理页正在退出。")
                project = self.project(slug)
                if not project.supports_remote_lookup:
                    raise ValueError("外网链接需要一个由管理页创建的 Pages 项目，服务端口为 3389。")
                if project.remote_link:
                    return project.remote_link
                platform = self.platforms.selected()
            PagesProjects(platform).deploy_remote_lookup(project.slug, project.entry, project.owner)
            with self.lock:
                current = self.project(slug)
                if not current.supports_remote_lookup or (current.entry, current.owner) != (project.entry, project.owner):
                    raise ValueError("项目配置已变化，外网链接等待下次同步。")
                updated = replace(current, rdp_lookup_ready=True)
                self.store(updated)
                return updated.remote_link

    def store(self, project):
        self.save_projects({**self.projects, project.slug: project}, self.removed_owners)

    def save_projects(self, records, removed_owners, *, sort_mode=None):
        sort_mode = self.sort_mode if sort_mode is None else sort_mode
        write_json(self.projects_file, {"projects": [asdict(row) for row in records.values()],
                                        "removed_owners": removed_owners, "sort_mode": sort_mode})
        self.projects = records
        self.removed_owners = removed_owners
        self.sort_mode = sort_mode

    def sort_projects(self, mode, order=None):
        if mode not in PROJECT_SORT_MODES or (order is not None and mode != "custom"):
            raise ValueError("请选择有效的排序方式。")
        with self.lock:
            records = self.projects
            if order is not None:
                ready = {slug for slug, project in records.items() if project.ready}
                if len(order) != len(ready) or set(order) != ready:
                    raise ValueError("项目列表已变化，请刷新后重新调整顺序。")
                ordered = iter(order)
                slugs = (next(ordered) if project.ready else slug for slug, project in records.items())
                records = {slug: self.projects[slug] for slug in slugs}
            self.save_projects(records, self.removed_owners, sort_mode=mode)

    def project(self, slug):
        if slug not in self.projects:
            raise ValueError("找不到这个项目。")
        return self.projects[slug]

    def active(self, slug):
        task = self.tasks.get(slug)
        return bool(task and task.thread and task.thread.is_alive())

    def create(self, project, draft_slug=""):
        with self.lock:
            if self.closing.is_set():
                raise ValueError("管理页正在退出。")
            if project.slug == self.default_slug:
                raise ProjectInputError("slug", "这是已有项目的子域名，请使用「导入已有项目」。")
            existing = self.projects.get(project.slug)
            if existing and (existing.ready or not existing.owner or project.scheme == "tcp"):
                raise ProjectInputError("slug", "该子域名已添加，请换一个子域名。")
            if self.active(project.slug):
                raise ProjectInputError("slug", "该项目正在创建，请稍候。")

            platform = self.platforms.selected() if project.scheme != "tcp" else None
            records = self.projects.copy()
            removed_owners = self.removed_owners.copy()
            previous = records.get(draft_slug)
            if previous and draft_slug != project.slug and not previous.ready:
                if self.active(draft_slug):
                    raise ValueError("原项目正在创建，请等它完成后再更换子域名。")
                records.pop(draft_slug)
                if previous.owner:
                    removed_owners[draft_slug] = previous.owner
            if platform is not None:
                owner = existing.owner if existing else removed_owners.pop(project.slug, None) or token_urlsafe(24)
                project = replace(project, owner=owner)
            records[project.slug] = project
            self.save_projects(records, removed_owners)
            if previous and draft_slug not in records:
                self.tasks.pop(draft_slug, None)
            if platform is not None:
                self.begin(project.slug, "provision", platform=platform)

    def import_default(self):
        with self.lock:
            if self.default_project is None:
                raise ValueError("当前没有可导入的旧默认入口。")
            if self.default_slug not in self.projects:
                self.store(self.default_project)

    def remove(self, slug):
        with self.lock:
            project = self.project(slug)
            if self.active(slug):
                raise ValueError("请等创建结束或停止运行后再删除配置。")
            records = self.projects.copy()
            records.pop(slug)
            removed_owners = self.removed_owners.copy()
            if project.owner:
                removed_owners[slug] = project.owner
            self.save_projects(records, removed_owners)
            self.tasks.pop(slug, None)
            self.remote_lookups.pop(slug, None)

    def edit(self, slug, name, target_port, bind_port, scheme, target_host=None):
        with self.lock:
            project = self.project(slug)
            if not project.ready:
                raise ValueError("请在新建项目表单中修改未完成的项目。")
            updated = replace(project, name=name, target_port=target_port, bind_port=bind_port, scheme=scheme,
                              target_host=project.target_host if target_host is None else target_host)
            if not updated.ready:
                raise ValueError("网页协议需要 Pages 入口。请新建一个网页项目。")
            task = self.tasks.get(slug)
            restart = self.active(slug) and task.phase in ("运行中", "正在重启") and not self.closing.is_set()
            if restart:
                self.check_mapping_ports(updated)
            self.store(updated)
            if restart:
                task.phase = "正在重启"
                task.stop.set()
            return restart

    def check_mapping_ports(self, project):
        used = {ADMIN_PORT}
        for other_slug, other in self.projects.items():
            used.add(other.bind_port)
            if other.target_is_loopback:
                used.add(other.target_port)
            if other_slug == project.slug or not self.active(other_slug):
                continue
            task = self.tasks[other_slug]
            if task.bind_port is None:
                continue
            active_ports = {task.bind_port}
            if task.project.target_is_loopback:
                active_ports.add(task.project.target_port)
            used.update(active_ports)
            if project.bind_port in active_ports or (project.target_is_loopback and project.target_port == task.bind_port):
                raise ValueError(f"端口与运行中的「{other.name}」冲突。")
        return used

    def mapping_port(self, project):
        used = self.check_mapping_ports(project)
        if project.bind_port is not None:
            return project.bind_port
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                probe.bind(("0.0.0.0", 0))
                candidate = probe.getsockname()[1]
                if candidate not in used:
                    return candidate
        raise ValueError("暂时找不到可用的 NATMap 本地端口，请重试。")

    def begin(self, slug, action, *, platform=None):
        with self.lock:
            if self.closing.is_set():
                raise ValueError("管理页正在退出。")
            project = self.project(slug)
            if self.active(slug):
                raise ValueError("该任务正在运行，请稍候。")
            if action == "provision" and (project.ready or not project.owner):
                raise ValueError("这个 Pages 项目已经创建。")
            if action == "provision" and platform is None:
                platform = self.platforms.selected()
            bind_port = None
            if action == "mapping":
                if not project.ready:
                    raise ValueError("请先创建 Pages 项目。")
                try:
                    bind_port = self.mapping_port(project)
                except OSError as error:
                    raise ValueError("无法分配 NATMap 本地端口，请重试。") from error
            task = Task("创建中" if action == "provision" else "运行中", project, platform=platform, bind_port=bind_port)
            task.thread = Thread(target=self.work, args=(action, task), name=f"natmap-{slug}")
            self.tasks[slug] = task
            task.thread.start()

    def start_saved_projects(self):
        with self.lock:
            projects = [project for project in self.projects.values() if project.ready]
        for project in projects:
            try:
                with self.lock:
                    if self.closing.is_set():
                        break
                    if project.slug not in self.projects or self.active(project.slug):
                        continue
                    self.begin(project.slug, "mapping")
            except (OSError, ValueError, RuntimeError) as error:
                message = str(error) or "无法启动打洞任务。"
                task = Task("启动失败", project, detail=message)
                task.logs.append(message)
                with self.lock:
                    if project.slug in self.projects and not self.active(project.slug):
                        self.tasks[project.slug] = task

    def work(self, action, task):
        project = task.project

        def report(message):
            with self.lock:
                task.logs.append(message)
                if message.startswith(("等待本地网页服务 ", "等待本地服务 ", "本地端口 ")):
                    task.detail = message

        def save_address(address):
            with self.lock:
                task.detail = address
            if project.slug == self.default_slug:
                save_access_address(address)

        def save_scheme(scheme):
            with self.lock:
                task.detected_scheme = scheme

        try:
            if action == "provision":
                report("正在创建 Pages 项目并部署跳转函数。")
                with self.provision_lock:
                    if task.stop.is_set():
                        return
                    entry = PagesProjects(task.platform).provision(project.slug, project.owner, self.publish_token(project))
                with self.lock:
                    self.store(replace(project, entry=entry))
                    task.phase = "已创建"
                report(f"固定入口 {entry}/")
            else:
                self.run_project_mapping(task, report, save_address, save_scheme)
        except (CloudflareError, OSError, ValueError, TypeError, KeyError) as error:
            message = str(error) if isinstance(error, (CloudflareError, ValueError)) else "无法读取设置或启动程序，请检查本机文件。"
            report(message)
            with self.lock:
                task.detail = message
                if isinstance(error, PagesNameUnavailable):
                    task.error_field = "slug"
                task.phase = "创建失败" if action == "provision" else "启动失败"
        finally:
            if action == "provision":
                with self.lock:
                    task.platform = None

    def run_project_mapping(self, task, report, save_address, save_scheme):
        while True:
            project = task.project
            result = 0
            if not task.stop.is_set():
                args = Namespace(target_host=project.target_host, target_port=project.target_port,
                                 bind_port=task.bind_port, scheme=project.scheme, system_proxy=False)
                redirect = (project.entry, self.publish_token(project)) if project.entry else None

                def publish_via_d1(location):
                    pages = PagesProjects(self.platforms.selected())
                    pages.publish_mapping(project.slug, project.entry, project.owner, location)

                result = run_locked_mapping(
                    args, str(DEFAULT_NATMAP), redirect,
                    project="" if project.slug == self.default_slug else project.slug,
                    stop=task.stop, report=report, save_address=save_address, on_scheme=save_scheme,
                    rdp_lookup_enabled=(lambda: self.prepare_remote_lookup(project)) if project.supports_remote_lookup else None,
                    publish_via_d1=publish_via_d1 if project.entry and project.owner else None,
                )
            with self.lock:
                if task.phase != "正在重启" or self.closing.is_set():
                    task.phase = "启动失败" if result else "已停止"
                    if result and not task.detail:
                        task.detail = task.logs[-1] if task.logs else "无法启动打洞任务。"
                    return

                # The old run has exited and released its lock and listening port.
                updated = self.project(project.slug)
                task.bind_port = self.mapping_port(updated)
                task.project = updated
                task.stop = Event()
                task.detail = ""
                task.detected_scheme = ""
                task.phase = "运行中"
                task.logs.append("已应用新配置，正在启动打洞任务。")

    def stop(self, slug):
        with self.lock:
            if not self.active(slug) or self.tasks[slug].phase not in ("运行中", "正在重启"):
                raise ValueError("这个项目没有可停止的打洞任务。")
            self.tasks[slug].phase = "正在停止"
            self.tasks[slug].stop.set()

    def snapshot(self):
        with self.lock:
            rows = []
            for project in self.projects.values():
                task = self.tasks.get(project.slug)
                busy = self.active(project.slug)
                local_port = task.bind_port if busy and task.bind_port is not None else project.bind_port
                running = task.project if busy and task.bind_port is not None else project
                scheme_label = running.scheme.upper()
                effective_scheme = running.scheme
                if running.scheme == "auto":
                    detected = ""
                    if task and (busy or (task.project.target_port == project.target_port
                                          and task.project.target_host == project.target_host
                                          and task.project.scheme == project.scheme
                                          and task.detected_scheme == "tcp")):
                        detected = task.detected_scheme
                    effective_scheme = detected or running.scheme
                    scheme_label = f"{detected.upper()}（自动）" if detected else "自动检测"
                changes_pending = (running.target_host, running.target_port, running.bind_port, running.scheme) != (
                    project.target_host, project.target_port, project.bind_port, project.scheme,
                )
                endpoint = running.target_port
                if running.target_host != DEFAULT_TARGET_HOST:
                    endpoint = target_endpoint(running.target_host, running.target_port)
                remote_mode = project.supports_remote_lookup and effective_scheme in ("auto", "tcp")
                fixed_link = project.remote_link if remote_mode else (
                    project.entry + "/" if project.entry and effective_scheme != "tcp" else ""
                )
                lookup = self.remote_lookups.get(project.slug)
                lookup_status = ""
                lookup_error = ""
                if remote_mode and not fixed_link:
                    lookup_status = "等待映射"
                    if lookup and lookup.thread:
                        lookup_status = "正在部署"
                    elif lookup and lookup.error:
                        lookup_status = "等待重试"
                        lookup_error = lookup.error
                rows.append({"slug": project.slug, "name": project.name, "target_port": project.target_port,
                             "target_host": project.target_host, "display_target_port": running.target_port,
                             "display_target_endpoint": endpoint, "changes_pending": changes_pending,
                             "bind_port": project.bind_port, "local_port": local_port, "scheme": project.scheme,
                             "scheme_label": scheme_label, "rdp": effective_scheme == "tcp" and running.target_port == RDP_PORT,
                             "show_entry": bool(fixed_link), "fixed_link": fixed_link, "remote_link": project.remote_link,
                             "supports_remote_lookup": remote_mode, "remote_lookup_status": lookup_status,
                             "remote_lookup_error": lookup_error,
                             "entry": project.entry, "ready": project.ready, "busy": busy,
                             "phase": task.phase if task else ("待运行" if project.ready else "待创建"),
                             "detail": task.detail if task else "", "error_field": task.error_field if task else "",
                             "logs": "\n".join(task.logs) if task else ""})
            return rows

    def close(self):
        with self.lock:
            self.closing.set()
            tasks = list(self.tasks.values())
            for task in tasks:
                task.stop.set()
        self.wrangler_login.close()
        for task in tasks:
            if task.thread is not None:
                task.thread.join()


def create_app(manager):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=token_urlsafe(32), TRUSTED_HOSTS=["127.0.0.1", "localhost"],
                      SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=8192)

    @app.before_request
    def verify_form():
        if request.method == "POST":
            presented = request.form.get("csrf", "")
            expected = session.get("csrf")
            if not expected or not hmac.compare_digest(expected.encode(), presented.encode()):
                abort(403)

    @app.after_request
    def no_cache(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = token_urlsafe(24)
        return session["csrf"]

    def render_dashboard(edit_issue=None, *, open_create=False, draft_slug=None, values=None, issue=None):
        rows = manager.snapshot()
        projects = [row for row in rows if row["ready"]]
        drafts = [row for row in rows if not row["ready"]]
        draft = next((row for row in drafts if row["slug"] == draft_slug), None)
        if draft and issue is None and draft["phase"] == "创建失败":
            issue = {"field": draft["error_field"] or "form", "message": draft["detail"]}
        if edit_issue and not any(project["slug"] == edit_issue["slug"] for project in projects):
            flash(edit_issue["message"], "error")
        can_import = manager.default_project is not None and not any(
            project["slug"] == manager.default_slug for project in projects
        )
        return render_template(
            "natmap.html", projects=projects, drafts=drafts,
            can_import=can_import, csrf=csrf_token(), edit_issue=edit_issue, sort_mode=manager.sort_mode,
            open_create=open_create, draft=draft, values=values or draft or {"scheme": "auto"}, issue=issue,
        )

    @app.get("/")
    def index():
        draft_slug = request.args.get("draft")
        if draft_slug:
            return redirect(url_for("new_project", draft=draft_slug))
        return render_dashboard()

    @app.get("/project/new")
    def new_project():
        draft_slug = request.args.get("draft")
        if draft_slug and any(row["slug"] == draft_slug and row["ready"] for row in manager.snapshot()):
            return redirect(url_for("index", _anchor=f"project-{draft_slug}"))
        return render_dashboard(open_create=True, draft_slug=draft_slug)

    @app.get("/status")
    def status():
        return jsonify(manager.snapshot())

    def render_platform(profile_id=None, *, adding=False, values=None, issue=None):
        profiles, default_id = manager.platforms.snapshot()
        selected = None if adding else next((row for row in profiles if row["id"] == (profile_id or default_id)), None)
        return render_template(
            "platform.html", csrf=csrf_token(), profiles=profiles, default_id=default_id,
            values=values or selected or {"auth_source": "wrangler"}, selected=selected,
            issue=issue, auth_labels=AUTH_LABELS, wrangler=wrangler_login_status(),
            login=manager.wrangler_login.snapshot(), login_command=LOGIN_COMMAND,
        )

    @app.get("/platform")
    def platform_settings():
        return render_platform(request.args.get("profile"), adding=request.args.get("new") == "1")

    @app.get("/platform/login/status")
    def wrangler_login_status_route():
        return jsonify(login=manager.wrangler_login.snapshot(), wrangler=wrangler_login_status())

    @app.get("/platform/profiles")
    def platform_profiles():
        profiles, default_id = manager.platforms.snapshot()
        return render_template("platform_profiles.html", profiles=profiles, default_id=default_id, csrf=csrf_token())

    @app.post("/platform/<action>")
    def change_platform(action):
        profile_id = request.form.get("profile_id", "")
        auth_action = action in ("login", "discover", "choose")
        wants_auth_json = auth_action and request.accept_mimetypes.best == "application/json"
        if action == "save":
            values = {key: request.form.get(key, "").strip()
                      for key in ("name", "account_id", "database_id", "database_name", "auth_source")}
            values["account_id"] = values["account_id"].lower()
            values["database_id"] = values["database_id"].lower()
            try:
                profile_id = manager.platforms.save(profile_id, values, request.form.get("api_token", "").strip(),
                                                    request.form.get("make_default") == "1")
            except ValueError as error:
                return render_platform(profile_id, adding=not profile_id, values=values, issue=str(error)), 422
            except OSError:
                return render_platform(profile_id, adding=not profile_id, values=values,
                                       issue="无法保存平台配置，请检查本机文件。"), 500
            flash("平台配置已保存。")
        else:
            try:
                if action == "default":
                    manager.platforms.set_default(profile_id)
                    flash("已设为新建项目的默认配置。")
                elif action == "delete":
                    manager.platforms.delete(profile_id)
                    profile_id = ""
                    flash("本机平台配置已删除。")
                elif action == "check":
                    database_name = PagesProjects(manager.platforms.get(profile_id)).check_connection()
                    flash(f"已连接 Cloudflare Pages 和 D1 数据库 {database_name}。")
                elif action == "login":
                    manager.wrangler_login.start()
                elif action == "discover":
                    manager.wrangler_login.start_configure()
                elif action == "choose":
                    manager.wrangler_login.start_configure(request.form.get("connection", ""))
                else:
                    abort(404)
            except (ValueError, CloudflareError) as error:
                if wants_auth_json:
                    return jsonify(message=str(error)), 422
                flash(str(error), "error")
            except OSError:
                if wants_auth_json:
                    return jsonify(message="无法读取或保存本机平台配置。"), 500
                flash("无法读取或保存本机平台配置。", "error")
        if wants_auth_json:
            return jsonify(login=manager.wrangler_login.snapshot(), wrangler=wrangler_login_status()), 202
        return redirect(url_for("platform_settings", profile=profile_id or None,
                                _anchor="wrangler-heading" if auth_action else None), code=303)

    @app.post("/project/create")
    def create_project():
        wants_json = request.accept_mimetypes.best == "application/json"
        values = {key: request.form.get(key, "") for key in ("name", "slug", "target_port", "bind_port")}
        values["target_host"] = request.form.get("target_host", DEFAULT_TARGET_HOST)
        values["scheme"] = request.form.get("scheme", "auto")
        previous = request.form.get("draft", "")
        try:
            slug = f"tcp-{token_hex(8)}" if values["scheme"] == "tcp" else values["slug"].strip().lower()
            project = Project(slug, **project_settings(values))
            manager.create(project, previous)
        except ValueError as error:
            issue = {"field": getattr(error, "field", "form"), "message": str(error)}
            if wants_json:
                return jsonify(issue), 422
            return render_dashboard(open_create=True, draft_slug=previous, values=values, issue=issue), 422
        except OSError:
            issue = {"field": "form", "message": "无法保存本机配置，请检查本机文件。"}
            if wants_json:
                return jsonify(issue), 500
            return render_dashboard(open_create=True, draft_slug=previous, values=values, issue=issue), 500
        if wants_json:
            return jsonify(draft=project.slug), 201 if project.scheme == "tcp" else 202
        return redirect(url_for("new_project", draft=project.slug), code=303)

    @app.post("/project/save")
    def save_project():
        wants_json = request.accept_mimetypes.best == "application/json"
        slug = request.form.get("slug", "").strip().lower()
        values = {key: request.form.get(key, "") for key in ("name", "target_port", "bind_port")}
        values["target_host"] = request.form.get("target_host")
        values["scheme"] = request.form.get("scheme", "http")
        try:
            restarting = manager.edit(slug, **project_settings(values))
        except ValueError as error:
            if wants_json:
                return jsonify(message=str(error)), 422
            edit_issue = {"slug": slug, "fields": values, "message": str(error)}
            return render_dashboard(edit_issue=edit_issue), 422
        except OSError:
            message = "无法保存本机配置，请检查本机文件。"
            if wants_json:
                return jsonify(message=message), 500
            edit_issue = {"slug": slug, "fields": values, "message": message}
            return render_dashboard(edit_issue=edit_issue), 500
        message = "配置已保存，正在重启项目。" if restarting else "配置已保存。"
        if wants_json:
            return jsonify(name=values["name"].strip(), message=message)
        flash(message)
        return redirect(url_for("index", _anchor=f"project-{slug}"), code=303)

    @app.post("/project/sort")
    def sort_projects():
        mode = request.form.get("mode", "")
        order = request.form.getlist("order") if "order" in request.form else None
        try:
            manager.sort_projects(mode, order)
        except ValueError as error:
            return jsonify(message=str(error)), 422
        except OSError:
            return jsonify(message="无法保存排序，请检查本机项目配置。"), 500
        return jsonify(mode=mode)

    @app.post("/project/<action>")
    def change(action):
        slug = request.form.get("slug", "").strip().lower()
        try:
            if action in ("provision", "mapping"):
                manager.begin(slug, action)
            elif action == "stop":
                manager.stop(slug)
            elif action == "delete":
                manager.remove(slug)
                flash("本机配置已删除。")
            elif action == "import":
                manager.import_default()
            else:
                abort(404)
        except (ArgumentTypeError, ValueError) as error:
            flash(str(error) or "端口必须是整数。", "error")
        except OSError:
            flash("无法保存本机配置，请检查本机文件。", "error")
        return redirect(url_for("index"), code=303)

    return app


def main():
    try:
        manager = Manager()
    except OSError as error:
        print(f"无法读取或迁移 data 中的项目配置：{error}")
        return 1
    except (ValueError, KeyError, TypeError, ArgumentTypeError):
        print("无法读取 NATMap 配置，请检查 data 中的 settings.json 和 projects.json。")
        return 1
    server = make_server("127.0.0.1", ADMIN_PORT, create_app(manager), threaded=True)
    print(f"NATMap 管理页 {ADMIN_URL}  按 Ctrl+C 关闭。", flush=True)
    try:
        manager.wrangler_login.prepare()
        manager.start_saved_projects()
        webbrowser.open(ADMIN_URL)
        server.serve_forever()
    finally:
        manager.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
