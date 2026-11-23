"""Local web controls for the Windows NATMap publisher."""

from argparse import ArgumentTypeError, Namespace
from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
import hmac
from ipaddress import ip_address
import json
from pathlib import Path
from secrets import token_hex, token_urlsafe
import socket
import ssl
from threading import Event, Lock, RLock, Thread
from time import monotonic, time_ns
from urllib.parse import urlsplit
import webbrowser

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import make_server

from data_storage import PROJECTS_FILE, ensure_data
from duckdns_natmap import (
    ADMIN_PORT, DEFAULT_NATMAP, DEFAULT_TARGET_HOST, MAPPING_SCHEMES, RDP_PORT, SETTINGS_FILE,
    RedirectUpdateError, normalize_target_host, port, run_locked_mapping, save_access_address, target_endpoint,
)
from pages_projects import CloudflareError, LOGIN_COMMAND, PAGES_HOST, PROJECT_NAME, REMOTE_LOOKUP_VERSION, WEB_ACCESS_MODES, PagesNameUnavailable, PagesProjects, WranglerLogin, cloudflare_request, discover_cloudflare_connections, normalize_proxy_origin, project_token
from platform_settings import AUTH_LABELS, PlatformProfile, PlatformSettings, pages_config, wrangler_login_status, write_json


ADMIN_URL = f"http://127.0.0.1:{ADMIN_PORT}/"
REMOTE_LOOKUP_RETRY_SECONDS = 60
PROJECT_SORT_MODES = ("custom", "name-asc", "name-desc")
REMOTE_MANAGER_USER = "natmap"
PROJECT_NOTE_LIMIT = 200


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


def remote_manager_password_hash(password):
    if not password:
        raise ProjectInputError("manager_password", "请填写远程管理密码。")
    return generate_password_hash(password)


def remote_manager_tls(project):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(project.manager_certificate, project.manager_private_key, password=lambda: "")
    except (OSError, ValueError) as error:
        raise ProjectInputError("manager_certificate", "无法加载远程管理的 PEM 证书或私钥，请检查文件路径和证书配置。") from error
    return context


def manager_origin_settings(origin, certificate, private_key):
    fields = (
        ("manager_origin", origin, "HTTPS 回源域名"),
        ("manager_certificate", certificate, "PEM 证书路径"),
        ("manager_private_key", private_key, "PEM 私钥路径"),
    )
    https = any(value for _, value, _ in fields)
    if https:
        for name, value, label in fields:
            if not value:
                raise ProjectInputError(name, f"使用 HTTPS 时请填写{label}。使用 HTTP 可将三项全部留空。")
    return {
        "scheme": "https" if https else "http",
        "proxy_origin": origin,
        "manager_certificate": certificate,
        "manager_private_key": private_key,
    }


@contextmanager
def serve_management_in_thread(server, *, name):
    thread = Thread(target=server.serve_forever, name=name, daemon=True)
    try:
        thread.start()
        yield
    finally:
        if thread.is_alive():
            server.shutdown()
            thread.join()
        server.server_close()


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
    web_mode: str = "redirect"
    proxy_origin: str = ""
    manager_target: bool = False
    manager_certificate: str = ""
    manager_private_key: str = ""
    manager_password_hash: str = field(default="", repr=False)
    tcp_lookup_ready: bool = False
    shared_entry: str = ""
    tcp_group_ready: bool = False
    tcp_group_version: int = 0
    note: str = ""
    manager_username: str = REMOTE_MANAGER_USER

    def __post_init__(self):
        if not PROJECT_NAME.fullmatch(self.slug):
            raise ProjectInputError("slug", "子域名长度为 1 到 40，使用小写英文字母、数字或连字符，首尾不能为连字符。")
        if not self.name.strip() or len(self.name) > 60:
            raise ProjectInputError("name", "请填写项目名称，最多 60 个字。")
        if not isinstance(self.note, str) or len(self.note) > PROJECT_NOTE_LIMIT:
            raise ProjectInputError("note", f"备注最多 {PROJECT_NOTE_LIMIT} 个字符。")
        try:
            object.__setattr__(self, "target_host", normalize_target_host(self.target_host))
        except ValueError as error:
            raise ProjectInputError("target_host", str(error)) from error
        project_port(self.target_port, "target_port")
        if self.bind_port is not None:
            project_port(self.bind_port, "bind_port")
        if self.target_is_loopback and self.target_port == ADMIN_PORT and not self.manager_target:
            raise ProjectInputError("target_port", f"端口 {ADMIN_PORT} 正由本机管理页使用。")
        if self.bind_port == ADMIN_PORT:
            raise ProjectInputError("bind_port", f"端口 {ADMIN_PORT} 正由本机管理页使用。")
        if self.target_is_loopback and self.target_port == self.bind_port:
            raise ProjectInputError("bind_port", "NATMap 本地端口必须与本机服务端口不同。")
        if self.scheme not in MAPPING_SCHEMES:
            raise ProjectInputError("scheme", "请选择自动检测、HTTP、HTTPS 或 TCP。")
        if self.shared_entry and (self.scheme != "tcp" or self.shared_entry == self.slug
                                  or not PROJECT_NAME.fullmatch(self.shared_entry)):
            raise ProjectInputError("shared_entry", "共享入口只适用于 TCP 项目，请选择另一个项目的固定入口。")
        if self.web_mode not in WEB_ACCESS_MODES:
            raise ProjectInputError("web_mode", "请选择 302 跳转直连或反向代理。")
        try:
            object.__setattr__(self, "proxy_origin", normalize_proxy_origin(self.proxy_origin))
        except ValueError as error:
            raise ProjectInputError("proxy_origin", str(error)) from error
        if self.scheme == "https" and self.web_mode == "proxy" and not self.proxy_origin:
            raise ProjectInputError("proxy_origin", "代理 HTTPS 服务需要填写与证书匹配的回源域名。")
        if self.manager_target:
            if (self.target_host != DEFAULT_TARGET_HOST or self.target_port != ADMIN_PORT
                or self.scheme not in ("http", "https")):
                raise ProjectInputError("form", "NATMap 管理页需要使用专用的网页转发。")
            username = self.manager_username.strip()
            if not username or ":" in username or not username.isprintable():
                raise ProjectInputError("manager_username", "请填写登录用户名，用户名不能包含冒号或控制字符。")
            object.__setattr__(self, "manager_username", username)
            if not self.manager_password_hash:
                raise ProjectInputError("manager_password", "请设置远程管理密码。")
            if self.manager_https:
                if not self.proxy_origin:
                    raise ProjectInputError("proxy_origin", "请填写与证书匹配的 HTTPS 回源域名。")
                if self.proxy_origin == f"{self.slug}.pages.dev":
                    raise ProjectInputError("proxy_origin", "回源域名需要指向 NATMap 公网 IPv4，请填写独立的域名。")
                if not self.manager_certificate or not self.manager_private_key:
                    raise ProjectInputError("manager_certificate", "请填写远程管理的 PEM 证书和私钥路径。")
            elif self.web_mode != "redirect":
                raise ProjectInputError("web_mode", "HTTP 管理页使用 302 跳转直连。")
        if self.entry:
            host = urlsplit(self.entry).netloc
            if not PAGES_HOST.fullmatch(host) or self.entry != f"https://{host}":
                raise ValueError("项目入口必须是有效的 HTTPS Pages 网址。")

    @property
    def manager_https(self):
        return self.manager_target and self.scheme == "https"

    @property
    def target_is_loopback(self):
        return ip_address(self.target_host).is_loopback

    @property
    def ready(self):
        return bool(self.entry) or (self.scheme == "tcp" and not self.owner)

    @property
    def supports_remote_lookup(self):
        return bool(self.entry and self.owner) and self.scheme in ("auto", "tcp")

    @property
    def can_share_entry(self):
        return self.supports_remote_lookup and self.scheme == "tcp" and not self.shared_entry

    @property
    def tcp_group_current(self):
        return self.tcp_group_ready and self.tcp_group_version == REMOTE_LOOKUP_VERSION

    def remote_link(self, *, rdp):
        ready = self.rdp_lookup_ready if rdp else self.tcp_lookup_ready
        return f"{self.entry}/" if self.supports_remote_lookup and ready else ""


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
        self.resume_file = projects_file.with_name("running_projects.json")
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
        self.directory_revision = time_ns() // 1_000_000
        if projects_file.is_file():
            records = json.loads(projects_file.read_text(encoding="utf-8"))
            if isinstance(records, dict):
                self.removed_owners = dict(records.get("removed_owners", {}))
                revision = records.get("directory_revision", 0)
                if isinstance(revision, int):
                    self.directory_revision = max(self.directory_revision, revision)
                if records.get("sort_mode") in PROJECT_SORT_MODES:
                    self.sort_mode = records["sort_mode"]
                records = records["projects"]
            for data in records:
                data.pop("rdp_lookup_key", None)
                project = Project(**data)
                self.projects[project.slug] = project
        self.resume_slugs = set()
        try:
            saved_running = json.loads(self.resume_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            print("无法读取上次的运行状态，本次请手动启动项目。", flush=True)
        else:
            if isinstance(saved_running, list):
                self.resume_slugs = {
                    slug for slug in saved_running
                    if isinstance(slug, str) and slug in self.projects and self.projects[slug].ready
                }
        self.tasks = {}
        self.remote_lookups = {}
        self.web_access_updates = set()
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

    def share_members(self, slug):
        return [member for member in self.projects.values() if member.shared_entry == slug]

    def entry_project(self, project):
        return self.projects.get(project.shared_entry) if project.shared_entry else project

    def validate_shared_entry(self, project):
        if project.shared_entry:
            anchor = self.entry_project(project)
            if not anchor or not anchor.can_share_entry:
                raise ProjectInputError("shared_entry", "请选择已有 Pages 固定入口的 TCP 项目。")
        if self.share_members(project.slug) and not project.can_share_entry:
            raise ProjectInputError("shared_entry", "请先把共享此入口的其他项目移出，再更改该项目的协议或入口。")

    def tcp_directory(self, project, anchor):
        with self.lock:
            current = self.project(project.slug)
            gateway = self.entry_project(current)
            if not gateway or (gateway.slug, gateway.entry, gateway.owner) != (anchor.slug, anchor.entry, anchor.owner):
                raise RedirectUpdateError("共享入口已更改，请重新启动该项目。")
            members = self.share_members(gateway.slug)
            if not members and not gateway.tcp_group_ready:
                return None
            devices = [{"id": row.slug, "name": row.name, "note": row.note} for row in [gateway, *members]]
            return {"device": current.slug, "directory": {"revision": self.directory_revision, "devices": devices}}

    def prepare_remote_lookup(self, project, rdp):
        with self.lock:
            current = self.projects.get(project.slug)
            if self.closing.is_set() or not current or current.shared_entry != project.shared_entry:
                return False
            anchor = self.entry_project(current)
            if not anchor or not anchor.supports_remote_lookup:
                return False
            group = bool(self.share_members(anchor.slug))
            link = anchor.remote_link(rdp=rdp)
            if link and (not group or anchor.tcp_group_current):
                return True
            lookup = self.remote_lookups.setdefault(anchor.slug, RemoteLookup())
            if lookup.thread is None and monotonic() >= lookup.retry_at:
                lookup.error = ""
                lookup.thread = Thread(target=self.deploy_remote_lookup, args=(anchor.slug, lookup, rdp, group),
                                       name=f"natmap-remote-{anchor.slug}", daemon=True)
                lookup.thread.start()
            return bool(link and group and anchor.tcp_group_ready)

    def deploy_remote_lookup(self, slug, lookup, rdp, group):
        try:
            self.enable_remote_lookup(slug, rdp=rdp, group=group)
        except (CloudflareError, OSError, ValueError, TypeError, KeyError) as error:
            message = str(error) if isinstance(error, (CloudflareError, ValueError)) else "无法读取或保存外网链接配置。"
            with self.lock:
                lookup.error = message
        finally:
            with self.lock:
                lookup.retry_at = monotonic() + REMOTE_LOOKUP_RETRY_SECONDS
                lookup.thread = None

    def enable_remote_lookup(self, slug, *, rdp, group=False):
        with self.provision_lock:
            with self.lock:
                if self.closing.is_set():
                    raise ValueError("管理页正在退出。")
                project = self.project(slug)
                if not project.supports_remote_lookup:
                    raise ValueError("TCP 外网链接需要一个由管理页创建的 Pages 项目。")
                link = project.remote_link(rdp=rdp)
                if link and (not group or project.tcp_group_current):
                    return link
                platform = self.platforms.selected()
            PagesProjects(platform).deploy_remote_lookup(
                project.slug, project.entry, project.owner, web_mode=project.web_mode, proxy_origin=project.proxy_origin,
            )
            with self.lock:
                current = self.project(slug)
                if not current.supports_remote_lookup or (current.entry, current.owner) != (project.entry, project.owner):
                    raise ValueError("项目配置已变化，外网链接等待下次同步。")
                updated = replace(current, rdp_lookup_ready=True, tcp_lookup_ready=True,
                                  tcp_group_ready=current.tcp_group_ready or group,
                                  tcp_group_version=REMOTE_LOOKUP_VERSION)
                self.store(updated)
                return updated.remote_link(rdp=rdp)

    def set_web_access(self, slug, web_mode, proxy_origin):
        with self.provision_lock:
            with self.lock:
                project = self.project(slug)
                if slug in self.web_access_updates:
                    raise ValueError("这个项目正在更新固定入口，请稍候。")
                task = self.tasks.get(slug)
                detected = task.detected_scheme if task and self.active(slug) else ""
                if not project.entry or project.scheme == "tcp" or detected in ("tcp", "rdp"):
                    raise ValueError("固定入口方式适用于 HTTP 或 HTTPS 网页项目。")
                if project.manager_target or web_mode == "redirect":
                    proxy_origin = project.proxy_origin
                updated = replace(project, web_mode=web_mode, proxy_origin=proxy_origin)
                if updated.web_mode == "proxy" and detected == "https" and not updated.proxy_origin:
                    raise ProjectInputError("proxy_origin", "代理 HTTPS 服务需要填写与证书匹配的回源域名。")
                if self.closing.is_set():
                    raise ValueError("管理页正在退出。")
                platform = self.platforms.selected()
                self.web_access_updates.add(slug)
            try:
                PagesProjects(platform).set_web_access(
                    slug, project.entry, project.owner, updated.web_mode, updated.proxy_origin, https_only=project.manager_https,
                )
                with self.lock:
                    self.store(replace(self.project(slug), web_mode=updated.web_mode, proxy_origin=updated.proxy_origin))
            finally:
                with self.lock:
                    self.web_access_updates.discard(slug)

    def store(self, project):
        self.save_projects({**self.projects, project.slug: project}, self.removed_owners)

    def save_project_note(self, slug, note):
        note = note.replace("\r\n", "\n").replace("\r", "\n").strip()
        with self.lock:
            if self.closing.is_set():
                raise ValueError("管理页正在退出。")
            project = self.project(slug)
            if project.note != note:
                self.store(replace(project, note=note))
        return note

    def save_projects(self, records, removed_owners, *, sort_mode=None):
        sort_mode = self.sort_mode if sort_mode is None else sort_mode
        revision = max(self.directory_revision + 1, time_ns() // 1_000_000)
        write_json(self.projects_file, {"projects": [asdict(row) for row in records.values()],
                                        "removed_owners": removed_owners, "sort_mode": sort_mode,
                                        "directory_revision": revision})
        self.projects = records
        self.removed_owners = removed_owners
        self.sort_mode = sort_mode
        self.directory_revision = revision

    def save_resume_slugs(self, slugs):
        if slugs != self.resume_slugs:
            write_json(self.resume_file, sorted(slugs))
            self.resume_slugs = slugs

    def forget_finished_mapping(self, slug, task):
        try:
            self.save_resume_slugs(self.resume_slugs - {slug})
        except OSError:
            task.logs.append("无法保存项目的运行状态，请检查 data 目录。")

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

    def create(self, project, draft_slug="", *, local_only=False):
        with self.lock:
            if self.closing.is_set():
                raise ValueError("管理页正在退出。")
            if project.slug == self.default_slug:
                raise ProjectInputError("slug", "这是已有项目的子域名，请使用「导入已有项目」。")
            existing = self.projects.get(project.slug)
            if existing and (existing.ready or not existing.owner):
                raise ProjectInputError("slug", "该子域名已添加，请换一个子域名。")
            if self.active(project.slug):
                raise ProjectInputError("slug", "该项目正在创建，请稍候。")

            self.validate_shared_entry(project)
            platform = None if local_only else self.platforms.selected()
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
            if slug in self.web_access_updates:
                raise ValueError("这个项目正在更新固定入口，请稍候。")
            if self.active(slug):
                raise ValueError("请等创建结束或停止运行后再删除配置。")
            if self.share_members(slug):
                raise ValueError("请先把共享此入口的其他项目移出，再删除该项目。")
            self.save_resume_slugs(self.resume_slugs - {slug})
            records = self.projects.copy()
            records.pop(slug)
            removed_owners = self.removed_owners.copy()
            if project.owner:
                removed_owners[slug] = project.owner
            self.save_projects(records, removed_owners)
            self.tasks.pop(slug, None)
            self.remote_lookups.pop(slug, None)

    def edit(self, slug, name, target_port, bind_port, scheme, target_host=None,
             *, manager_username=None, manager_password="", manager_origin=None,
             manager_certificate="", manager_private_key="", shared_entry=None):
        with self.lock:
            project = self.project(slug)
            if slug in self.web_access_updates:
                raise ValueError("这个项目正在更新固定入口，请稍候。")
            if not project.ready:
                raise ValueError("请在新建项目表单中修改未完成的项目。")
            if project.manager_target:
                if manager_origin is None:
                    manager_origin = project.proxy_origin
                    manager_certificate = manager_certificate or project.manager_certificate
                    manager_private_key = manager_private_key or project.manager_private_key
                transport = manager_origin_settings(manager_origin, manager_certificate, manager_private_key)
                updated = replace(
                    project, name=name, bind_port=bind_port, **transport,
                    web_mode=project.web_mode if transport["scheme"] == "https" else "redirect",
                    manager_username=project.manager_username if manager_username is None else manager_username,
                    manager_password_hash=(remote_manager_password_hash(manager_password) if manager_password else project.manager_password_hash),
                )
                if updated.manager_https:
                    remote_manager_tls(updated)
            else:
                updated = replace(project, name=name, target_port=target_port, bind_port=bind_port, scheme=scheme,
                                  target_host=project.target_host if target_host is None else target_host,
                                  shared_entry=project.shared_entry if shared_entry is None else shared_entry)
            self.validate_shared_entry(updated)
            if not updated.ready:
                raise ValueError("网页协议需要 Pages 入口。请新建一个网页项目。")
            if not updated.manager_target or (updated.manager_https, updated.proxy_origin) == (
                project.manager_https, project.proxy_origin,
            ):
                return self._save_project_edit(updated)
            if self.closing.is_set():
                raise ValueError("管理页正在退出。")
            if self.active(slug):
                self.check_mapping_ports(updated)
            pages = PagesProjects(self.platforms.selected())
            self.web_access_updates.add(slug)

        def sync_entry(settings):
            pages.set_web_access(
                slug, settings.entry, settings.owner, settings.web_mode, settings.proxy_origin,
                https_only=settings.manager_https,
            )

        try:
            with self.provision_lock:
                sync_entry(updated)
                try:
                    with self.lock:
                        return self._save_project_edit(replace(updated, note=self.project(slug).note))
                except (OSError, ValueError):
                    try:
                        sync_entry(project)
                    except (CloudflareError, OSError, ValueError) as error:
                        raise CloudflareError("本机配置未更新，固定入口恢复暂未确认，请重新保存配置。") from error
                    raise
        finally:
            with self.lock:
                self.web_access_updates.discard(slug)

    def _save_project_edit(self, updated):
        task = self.tasks.get(updated.slug)
        restart = self.active(updated.slug) and task.phase in ("运行中", "正在重启") and not self.closing.is_set()
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
            if slug in self.web_access_updates:
                raise ValueError("这个项目正在更新固定入口，请稍候。")
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
            if action == "mapping":
                self.save_resume_slugs(self.resume_slugs | {slug})
            self.tasks[slug] = task
            try:
                task.thread.start()
            except RuntimeError as error:
                self.tasks.pop(slug, None)
                if action == "mapping":
                    self.save_resume_slugs(self.resume_slugs - {slug})
                raise ValueError("无法启动项目任务，请重试。") from error

    def start_saved_projects(self, *, restore_only=False):
        with self.lock:
            started = failed = 0
            for project in self.projects.values():
                if self.closing.is_set():
                    break
                if restore_only and project.slug not in self.resume_slugs:
                    continue
                if not project.ready or self.active(project.slug):
                    continue
                try:
                    self.begin(project.slug, "mapping")
                except (OSError, ValueError, RuntimeError) as error:
                    message = str(error) or "无法启动打洞任务。"
                    task = Task("启动失败", project, detail=message)
                    task.logs.append(message)
                    self.tasks[project.slug] = task
                    self.forget_finished_mapping(project.slug, task)
                    failed += 1
                else:
                    started += 1
            return started, failed

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
                report("正在创建 Pages 项目并部署固定入口。")
                with self.provision_lock:
                    if task.stop.is_set():
                        return
                    entry = PagesProjects(task.platform).provision(
                        project.slug, project.owner, self.publish_token(project),
                        web_mode=project.web_mode, proxy_origin=project.proxy_origin, https_only=project.manager_https,
                    )
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
            with self.lock:
                if action == "provision":
                    task.platform = None
                elif not self.closing.is_set():
                    self.forget_finished_mapping(project.slug, task)

    @contextmanager
    def mapping_target(self, project, bind_port):
        if not project.manager_target:
            yield project.target_host, project.target_port, None
            return
        tls = remote_manager_tls(project) if project.manager_https else None
        application = create_app(self, remote_project=project, remote_http=not project.manager_https)

        def update_public_host(address):
            hosts = [DEFAULT_TARGET_HOST]
            if address is not None:
                hosts.append(str(address))
            application.config["TRUSTED_HOSTS"] = hosts

        server = make_server(DEFAULT_TARGET_HOST, 0, application, threaded=True, ssl_context=tls)
        if server.server_port == bind_port:
            reserved = server
            try:
                server = make_server(DEFAULT_TARGET_HOST, 0, application, threaded=True, ssl_context=tls)
            finally:
                reserved.server_close()
        with serve_management_in_thread(server, name=f"natmap-management-{project.slug}"):
            yield DEFAULT_TARGET_HOST, server.server_port, update_public_host if tls is None else None

    def run_project_mapping(self, task, report, save_address, save_scheme):
        while True:
            project = task.project
            result = 0
            if not task.stop.is_set():
                with self.lock:
                    anchor = self.entry_project(project)
                if not anchor:
                    raise ValueError("找不到共享入口，请在项目配置中重新选择。")
                redirect = (anchor.entry, self.publish_token(anchor)) if anchor.entry else None

                def publish_via_d1(location, *, tcp_group=None):
                    pages = PagesProjects(self.platforms.selected())
                    pages.publish_mapping(anchor.slug, anchor.entry, anchor.owner, location, tcp_group=tcp_group)

                with self.mapping_target(project, task.bind_port) as (target_host, target_port, on_public_address):
                    args = Namespace(target_host=target_host, target_port=target_port,
                                     bind_port=task.bind_port, scheme=project.scheme, system_proxy=False)
                    result = run_locked_mapping(
                        args, str(DEFAULT_NATMAP), redirect,
                        project="" if project.slug == self.default_slug else project.slug,
                        stop=task.stop, report=report, save_address=save_address, on_scheme=save_scheme,
                        on_public_address=on_public_address,
                        tcp_lookup_enabled=(lambda rdp: self.prepare_remote_lookup(project, rdp)) if anchor.supports_remote_lookup else None,
                        publish_via_d1=publish_via_d1 if anchor.entry and anchor.owner else None,
                        tcp_group=(lambda: self.tcp_directory(project, anchor)) if anchor.supports_remote_lookup else None,
                        tcp_revision=(lambda: self.directory_revision) if redirect and project.scheme == "tcp" else None,
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
        if not self.stop_mappings((slug,)):
            raise ValueError("这个项目没有可停止的打洞任务。")

    def stop_running_projects(self):
        return self.stop_mappings(self.tasks)

    def stop_mappings(self, slugs):
        with self.lock:
            if self.closing.is_set():
                raise ValueError("管理页正在退出。")
            running = {
                slug for slug in slugs
                if self.active(slug) and self.tasks[slug].phase in ("运行中", "正在重启")
            }
            self.save_resume_slugs(self.resume_slugs - running)
            for slug in running:
                task = self.tasks[slug]
                task.phase = "正在停止"
                task.stop.set()
            return len(running)

    def snapshot(self, *, include_certificate_paths=False):
        with self.lock:
            rows = []
            for project in self.projects.values():
                task = self.tasks.get(project.slug)
                busy = self.active(project.slug)
                local_port = task.bind_port if busy and task.bind_port is not None else project.bind_port
                running = task.project if busy and task.bind_port is not None else project
                detected = ""
                if task and (busy or (task.project.target_port == project.target_port
                                      and task.project.target_host == project.target_host
                                      and task.project.scheme == project.scheme
                                      and task.detected_scheme in ("tcp", "rdp"))):
                    detected = task.detected_scheme
                rdp = detected == "rdp" or (not detected and running.scheme == "tcp" and running.target_port == RDP_PORT)
                effective_scheme = "tcp" if rdp else (detected or running.scheme)
                scheme_label = running.scheme.upper()
                if running.scheme == "auto":
                    scheme_label = f"{effective_scheme.upper()}（自动）" if detected else "自动检测"
                changes_pending = (running.target_host, running.target_port, running.bind_port, running.scheme) != (
                    project.target_host, project.target_port, project.bind_port, project.scheme,
                )
                endpoint = running.target_port
                if running.target_host != DEFAULT_TARGET_HOST:
                    endpoint = target_endpoint(running.target_host, running.target_port)
                tcp = effective_scheme == "tcp"
                rdp_pending = effective_scheme == "auto" and running.target_port == RDP_PORT
                anchor = self.entry_project(project)
                entry = anchor.entry if anchor else ""
                remote_mode = bool(anchor and anchor.supports_remote_lookup and (tcp or rdp_pending))
                remote_link = anchor.remote_link(rdp=rdp or rdp_pending) if remote_mode else ""
                if project.shared_entry and anchor and not anchor.tcp_group_ready:
                    remote_link = ""
                fixed_link = remote_link if remote_mode else (
                    entry + "/" if entry and effective_scheme != "tcp" else ""
                )
                lookup = self.remote_lookups.get(anchor.slug) if anchor else None
                lookup_status = ""
                lookup_error = ""
                if remote_mode and not fixed_link:
                    lookup_status = "等待映射"
                    if lookup and lookup.thread:
                        lookup_status = "正在部署"
                    elif lookup and lookup.error:
                        lookup_status = "等待重试"
                        lookup_error = lookup.error
                rows.append({"slug": project.slug, "name": project.name, "note": project.note, "target_port": project.target_port,
                             "target_host": project.target_host, "display_target_port": running.target_port,
                             "display_target_endpoint": endpoint, "changes_pending": changes_pending,
                             "bind_port": project.bind_port, "local_port": local_port, "scheme": project.scheme,
                             "web_mode": project.web_mode, "proxy_origin": project.proxy_origin,
                             "manager_target": project.manager_target, "manager_username": project.manager_username,
                             "scheme_label": scheme_label, "rdp": rdp, "tcp": tcp,
                             "show_entry": bool(fixed_link), "fixed_link": fixed_link, "remote_link": remote_link,
                             "supports_remote_lookup": remote_mode, "remote_lookup_status": lookup_status,
                             "remote_lookup_error": lookup_error,
                             "entry": entry, "own_entry": project.entry, "shared_entry": project.shared_entry,
                             "can_share_entry": project.can_share_entry, "ready": project.ready, "busy": busy,
                             "phase": task.phase if task else ("待运行" if project.ready else "待创建"),
                             "detail": task.detail if task else "", "error_field": task.error_field if task else "",
                             "logs": "\n".join(task.logs) if task else ""})
                if include_certificate_paths and project.manager_target:
                    rows[-1].update(manager_certificate=project.manager_certificate, manager_private_key=project.manager_private_key)
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


def create_app(manager, *, remote_project=None, remote_http=False):
    app = Flask(__name__)
    remote_username = getattr(remote_project, "manager_username", REMOTE_MANAGER_USER)
    trusted_hosts = [remote_project.proxy_origin] if remote_project and not remote_http else [DEFAULT_TARGET_HOST, "localhost"]
    app.config.update(SECRET_KEY=token_urlsafe(32), TRUSTED_HOSTS=trusted_hosts,
                      SESSION_COOKIE_NAME="natmap_session", SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=8192)
    if remote_project:
        app.config.update(SESSION_COOKIE_NAME="natmap_remote_http_session" if remote_http else "natmap_remote_session",
                          SESSION_COOKIE_SECURE=not remote_http)

    @app.before_request
    def verify_form():
        if remote_project:
            if not remote_http and not request.is_secure:
                abort(403)
            auth = request.authorization
            if (not auth or auth.type != "basic" or auth.username != remote_username
                or not check_password_hash(remote_project.manager_password_hash, auth.password or "")):
                return "", 401, {"WWW-Authenticate": 'Basic realm="NATMap", charset="UTF-8"'}
        if request.method == "POST":
            presented = request.form.get("csrf", "")
            expected = session.get("csrf")
            if not expected or not hmac.compare_digest(expected.encode(), presented.encode()):
                message = "页面会话已过期，请刷新后重试。"
                if request.accept_mimetypes.best == "application/json":
                    return jsonify(message=message), 403, {"X-NATMap-CSRF": "expired"}
                abort(403, description=message)

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
        rows = manager.snapshot(include_certificate_paths=True)
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
            note_limit=PROJECT_NOTE_LIMIT, default_manager_username=REMOTE_MANAGER_USER,
            shared_entries=[project for project in projects if project["can_share_entry"]],
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

    @app.get("/csrf")
    def refresh_csrf():
        return jsonify(csrf=csrf_token())

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
        values["target_kind"] = request.form.get("target_kind", "service")
        values["manager_username"] = request.form.get("manager_username", REMOTE_MANAGER_USER)
        for name in ("manager_origin", "manager_certificate", "manager_private_key"):
            values[name] = request.form.get(name, "").strip()
        values["shared_entry"] = request.form.get("shared_entry", "").strip().lower()
        values["target_host"] = request.form.get("target_host", DEFAULT_TARGET_HOST)
        values["scheme"] = request.form.get("scheme", "auto")
        values["web_mode"] = request.form.get("web_mode", "redirect") if values["scheme"] != "tcp" else "redirect"
        values["proxy_origin"] = request.form.get("proxy_origin", "") if values["web_mode"] == "proxy" else ""
        previous = request.form.get("draft", "")
        try:
            if values["target_kind"] not in ("service", "manager"):
                raise ProjectInputError("target_kind", "请选择要转发的服务。")
            manager_options = {}
            if values["target_kind"] == "manager":
                transport = manager_origin_settings(
                    values["manager_origin"], values["manager_certificate"], values["manager_private_key"],
                )
                values.update(target_host=DEFAULT_TARGET_HOST, target_port=str(ADMIN_PORT), web_mode="redirect",
                              shared_entry="", scheme=transport["scheme"], proxy_origin=transport["proxy_origin"])
                manager_options = {
                    "manager_target": True,
                    "manager_username": values["manager_username"],
                    "manager_password_hash": remote_manager_password_hash(request.form.get("manager_password", "")),
                    "manager_certificate": transport["manager_certificate"],
                    "manager_private_key": transport["manager_private_key"],
                }
            slug = values["slug"].strip().lower()
            local_only = values["scheme"] == "tcp" and (bool(values["shared_entry"]) or not slug)
            if local_only:
                slug = f"tcp-{token_hex(8)}"
            project = Project(slug, **project_settings(values), web_mode=values["web_mode"],
                              proxy_origin=values["proxy_origin"], shared_entry=values["shared_entry"], **manager_options)
            if project.manager_https:
                remote_manager_tls(project)
            manager.create(project, previous, local_only=local_only)
        except ValueError as error:
            field = getattr(error, "field", "form")
            if field == "proxy_origin" and values["target_kind"] == "manager":
                field = "manager_origin"
            issue = {"field": field, "message": str(error)}
            if wants_json:
                return jsonify(issue), 422
            return render_dashboard(open_create=True, draft_slug=previous, values=values, issue=issue), 422
        except OSError:
            issue = {"field": "form", "message": "无法保存本机配置，请检查本机文件。"}
            if wants_json:
                return jsonify(issue), 500
            return render_dashboard(open_create=True, draft_slug=previous, values=values, issue=issue), 500
        if wants_json:
            return jsonify(draft=project.slug), 201 if local_only else 202
        return redirect(url_for("new_project", draft=project.slug), code=303)

    @app.post("/project/save")
    def save_project():
        wants_json = request.accept_mimetypes.best == "application/json"
        slug = request.form.get("slug", "").strip().lower()
        values = {key: request.form.get(key, "") for key in ("name", "target_port", "bind_port")}
        values["manager_username"] = request.form.get("manager_username")
        submitted_origin = request.form.get("manager_origin")
        values["manager_origin"] = submitted_origin.strip() if submitted_origin is not None else None
        for name in ("manager_certificate", "manager_private_key"):
            values[name] = request.form.get(name, "").strip()
        values["target_host"] = request.form.get("target_host")
        values["scheme"] = request.form.get("scheme", "http")
        share = request.form.get("shared_entry") if values["scheme"] == "tcp" else ""
        values["shared_entry"] = share.strip().lower() if share is not None else None
        try:
            restarting = manager.edit(
                slug, **project_settings(values), manager_username=values["manager_username"],
                manager_password=request.form.get("manager_password", ""), manager_origin=values["manager_origin"],
                manager_certificate=values["manager_certificate"], manager_private_key=values["manager_private_key"],
                shared_entry=values["shared_entry"],
            )
        except (ValueError, CloudflareError) as error:
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

    @app.post("/project/note")
    def save_project_note():
        slug = request.form.get("slug", "").strip().lower()
        wants_json = request.accept_mimetypes.best == "application/json"
        status = 200
        try:
            note = manager.save_project_note(slug, request.form.get("note", ""))
            message = "备注已保存。"
        except ValueError as error:
            status, message = 422, str(error)
        except OSError:
            status, message = 500, "无法保存备注，请检查本机文件。"
        if wants_json:
            if status != 200:
                return jsonify(message=message), status
            return jsonify(note=note, message=message)
        flash(message, "message" if status == 200 else "error")
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

    @app.post("/project/web-access")
    def set_web_access():
        slug = request.form.get("slug", "").strip().lower()
        web_mode = request.form.get("web_mode", "")
        try:
            manager.set_web_access(slug, web_mode, request.form.get("proxy_origin", ""))
        except (CloudflareError, ValueError) as error:
            return jsonify(message=str(error)), 422
        except OSError:
            return jsonify(message="无法保存本机入口设置，请重试。"), 500
        label = "反向代理" if web_mode == "proxy" else "302 跳转直连"
        return jsonify(message=f"固定入口已切换为{label}。")

    @app.post("/project/<action>")
    def change(action):
        slug = request.form.get("slug", "").strip().lower()
        try:
            if action in ("provision", "mapping"):
                manager.begin(slug, action)
            elif action == "stop":
                manager.stop(slug)
            elif action == "start-all":
                started, failed = manager.start_saved_projects()
                message = f"已发起 {started} 个项目的启动。"
                if failed:
                    message += f"{failed} 个项目启动失败，请查看运行日志。"
                flash(message, "error" if failed else "message")
            elif action == "stop-all":
                stopped = manager.stop_running_projects()
                flash(f"已向 {stopped} 个运行中的项目发送停止请求。")
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
        manager.start_saved_projects(restore_only=True)
        webbrowser.open(ADMIN_URL)
        server.serve_forever()
    finally:
        manager.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
