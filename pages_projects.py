"""Create and deploy Pages projects for the local NATMap manager."""

from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
from queue import Empty, Queue
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
import webbrowser

from data_storage import TEMP_DIR, WRANGLER_CACHE_DIR, WRANGLER_CONFIG_DIR
from platform_settings import PAGES_DIR, default_platform, pages_config, read_wrangler_profile


WRANGLER_VERSION = "4.162.0"
PROJECT_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?\Z")
PAGES_HOST = re.compile(r"[a-z0-9-]+\.pages\.dev\Z")


def powershell_path(path):
    return "'" + str(path).replace("'", "''") + "'"


LOGIN_COMMAND = (
    f"$env:XDG_CONFIG_HOME = {powershell_path(WRANGLER_CONFIG_DIR)}\n"
    f"$env:XDG_CACHE_HOME = {powershell_path(WRANGLER_CACHE_DIR)}\n"
    "$env:CLOUDFLARE_AUTH_USE_KEYRING = 'false'\n"
    f"npx.cmd --yes wrangler@{WRANGLER_VERSION} login "
    "--scopes user:read account:read pages:write d1:write"
)


def project_token(base_token, project):
    return hmac.digest(base_token.encode(), f"pages:{project}".encode(), "sha256").hex()


class CloudflareError(RuntimeError):
    pass


class PagesNameUnavailable(CloudflareError):
    pass


def wrangler_environment():
    environment = {
        **os.environ,
        "XDG_CONFIG_HOME": str(WRANGLER_CONFIG_DIR),
        "XDG_CACHE_HOME": str(WRANGLER_CACHE_DIR),
        "CLOUDFLARE_AUTH_USE_KEYRING": "false",
    }
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR"):
        environment[key] = str(TEMP_DIR)
    return environment


def run_wrangler(*args, environment=None, cwd=None):
    npx = shutil.which("npx.cmd")
    if not npx:
        raise CloudflareError("创建 Pages 项目需要 Node.js 和 npx.cmd。")
    try:
        return subprocess.run(
            [npx, "--yes", f"wrangler@{WRANGLER_VERSION}", *args], cwd=cwd,
            env=environment if environment is not None else wrangler_environment(),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CloudflareError("Wrangler 未能在两分钟内完成操作，请重试。") from error


def wrangler_token(refresh):
    settings = read_wrangler_profile()
    if settings.get("refresh_token") and "pages:write" in settings.get("scopes", []):
        try:
            fresh = datetime.fromisoformat(settings["expiration_time"]) > datetime.now(timezone.utc) + timedelta(minutes=3)
        except (KeyError, ValueError, TypeError):
            fresh = False
        if not fresh:
            refresh()
            settings = read_wrangler_profile()
    if "pages:write" in settings.get("scopes", []) and settings.get("oauth_token"):
        return settings["oauth_token"]
    raise CloudflareError("请先在「平台配置」点击「登录 Cloudflare」完成授权。")


def cloudflare_request(token, path, *, method="GET", payload=None, missing_ok=False, auth_source="wrangler"):
    request = Request(
        f"https://api.cloudflare.com/client/v4{path}", method=method,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=20) as response:
            result = json.load(response)
    except HTTPError as error:
        with error:
            try:
                codes = ", ".join(str(item.get("code")) for item in json.load(error).get("errors", []))
            except ValueError:
                codes = ""
        if missing_ok and error.code == 404:
            return None
        if error.code in (401, 403):
            if auth_source == "wrangler":
                raise CloudflareError("Cloudflare 登录已过期或缺少权限，请在「平台配置」重新登录。") from error
            raise CloudflareError("Cloudflare API Token 无效或缺少所需权限，请检查平台配置。") from error
        raise CloudflareError(f"Cloudflare 请求失败（HTTP {error.code}，错误码 {codes or '未知'}）。") from error
    except (URLError, OSError, ValueError) as error:
        raise CloudflareError("无法连接 Cloudflare API。请检查网络后重试。") from error
    if not isinstance(result, dict) or not result.get("success"):
        raise CloudflareError("Cloudflare 没有确认该操作成功。")
    return result


def list_cloudflare_resources(token, path):
    resources = []
    page = 1
    while True:
        response = cloudflare_request(token, f"{path}?page={page}&per_page=100")
        rows = response.get("result")
        if not isinstance(rows, list):
            raise CloudflareError("Cloudflare 返回的账号或数据库列表无效。")
        resources.extend(rows)
        info = response.get("result_info") or {}
        if info.get("total_count") is not None:
            if len(resources) >= info["total_count"] or not rows:
                return resources
        elif info.get("total_pages") is not None:
            if page >= info["total_pages"] or not rows:
                return resources
        elif len(rows) < 100:
            return resources
        page += 1


def discover_cloudflare_connections():
    def refresh():
        environment = wrangler_environment()
        for key in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL"):
            environment.pop(key, None)
        run_wrangler("whoami", "--json", environment=environment)

    token = wrangler_token(refresh)
    accounts = list_cloudflare_resources(token, "/accounts")
    if not accounts:
        raise CloudflareError("当前登录没有可用的 Cloudflare 账号。")
    choices = []
    for account in accounts:
        account_id = account["id"]
        databases = list_cloudflare_resources(token, f"/accounts/{account_id}/d1/database")
        for database in databases:
            choices.append({
                "account_id": account_id, "account_name": account.get("name") or "Cloudflare 账号",
                "database_id": database["uuid"], "database_name": database["name"],
            })
        if not databases:
            choices.append({
                "account_id": account_id, "account_name": account.get("name") or "Cloudflare 账号",
                "database_id": "", "database_name": "",
            })
    return token, choices


class WranglerLogin:
    def __init__(self, configure=None):
        self.lock = Lock()
        self.stop = Event()
        self.thread = None
        self.phase = "idle"
        self.message = ""
        self.url = ""
        self.configure = configure
        self.choices = []
        self.revision = 0

    def snapshot(self):
        with self.lock:
            return {"phase": self.phase, "message": self.message, "url": self.url,
                    "choices": list(self.choices), "revision": self.revision}

    def start(self):
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise CloudflareError("已有登录正在进行，请先完成浏览器中的授权。")
            npx = shutil.which("npx.cmd")
            if not npx:
                raise CloudflareError("未找到 Node.js，请先安装 Node.js 后再登录。")
            self.stop.clear()
            self.phase = "starting"
            self.message = "正在准备 Cloudflare 登录页面。"
            self.url = ""
            self.choices = []
            self.thread = Thread(target=self.run, args=(npx,), name="wrangler-login", daemon=True)
            self.thread.start()

    def start_configure(self, selection=None):
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise CloudflareError("正在处理登录或连接配置，请稍候。")
            if selection is not None and selection not in {choice["value"] for choice in self.choices}:
                raise CloudflareError("所选账号或数据库已失效，请重新获取。")
            self.phase = "configuring"
            self.message = "正在获取 Cloudflare 账号和数据库。"
            self.url = ""
            self.thread = Thread(target=self.finish_configuration, args=(selection,), daemon=True)
            self.thread.start()

    def finish_configuration(self, selection=None):
        try:
            result = self.configure(selection) if self.configure else {"message": "Cloudflare 登录成功，授权已保存。"}
            with self.lock:
                self.choices = result.get("choices", [])
                self.phase = "choose" if self.choices else "success"
                self.message = result["message"]
                if result.get("updated"):
                    self.revision += 1
        except (CloudflareError, OSError, ValueError, KeyError, TypeError) as error:
            message = str(error) if isinstance(error, CloudflareError) else "请检查本机配置后重试。"
            with self.lock:
                self.phase = "error"
                prefix = "已登录，但连接配置未完成。" if read_wrangler_profile().get("oauth_token") else "获取连接配置失败。"
                self.message = f"{prefix}{message}"
                self.choices = []

    def close(self):
        self.stop.set()
        with self.lock:
            thread = self.thread
        if thread is not None:
            thread.join(timeout=10)

    def run(self, npx):
        process = None
        output = Queue()
        error_message = "登录未完成，请检查网络后重试。"
        try:
            environment = wrangler_environment()
            for key in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL"):
                environment.pop(key, None)
            scopes = ["user:read", "account:read", "pages:write", "d1:write"]
            for scope in read_wrangler_profile().get("scopes", []):
                if (isinstance(scope, str) and scope != "offline_access"
                    and re.fullmatch(r"[a-z0-9_-]+:[a-z0-9_-]+", scope) and scope not in scopes):
                    scopes.append(scope)
            process = subprocess.Popen(
                [npx, "--yes", f"wrangler@{WRANGLER_VERSION}", "login",
                 "--browser=false", "--scopes", *scopes],
                cwd=TEMP_DIR, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW,
            )

            def read_output():
                try:
                    for line in process.stdout:
                        output.put(line)
                finally:
                    output.put(None)

            Thread(target=read_output, daemon=True).start()
            deadline = time.monotonic() + 300
            while not self.stop.is_set() and time.monotonic() < deadline:
                try:
                    line = output.get(timeout=1)
                except Empty:
                    continue
                if line is None:
                    if process.wait(timeout=5) == 0 and read_wrangler_profile().get("oauth_token"):
                        with self.lock:
                            self.phase = "configuring"
                            self.message = "登录成功，正在获取 Cloudflare 账号和数据库。"
                            self.url = ""
                        self.finish_configuration()
                        return
                    break
                if "EADDRINUSE" in line or "port is already in use" in line:
                    error_message = "本机授权端口 8976 正在使用，请关闭其他登录窗口后重试。"
                elif "access_denied" in line or "consent denied" in line.lower():
                    error_message = "未完成 Cloudflare 授权，请重新登录并允许授权。"
                match = re.search(r"https://dash\.cloudflare\.com/oauth2/auth\?[^\s\x1b]+", line)
                if match and not self.url:
                    url = match.group(0)
                    parsed = urlsplit(url)
                    if parsed.scheme == "https" and parsed.netloc == "dash.cloudflare.com":
                        with self.lock:
                            self.phase = "waiting"
                            self.message = "请在打开的 Cloudflare 页面登录并点击 Allow，然后返回这里。"
                            self.url = url
                        try:
                            webbrowser.open(url, new=2)
                        except (OSError, webbrowser.Error):
                            pass
            if self.stop.is_set():
                error_message = "登录已停止，请重新登录。"
            elif time.monotonic() >= deadline:
                error_message = "等待授权超时，请重新登录。"
        except (OSError, subprocess.SubprocessError):
            error_message = "无法启动 Cloudflare 登录，请检查 Node.js 和网络后重试。"
        finally:
            if process is not None and process.poll() is None:
                try:
                    result = subprocess.run(
                        ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=5, creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    if result.returncode and process.poll() is None:
                        process.terminate()
                except (OSError, subprocess.SubprocessError):
                    if process.poll() is None:
                        try:
                            process.terminate()
                        except OSError:
                            pass
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
        with self.lock:
            self.phase = "error"
            self.message = error_message
            self.url = ""


def has_project_owner(project, owner_id):
    production = (project.get("deployment_configs") or {}).get("production") or {}
    variables = production.get("env_vars") or {}
    return (variables.get("NATMAP_MANAGER_ID") or {}).get("value") == owner_id


class PagesProjects:
    def __init__(self, platform=None):
        self.platform = platform if platform is not None else default_platform()
        self.account = self.platform.account_id
        self.config = pages_config()
        legacy_databases = self.config.get("d1_databases", [])
        self.legacy_database = legacy_databases[0]["database_id"] if legacy_databases else None
        self.config.setdefault("compatibility_date", "2026-11-16")
        self.config["d1_databases"] = [{
            "binding": "REDIRECT_DB", "database_name": self.platform.database_name,
            "database_id": self.platform.database_id,
        }]

    def wrangler(self, *args, cwd=None):
        environment = wrangler_environment()
        environment["CLOUDFLARE_ACCOUNT_ID"] = self.account
        if self.platform.auth_source == "token":
            environment["CLOUDFLARE_API_TOKEN"] = self.platform.api_token
        elif self.platform.auth_source == "wrangler":
            environment.pop("CLOUDFLARE_API_TOKEN", None)
        return run_wrangler(*args, environment=environment, cwd=cwd)

    def token(self):
        if self.platform.auth_source == "token":
            return self.platform.api_token
        if self.platform.auth_source == "environment":
            if token := os.environ.get("CLOUDFLARE_API_TOKEN"):
                return token
            raise CloudflareError("当前进程没有 CLOUDFLARE_API_TOKEN 环境变量。")
        return wrangler_token(lambda: self.wrangler("whoami", "--json"))

    def api(self, token, path, **options):
        return self.account_api(token, f"/pages/projects{path}", **options)

    def account_api(self, token, path, *, method="GET", payload=None, missing_ok=False):
        result = cloudflare_request(
            token, f"/accounts/{self.account}{path}", method=method, payload=payload,
            missing_ok=missing_ok, auth_source=self.platform.auth_source,
        )
        return None if result is None else result["result"]

    def check_connection(self):
        token = self.token()
        self.api(token, "?per_page=1")
        database = self.account_api(token, f"/d1/database/{self.platform.database_id}")
        return database["name"]

    def prepare_database(self, token):
        if self.platform.database_id == self.legacy_database:
            return
        path = f"/d1/database/{self.platform.database_id}/query"
        tables = self.account_api(token, path, method="POST", payload={
            "sql": "SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'natmap_projects'",
        })
        if tables and tables[0].get("results"):
            return
        result = self.account_api(token, path, method="POST", payload={
            "sql": "CREATE TABLE IF NOT EXISTS natmap_projects ("
                   "project TEXT PRIMARY KEY NOT NULL, location TEXT NOT NULL, expires_at INTEGER NOT NULL)",
        })
        if not result or not result[0].get("success"):
            raise CloudflareError("D1 未确认 NATMap 数据表已准备好。")

    def discard_new_project(self, token, name, project_id, owner_id):
        project = self.api(token, f"/{name}", missing_ok=True)
        if project is None:
            return
        if (not project_id or project.get("id") != project_id or project.get("name") != name
            or not has_project_owner(project, owner_id)
            or project.get("latest_deployment") or project.get("canonical_deployment")):
            raise CloudflareError("无法确认临时项目仍为空项目。")
        self.api(token, f"/{name}", method="DELETE", missing_ok=True)

    def deploy(self, name, owner_id, branch):
        public_vars = {"NATMAP_PROJECT": name, "NATMAP_MANAGER_ID": owner_id}
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix="natmap-pages-", dir=TEMP_DIR) as directory:
            folder = Path(directory)
            shutil.copytree(PAGES_DIR / "public", folder / "public")
            config = {**self.config, "name": name, "vars": public_vars, "pages_build_output_dir": "./public"}
            (folder / "wrangler.jsonc").write_text(json.dumps(config, indent=2), encoding="utf-8")
            result = self.wrangler("pages", "deploy", "--project-name", name, "--branch", branch, cwd=folder)
        if result.returncode:
            raise CloudflareError("Pages 部署未成功。请检查 Cloudflare 登录和网络，然后重试。")

    def matches_deployment(self, project, host, owner_id):
        production = (project.get("deployment_configs") or {}).get("production") or {}
        env_vars = production.get("env_vars") or {}
        database = (production.get("d1_databases") or {}).get("REDIRECT_DB") or {}
        return (
            project.get("subdomain") == host and has_project_owner(project, owner_id)
            and (env_vars.get("REDIRECT_TOKEN") or {}).get("type") == "secret_text"
            and (database.get("id") or database.get("database_id")) == self.platform.database_id
        )

    def deploy_remote_lookup(self, name, entry, owner_id):
        token = self.token()
        project = self.api(token, f"/{name}", missing_ok=True)
        host = urlsplit(entry).netloc
        if not project or not self.matches_deployment(project, host, owner_id):
            raise CloudflareError("无法确认项目归属和 D1 绑定。请在平台配置中选中该项目原来的 Cloudflare 连接。")
        if project.get("production_branch") != "main":
            raise CloudflareError("这个 Pages 项目的生产分支已变更，请在 Cloudflare 中检查项目配置。")
        if self.remote_lookup_deployed(entry):
            return
        self.deploy(name, owner_id, "main")
        if not self.matches_deployment(self.api(self.token(), f"/{name}"), host, owner_id):
            raise CloudflareError("外网链接部署后校验失败，请重试。")

    @staticmethod
    def remote_lookup_deployed(entry):
        request = Request(f"{entry}/remote/", method="HEAD", headers={"User-Agent": "NATMap-Manager/1.0"})
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
                return response.headers.get("X-NATMap-Remote-Version") == "3"
        except (OSError, ValueError):
            return False

    def provision(self, name, owner_id, redirect_token):
        if not PROJECT_NAME.fullmatch(name):
            raise ValueError("无效的 Pages 项目名称。")

        token = self.token()
        expected_host = f"{name}.pages.dev"
        public_vars = {"NATMAP_PROJECT": name, "NATMAP_MANAGER_ID": owner_id}
        project = self.api(token, f"/{name}", missing_ok=True)
        created = project is None
        if created:
            variables = {key: {"type": "plain_text", "value": value} for key, value in public_vars.items()}
            variables["REDIRECT_TOKEN"] = {"type": "secret_text", "value": redirect_token}
            project = self.api(token, "", method="POST", payload={
                "name": name,
                "production_branch": "main",
                "deployment_configs": {"production": {"env_vars": variables}},
            })
        elif not has_project_owner(project, owner_id):
            raise PagesNameUnavailable(f"{name} 已是账号中的 Pages 项目名称。请换一个子域名。")

        host = project.get("subdomain") or ""
        if host != expected_host:
            if not PAGES_HOST.fullmatch(host):
                raise CloudflareError(f"Cloudflare 未确认 {expected_host} 的分配结果，请重试。")
            message = f"{expected_host} 已被占用。请换一个子域名。"
            if created:
                try:
                    self.discard_new_project(token, name, project.get("id"), owner_id)
                except CloudflareError as error:
                    raise PagesNameUnavailable(f"{message} Cloudflare 上的临时空项目清理未完成。") from error
            raise PagesNameUnavailable(message)

        self.prepare_database(token)
        self.deploy(name, owner_id, "main")

        deployed = self.api(self.token(), f"/{name}")
        if not self.matches_deployment(deployed, expected_host, owner_id):
            raise CloudflareError("Pages 配置校验失败，请重试创建。")
        return f"https://{expected_host}"
