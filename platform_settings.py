"""Local Cloudflare connection settings and Wrangler login information."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from secrets import token_urlsafe
from tempfile import NamedTemporaryFile
from threading import RLock
import tomllib

from data_storage import PAGES_CONFIG_FILE, PLATFORMS_FILE, WRANGLER_PROFILE_FILE


PAGES_DIR = Path(__file__).with_name("pages")
AUTH_LABELS = {"wrangler": "Wrangler 登录", "token": "API Token", "environment": "环境变量"}
SCOPE_LABELS = {
    "user:read": "读取用户信息", "account:read": "读取账号信息", "offline_access": "刷新登录",
    "workers:write": "管理 Workers", "pages:write": "管理 Pages", "d1:write": "管理 D1",
}


def pages_config():
    try:
        return json.loads(PAGES_CONFIG_FILE.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return {}


def read_wrangler_profile():
    try:
        return tomllib.loads(WRANGLER_PROFILE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def wrangler_login_status():
    profile = read_wrangler_profile()
    status = "尚未登录"
    expires_at = ""
    if profile.get("oauth_token"):
        status = "已登录"
        try:
            expiry = datetime.fromisoformat(profile["expiration_time"])
            expires_at = expiry.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M UTC+8")
            if expiry <= datetime.now(timezone.utc):
                status = "已过期，可自动刷新" if profile.get("refresh_token") else "已过期"
        except (KeyError, ValueError, TypeError):
            status = "已配置，未读取到有效期"
    return {"status": status, "scopes": profile.get("scopes") or [], "labels": SCOPE_LABELS,
            "expires_at": expires_at}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, ensure_ascii=False, indent=2)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class PlatformProfile:
    id: str
    name: str
    account_id: str
    database_id: str
    database_name: str
    auth_source: str = "wrangler"
    api_token: str = ""

    def __post_init__(self):
        if not self.name or len(self.name) > 60:
            raise ValueError("请填写配置名称，最多 60 个字。")
        if not re.fullmatch(r"[a-f0-9]{32}", self.account_id):
            raise ValueError("Cloudflare 账号 ID 应为 32 位十六进制字符。")
        if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", self.database_id):
            raise ValueError("请填写 D1 数据库的 UUID。")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", self.database_name):
            raise ValueError("请填写有效的 D1 数据库名称。")
        if self.auth_source not in AUTH_LABELS:
            raise ValueError("请选择 Cloudflare 授权来源。")
        if self.auth_source == "token" and not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,512}", self.api_token):
            raise ValueError("请输入有效的 Cloudflare API Token。")

    def public(self):
        token_configured = {
            "token": bool(self.api_token), "environment": bool(os.getenv("CLOUDFLARE_API_TOKEN")),
        }.get(self.auth_source, False)
        return {
            "id": self.id, "name": self.name, "account_id": self.account_id,
            "database_id": self.database_id, "database_name": self.database_name,
            "auth_source": self.auth_source, "auth_label": AUTH_LABELS[self.auth_source],
            "token_configured": token_configured,
        }


def default_platform():
    return PlatformSettings(PLATFORMS_FILE).selected()


class PlatformSettings:
    def __init__(self, path):
        self.path = path
        self.lock = RLock()
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.profiles = {row["id"]: PlatformProfile(**row) for row in data["profiles"]}
            self.default_id = data.get("default_id")
        else:
            self.profiles = {}
            self.default_id = None

    def snapshot(self):
        with self.lock:
            return [profile.public() for profile in self.profiles.values()], self.default_id

    def get(self, profile_id):
        with self.lock:
            if profile_id not in self.profiles:
                raise ValueError("找不到这个平台配置。")
            return self.profiles[profile_id]

    def selected(self):
        with self.lock:
            profile = self.profiles.get(self.default_id)
            if profile is None:
                raise ValueError("请先在「平台配置」中添加并选择 Cloudflare 配置。")
            return profile

    def persist(self, profiles, default_id):
        write_json(self.path, {"profiles": [asdict(profile) for profile in profiles.values()], "default_id": default_id})
        self.profiles, self.default_id = profiles, default_id

    def save(self, profile_id, values, token, make_default):
        with self.lock:
            previous = self.get(profile_id) if profile_id else None
            profile_id = profile_id or token_urlsafe(12)
            if values["auth_source"] == "token":
                token = token or (previous.api_token if previous else "")
            else:
                token = ""
            profile = PlatformProfile(profile_id, **values, api_token=token)
            default_id = profile_id if make_default or not self.profiles else self.default_id
            self.persist({**self.profiles, profile_id: profile}, default_id)
            return profile_id

    def set_default(self, profile_id):
        with self.lock:
            self.get(profile_id)
            self.persist(self.profiles, profile_id)

    def ensure_discovered(self, account_id, database_id, database_name):
        with self.lock:
            for profile in self.profiles.values():
                if profile.account_id == account_id and profile.database_id == database_id:
                    if self.default_id not in self.profiles:
                        self.persist(self.profiles, profile.id)
                        return True
                    return False
            profile = PlatformProfile(
                token_urlsafe(12), "Cloudflare 自动配置", account_id, database_id,
                database_name, "wrangler",
            )
            default_id = self.default_id if self.default_id in self.profiles else profile.id
            self.persist({**self.profiles, profile.id: profile}, default_id)
            return True

    def delete(self, profile_id):
        with self.lock:
            self.get(profile_id)
            profiles = {key: value for key, value in self.profiles.items() if key != profile_id}
            default_id = next(iter(profiles), None) if profile_id == self.default_id else self.default_id
            self.persist(profiles, default_id)
