"""Paths and one-time migration for this project's local data."""

import json
import msvcrt
import os
from pathlib import Path
from secrets import token_urlsafe
from tempfile import NamedTemporaryFile, gettempdir


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"
PROJECTS_FILE = DATA_DIR / "projects.json"
PLATFORMS_FILE = DATA_DIR / "platforms.json"
ACCESS_ADDRESS_FILE = DATA_DIR / "当前访问地址.txt"
PAGES_CONFIG_FILE = DATA_DIR / "wrangler.jsonc"
WRANGLER_CONFIG_DIR = DATA_DIR / "wrangler"
WRANGLER_PROFILE_FILE = WRANGLER_CONFIG_DIR / ".wrangler" / "config" / "default.toml"
WRANGLER_CACHE_DIR = DATA_DIR / "cache"
TEMP_DIR = DATA_DIR / "tmp"


def _write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _migrate_file(source, destination, *, remove_source=True, transform=None):
    if not source.is_file():
        return
    original = source.read_bytes()
    contents = transform(original) if transform else original
    if destination.exists():
        if remove_source and destination.read_bytes() != contents:
            raise OSError(f"数据迁移遇到同名文件，请检查 {destination.name}。")
        if remove_source:
            if source.read_bytes() != original:
                raise OSError(f"迁移时源文件发生变化，请检查 {source.name}。")
            source.unlink()
        return
    _write_bytes(destination, contents)
    if destination.read_bytes() != contents:
        raise OSError(f"数据迁移校验失败，请检查 {destination.name}。")
    if remove_source:
        if source.read_bytes() != original:
            raise OSError(f"迁移时源文件发生变化，请检查 {source.name}。")
        source.unlink()


def _pages_config(contents):
    config = json.loads(contents.decode("utf-8-sig"))
    config["pages_build_output_dir"] = "../pages/public"
    for database in config.get("d1_databases", []):
        database.setdefault("migrations_dir", "../pages/migrations")
    return (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def ensure_data():
    """Migrate legacy files and initialize settings for a fresh installation."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = DATA_DIR / ".migration.lock"
    with lock_path.open("a+b") as lock:
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        try:
            marker = DATA_DIR / ".migration-complete"
            if not marker.exists():
                legacy_dir = Path(os.environ.get("LOCALAPPDATA", gettempdir())) / "wxcloud-natmap"
                for name in ("settings.json", "projects.json", "platforms.json"):
                    _migrate_file(legacy_dir / name, DATA_DIR / name)
                _migrate_file(PROJECT_DIR / "当前访问地址.txt", ACCESS_ADDRESS_FILE)
                _migrate_file(PROJECT_DIR / "pages" / "wrangler.jsonc", PAGES_CONFIG_FILE, transform=_pages_config)
                shared_profile = Path(os.environ.get("APPDATA", "")) / "xdg.config/.wrangler/config/default.toml"
                _migrate_file(shared_profile, WRANGLER_PROFILE_FILE, remove_source=False)
                _write_bytes(marker, b"1\n")
            # Existing projects need their original token to update their Pages endpoints.
            if not SETTINGS_FILE.exists() and not PROJECTS_FILE.exists():
                settings = {"redirect": {"token": token_urlsafe(32)}}
                _write_bytes(SETTINGS_FILE, (json.dumps(settings, indent=2) + "\n").encode("utf-8"))
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
