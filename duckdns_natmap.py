"""Forward the local web service and publish its public address to the fixed entry."""

import argparse
from contextlib import ExitStack, closing
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from ipaddress import IPv4Address, ip_address
from itertools import cycle
import json
import msvcrt
from pathlib import Path
from queue import Empty, Queue
import shutil
import socket
import ssl
import subprocess
from tempfile import gettempdir
from threading import Event, Thread
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from data_storage import ACCESS_ADDRESS_FILE, PROJECTS_FILE, SETTINGS_FILE, ensure_data
from pages_projects import CloudflareError, PROJECT_NAME, project_token


DEFAULT_NATMAP = Path(__file__).with_name("natmap-win-x64.exe")
DEFAULT_TARGET_HOST = "127.0.0.1"
ADMIN_PORT = 8765
MAPPING_SCHEMES = ("auto", "http", "https", "tcp")
RDP_PORT = 3389
# Keep the original tcp:// records for existing RDP entry pages.
TCP_ADDRESS_SCHEME = "tcp-address"
# X.224 Connection Request with an RDP Negotiation Request for TLS and CredSSP.
RDP_NEGOTIATION = bytes.fromhex("03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 0b 00 00 00")
MAPPING_TARGETS = (
    ("example.com", "turn.cloudflare.com:3478"),
    ("qq.com", "turn.cloudflare.com:80"),
)
KEEPALIVE_SECONDS = 15
RESTART_DELAY_SECONDS = 5
ADDRESS_RETRY_DELAY_SECONDS = 15
FIRST_MAPPING_TIMEOUT_SECONDS = 120
REDIRECT_RETRY_SECONDS = 30
REDIRECT_REFRESH_SECONDS = 60


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1 到 65535 之间")
    return number


def target_endpoint(host, port_number):
    return f"[{host}]:{port_number}" if ":" in host else f"{host}:{port_number}"


def normalize_target_host(value):
    host = value.strip() if isinstance(value, str) else ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        address = ip_address(host)
    except ValueError as error:
        raise ValueError("请输入服务的 IPv4 或 IPv6 地址，端口请单独填写。") from error
    address = getattr(address, "ipv4_mapped", None) or address
    if address.version == 6 and (address.is_link_local or address.scope_id):
        raise ValueError("请输入可直接访问的 IPv4 或 IPv6 地址，链路本地 IPv6 需要网卡作用域。")
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("请输入运行服务的设备 IP 地址。")
    return str(address)


def available_bind_port(target_port):
    for _ in range(10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            probe.bind(("0.0.0.0", 0))
            bind_port = probe.getsockname()[1]
            if bind_port != target_port:
                return bind_port
    raise OSError("无法分配 NATMap 本地端口。")


def parse_mapping(line):
    # NATMap prints the same six fields it passes to its notification hook.
    fields = line.split()
    if len(fields) != 6 or fields[4].lower() != "tcp":
        return None
    try:
        address = IPv4Address(fields[0])
        public_port = port(fields[1])
    except (ValueError, argparse.ArgumentTypeError):
        return None
    if address.is_global and not address.is_multicast:
        return address, public_port
    return None


class RedirectUpdateError(RuntimeError):
    def __init__(self, message, *, allow_fallback=False):
        super().__init__(message)
        self.allow_fallback = allow_fallback


class NoUpdateRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def update_redirect(url, token, scheme, address, public_port, *, system_proxy=False):
    request = Request(
        f"{url}/_natmap",
        data=json.dumps({"ip": str(address), "port": public_port, "scheme": scheme}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "NATMap-Manager/1.0 (+https://github.com/pppyl/natmap-manager)",
        },
        method="PUT",
    )
    proxy = ProxyHandler() if system_proxy else ProxyHandler({})
    try:
        with build_opener(proxy, NoUpdateRedirect()).open(request, timeout=10) as response:
            if response.status != 204:
                raise RedirectUpdateError(f"固定入口返回 HTTP {response.status}，更新需要 HTTP 204。")
    except HTTPError as error:
        status = error.code
        error.close()
        hints = {
            400: "Cloudflare 拒绝了映射地址或协议。",
            401: "固定入口的更新令牌未通过验证。",
            403: "Cloudflare 拒绝了固定入口更新请求。",
            404: "找不到固定入口的更新接口，请检查 Pages 部署。",
            405: "固定入口未启用更新接口，请检查 Pages 部署。",
            429: "Cloudflare 暂时限制了更新频率。",
        }
        hint = hints.get(status, "请检查固定入口的 Pages 函数。")
        raise RedirectUpdateError(
            f"HTTP {status}，{hint}", allow_fallback=status in (401, 403) or 500 <= status <= 599,
        ) from error
    except (OSError, HTTPException) as error:
        cause = error.reason if isinstance(error, URLError) else error
        if isinstance(cause, socket.gaierror):
            message = "固定入口域名解析失败。"
        elif isinstance(cause, TimeoutError):
            message = "连接固定入口超时。"
        elif isinstance(cause, ssl.SSLError):
            message = "固定入口的 HTTPS 握手或证书验证失败。"
        else:
            message = "固定入口连接中断，请检查网络。"
        raise RedirectUpdateError(message, allow_fallback=True) from error


def publish_mapping(redirect, scheme, address, public_port, direct_url, *, system_proxy, publish_via_d1):
    try:
        update_redirect(*redirect, scheme, address, public_port, system_proxy=system_proxy)
    except RedirectUpdateError as error:
        if publish_via_d1 is None or not error.allow_fallback:
            raise
        location = f"{scheme}://{direct_url}" if scheme in ("tcp", TCP_ADDRESS_SCHEME) else direct_url + "/"
        try:
            publish_via_d1(location)
        except (CloudflareError, ValueError) as fallback_error:
            raise RedirectUpdateError(f"{error} D1 同步失败。{fallback_error}") from fallback_error
        except (OSError, KeyError, TypeError) as fallback_error:
            raise RedirectUpdateError(f"{error} D1 同步失败，请检查本机平台配置。") from fallback_error
        return f"固定入口已通过 Cloudflare D1 同步。Pages 上报结果为 {error}"
    return ""


def save_access_address(text):
    temporary_file = ACCESS_ADDRESS_FILE.with_suffix(".tmp")
    try:
        ACCESS_ADDRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary_file.write_text(f"{text}\n", encoding="utf-8-sig")
        temporary_file.replace(ACCESS_ADDRESS_FILE)
    except OSError as error:
        print(f"无法更新 {ACCESS_ADDRESS_FILE.name}（{error.strerror}）。", flush=True)


def log_line(message):
    print(message, flush=True)


def detects_rdp(target_host, target_port):
    try:
        with socket.create_connection((target_host, target_port), timeout=2) as connection:
            connection.sendall(RDP_NEGOTIATION)
            with connection.makefile("rb") as response:
                header = response.read(4)
                length = int.from_bytes(header[2:], "big")
                if header[:2] != b"\x03\x00" or length not in (11, 19):
                    return False
                confirm = response.read(length - 4)
    except OSError:
        return False
    if len(confirm) != length - 4 or confirm[:4] != bytes((length - 5, 0xD0, 0, 0)) or confirm[6] != 0:
        return False
    return length == 11 or (confirm[7] in (2, 3) and confirm[9:11] == b"\x08\x00")


def detect_origin_scheme(target_port, stop, *, target_host=DEFAULT_TARGET_HOST):
    if target_port == RDP_PORT and not stop.is_set() and detects_rdp(target_host, target_port):
        return "rdp"
    # Detect HTTPS even when the origin uses a local development certificate.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    probes = (
        ("https", HTTPSConnection(target_host, target_port, timeout=2, context=context)),
        ("http", HTTPConnection(target_host, target_port, timeout=2)),
    )
    for scheme, connection in probes:
        if stop.is_set():
            break
        try:
            with closing(connection):
                connection.request("HEAD", "/")
                connection.getresponse().close()
            return scheme
        except (OSError, HTTPException):
            continue
    return None if stop.is_set() else "tcp"


def wait_for_origin(target_port, stop, report, *, scheme, target_host=DEFAULT_TARGET_HOST):
    previous_message = None
    endpoint = target_endpoint(target_host, target_port)
    while not stop.is_set():
        try:
            with socket.create_connection((target_host, target_port), timeout=3):
                pass
        except OSError:
            service = "本地服务" if scheme in ("auto", "tcp") else "本地网页服务"
            message = f"等待{service} {endpoint} 启动。"
        else:
            if stop.is_set():
                return None
            if scheme == "auto":
                report(f"本地端口 {endpoint} 已监听，正在检测协议。")
                return detect_origin_scheme(target_port, stop, target_host=target_host)
            if scheme == "tcp" and target_port == RDP_PORT and detects_rdp(target_host, target_port):
                return "rdp"
            return scheme
        if message != previous_message and not stop.is_set():
            report(message)
            previous_message = message
        stop.wait(RESTART_DELAY_SECONDS)
    return None


def read_natmap_output(stream, messages):
    try:
        for line in stream:
            messages.put(line)
    finally:
        messages.put(None)


def maintain_mapping(command, scheme, redirect, *, system_proxy=False, stop=None,
                     report=log_line, save_address=save_access_address, tcp_lookup_enabled=None,
                     publish_via_d1=None, rdp=False):
    """Run one NATMap attempt and report whether the local address could not be reused."""
    messages = Queue()
    stop = stop if stop is not None else Event()
    if stop.is_set():
        return False
    mapping = None
    redirected_mapping = None
    last_publish_note = ""
    direct_url = None
    published_scheme = TCP_ADDRESS_SCHEME if scheme == "tcp" and not rdp else scheme
    refresh_redirect_at = 0
    default_port = 443 if scheme == "https" else 80
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
    ) as process:
        reader = Thread(target=read_natmap_output, args=(process.stdout, messages))
        reader.start()
        first_mapping_deadline = time.monotonic() + FIRST_MAPPING_TIMEOUT_SECONDS
        try:
            while not stop.is_set():
                try:
                    line = messages.get(timeout=1)
                except Empty:
                    if mapping is None and time.monotonic() >= first_mapping_deadline:
                        report("等待公网 TCP 映射超时，准备重连。")
                        return False
                else:
                    if line is None:
                        report(f"NATMap 已停止输出，进程状态 {process.poll()}，准备重连。")
                        return False
                    received = parse_mapping(line)
                    if received is None:
                        message = line.rstrip()
                        report(message)
                        if "Cannot assign requested address" in message:
                            return True
                        if message.endswith((
                            "Start TCP keep-alive service failed.",
                            "STUN TCP send failed.",
                            "STUN TCP recv failed.",
                        )):
                            report(f"TCP 打洞连接失败，{RESTART_DELAY_SECONDS} 秒后更换保活和 STUN 目标重试。")
                            return False
                    elif received != mapping:
                        mapping = received
                        refresh_redirect_at = 0
                        address, public_port = mapping
                        suffix = "" if public_port == default_port else f":{public_port}"
                        direct_url = f"{address}:{public_port}" if scheme == "tcp" else f"{scheme}://{address}{suffix}"
                        report(f"公网 TCP 映射 {address}:{public_port}。")
                        report(f"直连地址 {direct_url}")
                        if scheme == "tcp":
                            save_address(f"直连地址 {direct_url}")
                        elif redirect:
                            save_address(f"等待固定入口确认。\n直连地址 {direct_url}")

                if stop.is_set() or not redirect or mapping is None or time.monotonic() < refresh_redirect_at:
                    continue
                if scheme == "tcp" and (tcp_lookup_enabled is None or not tcp_lookup_enabled(rdp)):
                    continue
                address, public_port = mapping
                try:
                    note = publish_mapping(redirect, published_scheme, address, public_port, direct_url,
                                           system_proxy=system_proxy, publish_via_d1=publish_via_d1)
                except RedirectUpdateError as error:
                    refresh_redirect_at = time.monotonic() + REDIRECT_RETRY_SECONDS
                    redirected_mapping = None
                    save_address(f"固定入口更新暂未确认。{error}\n直连地址 {direct_url}")
                    report(f"固定入口更新暂未确认。{error} {REDIRECT_RETRY_SECONDS} 秒后重试。")
                else:
                    refresh_redirect_at = time.monotonic() + REDIRECT_REFRESH_SECONDS
                    if mapping != redirected_mapping or note != last_publish_note:
                        redirected_mapping = mapping
                        last_publish_note = note
                        if scheme == "tcp":
                            message = "外网远程命令已同步。" if rdp else "TCP 外网地址已同步。"
                        else:
                            message = f"固定入口 {redirect[0]}/"
                        save_address(f"{message}\n直连地址 {direct_url}")
                        if note:
                            report(note)
                        report(message)
        finally:
            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            process.wait()
            reader.join()
    return False


def run_natmap(args, executable, redirect, *, stop=None, report=log_line,
               save_address=save_access_address, on_scheme=None, tcp_lookup_enabled=None,
               publish_via_d1=None):
    stop = stop if stop is not None else Event()
    # Also detect a listener from an older launch that predates the lock.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("0.0.0.0", args.bind_port))
        except OSError:
            report(f"无法使用本地 TCP {args.bind_port}。请检查该端口是否被占用。")
            return 1

    report(f"NATMap 将使用本地 TCP {args.bind_port} 建立映射，保活间隔 {KEEPALIVE_SECONDS} 秒。")
    configured_scheme = getattr(args, "scheme", None) or ("https" if args.https else "http")
    target_host = getattr(args, "target_host", DEFAULT_TARGET_HOST)
    last_scheme = None
    track_address = bool(redirect) or configured_scheme in ("auto", "tcp")
    consecutive_address_errors = 0
    try:
        for keepalive_host, stun_server in cycle(MAPPING_TARGETS):
            if track_address:
                save_address("等待公网映射。")
            detected = wait_for_origin(args.target_port, stop, report, scheme=configured_scheme, target_host=target_host)
            if detected is None or stop.is_set():
                break
            rdp = detected == "rdp"
            scheme = "tcp" if rdp else detected
            mapping_redirect = redirect if scheme != "tcp" or tcp_lookup_enabled is not None else None
            if track_address:
                save_address("等待公网映射和固定入口更新。" if scheme != "tcp" and mapping_redirect else "等待公网映射。")
            if detected != last_scheme:
                if configured_scheme == "auto":
                    if rdp:
                        report("已识别 Windows 远程桌面（RDP），使用 TCP 直连。")
                    elif scheme == "tcp":
                        report("本地端口可连接，按普通 TCP 服务建立映射。")
                    else:
                        report(f"检测到本地网页协议为 {scheme.upper()}。")
                if mapping_redirect:
                    route = "系统代理" if args.system_proxy else "直连"
                    report(f"固定入口上报方式 {route}。")
                if on_scheme is not None:
                    on_scheme("rdp" if rdp else scheme)
                last_scheme = detected
            command = [
                executable, "-4", "-k", str(KEEPALIVE_SECONDS),
                "-s", stun_server, "-h", keepalive_host,
                "-b", str(args.bind_port), "-t", target_host, "-p", str(args.target_port),
            ]
            report(f"TCP 保活目标 {keepalive_host}:80，STUN 目标 {stun_server}。")
            address_error = maintain_mapping(command, scheme, mapping_redirect, system_proxy=args.system_proxy,
                                             stop=stop, report=report, save_address=save_address,
                                             tcp_lookup_enabled=tcp_lookup_enabled, publish_via_d1=publish_via_d1,
                                             rdp=rdp)
            if stop.is_set():
                break
            if track_address:
                save_address("NATMap 正在重连。")
            retry_delay = RESTART_DELAY_SECONDS
            if address_error:
                consecutive_address_errors += 1
                if consecutive_address_errors >= len(MAPPING_TARGETS):
                    retry_delay = ADDRESS_RETRY_DELAY_SECONDS
                report(f"本地 TCP {args.bind_port} 暂时无法建立连接，{retry_delay} 秒后切换目标重试。")
            else:
                consecutive_address_errors = 0
            stop.wait(retry_delay)
    finally:
        if track_address:
            save_address("NATMap 已停止。")
    return 0


def run_locked_mapping(args, executable, redirect, *, project="", report=log_line, **options):
    project_lock = f"wxcloud-natmap-project-{project}.lock" if project else "wxcloud-natmap.lock"
    lock_names = (project_lock, f"wxcloud-natmap-tcp-{args.bind_port}.lock")
    with ExitStack() as locks:
        for name in lock_names:
            lock = locks.enter_context((Path(gettempdir()) / name).open("a+b"))
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except PermissionError:
                report("该项目已在运行，或 NATMap 本地端口已被其他任务占用。")
                return 1
        return run_natmap(args, executable, redirect, report=report, **options)


def main():
    try:
        ensure_data()
    except (OSError, ValueError) as error:
        print(f"无法迁移项目数据：{error}", flush=True)
        return 1
    parser = argparse.ArgumentParser(description="建立 NATMap TCP IPv4 映射并更新固定入口")
    parser.add_argument("--natmap", default=str(DEFAULT_NATMAP), help="NATMap 可执行文件路径")
    parser.add_argument("--project", help="使用管理页面中已保存项目的子域名")
    parser.add_argument("--target-host", help="目标服务的 IPv4 或 IPv6 地址，默认读取项目设置")
    parser.add_argument("--target-port", type=port, help="目标服务端口，默认读取项目设置")
    parser.add_argument("--bind-port", type=port, help="NATMap 本地监听端口，默认读取项目设置")
    parser.add_argument("--settings", type=Path, help=f"端口和固定入口配置，默认 {SETTINGS_FILE}")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--publish", action="store_true", help="发布到固定入口（默认）")
    mode.add_argument("--test", dest="publish", action="store_false", help="只打洞并显示公网测试地址")
    parser.set_defaults(publish=True)
    parser.add_argument("--system-proxy", action="store_true", help="使用系统代理上报固定入口，默认直连")
    parser.add_argument("--https", action="store_true", help="本地服务已启用 HTTPS 时，显示 HTTPS 链接")
    args = parser.parse_args()

    project = None
    if args.project:
        args.project = args.project.strip().lower()
        if not PROJECT_NAME.fullmatch(args.project):
            parser.error("项目子域名无效。")
        try:
            project_data = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
            projects = project_data.get("projects", []) if isinstance(project_data, dict) else project_data
            project = next(item for item in projects if item.get("slug") == args.project)
            if project.get("manager_target"):
                parser.error("NATMap 管理页项目需要从管理界面启动其 HTTPS 入口。")
            if not project.get("entry") and (project.get("scheme") != "tcp" or project.get("owner")):
                raise ValueError
        except (OSError, ValueError, TypeError, AttributeError, StopIteration):
            parser.error("找不到已创建的项目，请检查 --project 指定的子域名。")

    try:
        settings = {}
        if args.settings or SETTINGS_FILE.is_file():
            settings = json.loads((args.settings or SETTINGS_FILE).read_text(encoding="utf-8-sig"))
            if not isinstance(settings, dict):
                raise ValueError
        target_port = project.get("target_port") if project else settings.get("target_port", 21580)
        args.target_port = args.target_port or port(str(target_port))
        origin_settings = project if project else settings
        bind_port = project.get("bind_port") if project else settings.get("bind_port", 21581)
        args.bind_port = args.bind_port or (port(str(bind_port)) if bind_port else available_bind_port(args.target_port))
        if project:
            args.scheme = project.get("scheme", "http")
            if args.scheme not in MAPPING_SCHEMES:
                raise ValueError
            if args.https and args.scheme != "tcp":
                args.scheme = "https"
    except (OSError, ValueError, argparse.ArgumentTypeError):
        parser.error("无法读取设置，请检查 JSON 格式和端口范围。")

    host = args.target_host if args.target_host is not None else origin_settings.get("target_host", DEFAULT_TARGET_HOST)
    try:
        args.target_host = normalize_target_host(host)
    except ValueError as error:
        parser.error(str(error))
    if ip_address(args.target_host).is_loopback and args.target_port == ADMIN_PORT:
        parser.error("请在管理界面选择「NATMap 管理页（8765）」来创建受保护的远程入口。")

    def tcp_lookup_ready(rdp):
        key = "rdp_lookup_ready" if rdp else "tcp_lookup_ready"
        return bool(project and project.get("entry") and project.get("owner") and project.get(key))

    redirect = None
    has_tcp_entry = tcp_lookup_ready(False) or tcp_lookup_ready(True)
    if args.publish and (getattr(args, "scheme", None) != "tcp" or has_tcp_entry):
        try:
            redirect_settings = settings["redirect"]
            entry_url = project["entry"] if project else redirect_settings["url"]
            entry = urlsplit(entry_url)
            redirect_token = redirect_settings["token"]
            if (
                entry.scheme != "https"
                or not entry.hostname
                or not entry.hostname.endswith((".pages.dev", ".workers.dev"))
                or entry.netloc != entry.hostname
                or entry.path not in ("", "/")
                or entry.query or entry.fragment
                or not isinstance(redirect_token, str) or not redirect_token.strip()
            ):
                raise ValueError
            redirect_token = redirect_token.strip()
            if project and project.get("owner"):
                redirect_token = project_token(redirect_token, args.project)
            redirect = (f"https://{entry.hostname}", redirect_token)
        except (KeyError, TypeError, AttributeError, ValueError):
            parser.error("发布模式需要有效的固定入口和更新令牌。请用 --project 指定已保存的项目。")

    if ip_address(args.target_host).is_loopback and args.bind_port == args.target_port:
        parser.error("NATMap 监听端口必须与本机服务端口不同")
    executable = shutil.which(args.natmap)
    if executable is None:
        parser.error("找不到 NATMap，请通过 --natmap 指定 Windows 可执行文件")

    print("按 Ctrl+C 停止。", flush=True)
    try:
        redirect_settings = settings.get("redirect")
        legacy_url = redirect_settings.get("url", "") if isinstance(redirect_settings, dict) else ""
        legacy_project = project and project.get("entry") and isinstance(legacy_url, str) and project["entry"].rstrip("/") == legacy_url.rstrip("/")
        lock_project = "" if legacy_project else args.project or ""
        return run_locked_mapping(args, executable, redirect, project=lock_project,
                                  tcp_lookup_enabled=tcp_lookup_ready if has_tcp_entry else None)
    except KeyboardInterrupt:
        return 0
    except OSError as error:
        print(f"无法运行 NATMap（{error.strerror}）。")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
