#!/usr/bin/env python3
"""从订阅源拉取节点，xray 与 sing-box **各自独立**测速，各自保留最快的前 N 个
（默认各 50）写进对应配置。

数据来源只有两类（2026-10-12 起不再读 node.txt）：
  * 脚本旁的 `subscriptions.txt`（每行一个 URL，`#` 注释；支持 `datepattern:`
    模板，展开为“前天/昨天/今天”三天 × N=0..5）；
  * 命令行 `-s/--subscribe URL`（可重复）。

订阅支持三种格式，自动识别：纯 URI 列表 / base64 整块 / Clash `proxies:` YAML。

核心思路（xray 与 sing-box 支持的协议/传输并不完全一致，故分开跑）：
  * 候选池按“哪个核心能真跑”分区（partition_pool）：tuic 只有 sing-box 能跑，
    xhttp 只有 xray 能跑，vless/vmess/trojan/ss/hysteria2 两边都进、各自测；
  * 每个节点起一个**临时核心实例**（xray 用 `probe_once`，sing-box 用
    `probe_once_singbox`：本地 SOCKS inbound -> 该出站），`curl --socks5-hostname`
    打 gstatic + google 两个 `generate_204`：两个都 204 才算可用，计时取较慢者；
  * 两侧各自：提前结束 -> 失败低并发复测 -> 保留前低并发统一复测 -> 按延迟排名，
    取前 N 个；xray 写 `/etc/xray/config.json`，sing-box 写 `/etc/sing-box/config.json`；
  * 运行时“选快汰死”由两侧核心自己完成：xray 的 observatory + leastPing 均衡器、
    sing-box 的 urltest。`--watch` 守护模式周期性体检两侧已部署节点，健康数低于
    阈值就自动重跑一次完整同步，维持可用节点数量。

用法：
    ./preview.sh          # 预览：只测速排名，不改配置
    ./apply.sh            # 正式应用：写入最快的一批 + 重启 xray + 部署 sing-box

    python3 sync_nodes.py --dry-run              # same as preview.sh
    python3 sync_nodes.py --restart              # same as apply.sh
    python3 sync_nodes.py --keep 50 --sb-max 50
    python3 sync_nodes.py -s https://example.com/sub.txt   # 额外拉一个订阅
    python3 sync_nodes.py --singbox-only         # 只刷新 sing-box
    python3 sync_nodes.py --watch                # 守护模式：见底自动重同步
"""

from __future__ import annotations

import argparse
import atexit
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import date, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_NODE_FILE = os.path.join(SCRIPT_DIR, "node.txt")
DEFAULT_CONFIG = "/etc/xray/config.json"
STATE_FILE = os.path.join(SCRIPT_DIR, "state.json")
DEFAULT_SUB_FILE = os.path.join(SCRIPT_DIR, "subscriptions.txt")
FETCH_TIMEOUT = 20.0          # seconds allowed per subscription download
# Local Xray SOCKS inbound: tried as a fallback when a subscription URL is not
# reachable directly (GitHub raw etc. is often blocked without a proxy).
FALLBACK_PROXY = "socks5h://127.0.0.1:54321"
DEFAULT_KEEP = 50           # 只保留最快的前 N 个节点（0 = 不限制）；xray / sing-box 各自独立取前 N
DEFAULT_SB_MAX = 50         # sing-box 侧最多保留多少个节点出站（另加 via-xray）
DEFAULT_SAMPLES = 2         # 测速时每个节点成功请求的次数（取最快一次）
XRAY_BIN = "xray"
SB_BIN = "sing-box"
ASSET_DIR = "/etc/xray"
# 双站点探测(2026-10-01): 只测 gstatic 会被"假活"节点骗过 —— 实测 mz.hkychina.com
# 对 gstatic 秒回 204(0.07s) 却黑掉一切真实流量(劫持/白名单型节点), 且 leastPing
# 恰好优先选它, 导致走主端口的真实站点全部超时。两个站点都返回 204 才算可用,
# 计时取两站点中较慢者(更接近真实体感)。
PROBE_URLS = ("https://www.gstatic.com/generate_204",
              "https://www.google.com/generate_204")
PROBE_URL = PROBE_URLS[0]                     # 兼容旧引用(仅用于提示文案)
PROBE_EXPECTED = "204"

# Protocols Xray can act as a client for. Since Xray 26.3.x, Hysteria 2 is also
# supported as an outbound: protocol "hysteria" + network "hysteria".
# "ss" is Shadowsocks (SIP002 links; outbound protocol name "shadowsocks"),
# "vmess" is classic VMess. Both verified against xray 26.3.27 via -test.
SUPPORTED_SCHEMES = ("trojan", "vless", "hysteria2", "vmess", "ss")
SUPPORTED_NETWORKS = ("ws", "tcp", "xhttp", "hysteria")
# "" and "none" are the same thing (plaintext, no TLS layer); "reality" needs
# publicKey (pbk), see build_outbound().
SUPPORTED_SECURITIES = ("", "none", "tls", "reality")

# Any outbound whose tag starts with "proxy" is picked up by the balancer and
# the observatory (selector "proxy"), so every proxy_* outbound is fair game for
# the speed ranking. Tags this script creates (proxy_US_...) are recognised
# separately so that hand-written ones (proxy_sub1_..., proxy_4_...) can be told
# apart and reported.
PROXY_TAG_RE = re.compile(r"^proxy")

# Tags created by this script (e.g. proxy_US_104_18_152_144). Hand-written tags
# such as proxy_sub1_198_41_223_96 or proxy_4_... are deliberately not matched.
MANAGED_TAG_RE = re.compile(r"^proxy_[A-Z]{2}_")

# Region hint inside a subscription remark: "US_89", "FR|1.9MB/s", "HK_104|…".
REGION_HINT_RE = re.compile(r"([A-Z]{2})[_|]")


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def _uniq_low(seq):
    """Lower-case, de-duplicate while keeping order."""
    out, seen = [], set()
    for item in seq:
        item = item.lower()
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _fix_path(path: str) -> str:
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _recover_params(fragment: str) -> dict:
    """Recover connection params some subscriptions put in the remark instead.

    e.g. `vless://…@169.40.42.232:443?encryption=none&security=reality&type=tcp
    #🎗️98@oneclickvpnkeys&sni=yahoo.com&fp=chrome&flow=xtls-rprx-vision&pbk=…`
    - the real link only spells out security/type while sni/pbk/sid live in the
    fragment (sometimes behind an embedded "vless://…?"). Without them the node
    cannot be built at all, so they are recovered best-effort; if the guess is
    wrong the probe simply fails and the node is dropped.
    """
    text = urllib.parse.unquote(fragment)
    text = text.split("#", 1)[0]          # drop the trailing "…#remark"
    if "?" in text:                        # embedded copy of a whole URI
        text = text.split("?", 1)[1]
    return {key.lower(): value
            for key, value in urllib.parse.parse_qsl(text, keep_blank_values=True)}


def parse_node(line: str):
    """Parse one subscription URI into a normalized node dict (or None)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.lower().startswith("vmess://"):
        # Classic V2Ray share link: vmess://<base64 JSON>, no user@host form.
        return _parse_vmess(line)
    if "://" not in line:
        return None

    scheme, rest = line.split("://", 1)
    scheme = scheme.lower()
    rest, _, fragment = rest.partition("#")
    body, _, query = rest.partition("?")

    if scheme == "ss" and "@" not in body:
        # Legacy ss form: the whole body is base64("method:password@host:port").
        try:
            expanded = base64.b64decode(_b64_pad(body)).decode("utf-8", "replace")
        except Exception:
            return None
        if "@" not in expanded:
            return None
        body, _, query = expanded.partition("?")
        line = "ss://%s%s" % (body, "#" + fragment if fragment else "")

    if "@" not in body:
        return None
    user, hostport = body.rsplit("@", 1)
    if ":" not in hostport:
        return None
    host, port_s = hostport.rsplit(":", 1)
    host = urllib.parse.unquote(host)
    try:
        port = int(port_s)
    except ValueError:
        return None

    # SIP002 ss://: userinfo is base64(method:password) — or plain method:password.
    ss_method = ""
    if scheme == "ss":
        candidate = urllib.parse.unquote(user)
        decoded = ""
        if re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate or ""):
            for decoder in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    decoded = decoder(_b64_pad(candidate)).decode("utf-8", "replace")
                except Exception:
                    decoded = ""
                if ":" in decoded:
                    break
                decoded = ""
        if ":" in decoded:
            ss_method, user = decoded.split(":", 1)
        elif ":" in candidate:
            ss_method, user = candidate.split(":", 1)
        else:
            return None
        user = urllib.parse.unquote(user)

    params = {}
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        params[key.lower()] = value
    # Links whose params live in the remark (see _recover_params) only mention
    # security/type in the query; fill in what is missing, never overwrite.
    for key, value in _recover_params(fragment).items():
        if value and not params.get(key):
            params[key] = value

    security = (params.get("security") or "").lower()
    network = (params.get("type") or "tcp").lower()
    if scheme == "hysteria2":
        # Hysteria2 links carry no transport/security params: it is always
        # QUIC + TLS, which in Xray means network "hysteria".
        network, security = "hysteria", "tls"

    # xhttp "mode": Xray's own default is "auto", so an explicit mode=auto is
    # normalized to "" and the key never depends on how the link spelled it.
    mode = (params.get("mode") or "").lower()
    if mode == "auto":
        mode = ""

    return {
        "scheme": scheme,
        "user": urllib.parse.unquote(user),
        "address": host,
        "port": port,
        "security": security,
        "sni": params.get("sni", ""),
        "network": network,
        "path": _fix_path(params.get("path", "/")),
        "host": params.get("host", ""),
        # xhttp only: stream-up/packet-up must be sent as-is.
        "mode": mode,
        "alpn": _uniq_low([a.strip() for a in params.get("alpn", "").split(",") if a.strip()]),
        "fp": params.get("fp", ""),
        "flow": params.get("flow", ""),
        # REALITY (vless/trojan over tcp): publicKey authenticates the handshake,
        # shortId/spiderX are optional.
        "pbk": params.get("pbk", ""),
        "sid": params.get("sid", ""),
        "spx": params.get("spx", ""),
        # Both spellings appear in the wild (hysteria2 links use "insecure").
        "insecure": (params.get("insecure") or params.get("allowinsecure") or "")
                    in ("1", "true"),
        # Shadowsocks only: cipher from the SIP002 userinfo.
        "ss_method": ss_method,
        "label": urllib.parse.unquote(fragment).strip(),
        "raw": line,
    }


def node_key(node):
    """Identity of the connection parameters - used to drop duplicates."""
    return (
        node["scheme"],
        node["address"],
        str(node["port"]),
        node["user"],
        node["sni"],
        node["network"],
        node["path"],
        node["host"],
        node["mode"],
        ",".join(node["alpn"]),
        node["fp"],
        node["pbk"],
        node["sid"],
        node["flow"],
        node.get("ss_method", ""),
    )


def node_supported(node):
    """Return None if supported, otherwise the reason it must be skipped."""
    if node["scheme"] not in SUPPORTED_SCHEMES:
        return "protocol not supported by Xray (%s)" % node["scheme"]
    if node["network"] not in SUPPORTED_NETWORKS:
        return "transport not supported here (%s)" % node["network"]
    if node["security"] not in SUPPORTED_SECURITIES:
        return "security not supported here (%s)" % node["security"]
    if node["security"] == "reality":
        if node["scheme"] not in ("vless", "trojan"):
            return "reality is only supported for vless/trojan (%s)" % node["scheme"]
        if not node["pbk"]:
            return "reality without publicKey (pbk)"
    return None


def singbox_supported(node):
    """True 当 sing-box 能承载该节点（to_singbox_outbound 返回非 None）。

    与 node_supported() 分开判定：两边支持的协议/传输并不一致——
      * tuic            只有 sing-box 能跑（xray 无此出站）
      * xhttp           只有 xray 能跑（sing-box 无此出站）
      * grpc/httpupgrade sing-box 能跑、本脚本的 xray 侧不建模
    相同的 vless/vmess/trojan/ss/hysteria2 两边都能跑。
    """
    return to_singbox_outbound(node, "_probe") is not None


def partition_pool(pool):
    """把候选池按“哪个核心能真跑”拆成 (xray_pool, singbox_pool, skipped)。

    同一节点可能同时进两侧（协议/传输两边都支持时），各自用自己的核心独立测速；
    只有一侧能跑的（tuic 归 sing-box、xhttp 归 xray）只进对应一侧；两边都跑不了
    的进 skipped（[(reason, label)]）。
    """
    xray_pool, sb_pool, skipped = [], [], []
    for node in pool:
        reason = node_supported(node)
        in_x = reason is None
        in_sb = singbox_supported(node)
        if in_x:
            xray_pool.append(node)
        if in_sb:
            sb_pool.append(node)
        if not in_x and not in_sb:
            skipped.append((reason or "两边核心均不支持该节点",
                            node["label"] or node["address"]))
    return xray_pool, sb_pool, skipped


def load_nodes(node_file):
    """Read + de-duplicate nodes; returns (nodes, skipped list of (reason, label))."""
    with open(node_file, encoding="utf-8", errors="replace") as fh:
        return load_nodes_lines(fh.readlines())


def load_nodes_lines(lines):
    """Same as load_nodes() but from an in-memory line list (subscription text)."""
    nodes, skipped, seen = [], [], set()
    for line in lines:
        node = parse_node(line)
        if node is None:
            continue
        reason = node_supported(node)
        if reason:
            skipped.append((reason, node["label"] or node["raw"][:60]))
            continue
        key = node_key(node)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(node)
    return nodes, skipped


# --------------------------------------------------------------------------- #
# subscription downloads: plain URI list / base64 blob / Clash YAML
# --------------------------------------------------------------------------- #
# subscriptions.txt 里 `datepattern:` 模板行的日期窗口：前天、昨天、今天（共 3 天），
# 每个日期再展开 N=0..5 共 6 份。
DATEPATTERN_OFFSETS = (-2, -1, 0)   # 前天 / 昨天 / 今天


def expand_datepatterns(urls):
    """`datepattern:` 模板 -> 具体订阅 URL 列表。

    模板占位符：{year} {month} {day}（month/day 两位补零）、{ymd}（YYYYMMDD）、
    {n}（0..5）。来自 update_nodes.py 的按日期轮换订阅源，每天自动出新文件。
    """
    out = []
    for u in urls:
        if not u.startswith("datepattern:"):
            out.append(u)
            continue
        tmpl = u[len("datepattern:"):].strip()
        for off in DATEPATTERN_OFFSETS:
            d = date.today() + timedelta(days=off)
            for n in range(6):
                out.append(tmpl.format(
                    year=d.year, month="%02d" % d.month, day="%02d" % d.day,
                    ymd=d.strftime("%Y%m%d"), n=n))
    return out


def fetch_subscription(url):
    """Download one subscription; direct first, then via the local Xray SOCKS.

    GitHub raw and friends are often unreachable from CN networks directly,
    which is exactly what the running Xray (FALLBACK_PROXY) is there for.
    Returns the body text, or None when both attempts fail.
    """
    for extra in ([], ["-x", FALLBACK_PROXY]):
        try:
            result = subprocess.run(
                ["curl", "-sL", "--max-time", str(FETCH_TIMEOUT), "-A",
                 "clash-verge/v1.7.7"] + extra + [url],
                capture_output=True, timeout=FETCH_TIMEOUT + 5,
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            text = result.stdout.decode("utf-8", "replace")
            if text.strip():
                return text
    return None


def _b64_pad(text: str) -> str:
    return text + "=" * (-len(text) % 4)


def extract_uri_lines(text: str) -> list:
    """Subscription body -> share-URI lines (plain list or whole-body base64)."""
    if "://" in text:
        lines = [line.strip() for line in text.splitlines()
                 if line.strip() and not line.strip().startswith("#")
                 and "://" in line]
        if lines:
            return lines
    compact = "".join(text.split())
    if compact and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                decoded = decoder(_b64_pad(compact)).decode("utf-8", "replace")
            except Exception:
                continue
            if "://" not in decoded:
                continue
            return [line.strip() for line in decoded.splitlines()
                    if line.strip() and "://" in line]
    return []


def _parse_vmess(line: str):
    """vmess://<base64 JSON> -> node dict (the classic V2Ray share format)."""
    try:
        payload = base64.b64decode(
            _b64_pad(line[len("vmess://"):].strip())).decode("utf-8", "replace")
        data = json.loads(payload)
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("add"):
        return None
    try:
        port = int(str(data.get("port") or 0).strip() or 0)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return {
        "scheme": "vmess",
        "user": str(data.get("id") or ""),
        "address": str(data["add"]).strip(),
        "port": port,
        "security": "tls" if str(data.get("tls") or "").lower() == "tls" else "",
        "sni": str(data.get("sni") or data.get("host") or ""),
        "network": (str(data.get("net") or "tcp") or "tcp").lower(),
        "path": _fix_path(str(data.get("path") or "/")),
        "host": str(data.get("host") or ""),
        "mode": "",
        "alpn": _uniq_low([a.strip() for a in str(data.get("alpn") or "").split(",")
                           if a.strip()]),
        "fp": str(data.get("fp") or ""),
        "flow": str(data.get("flow") or ""),
        "pbk": "", "sid": "", "spx": "",
        "insecure": False,
        "label": str(data.get("ps") or ""),
        "raw": line,
    }


def parse_clash_proxy(proxy: dict):
    """One Clash `proxies:` entry -> node dict (or None if unmodelable)."""
    ptype = str(proxy.get("type") or "").lower()
    if ptype not in SUPPORTED_SCHEMES:
        return None
    address = str(proxy.get("server") or "").strip()
    try:
        port = int(proxy.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if not address or not (0 < port < 65536):
        return None

    network = str(proxy.get("network") or "tcp").lower()
    security, sni = "", str(proxy.get("servername") or proxy.get("sni") or "")
    reality = proxy.get("reality-opts") or {}
    if ptype == "hysteria2":
        network, security = "hysteria", "tls"
    elif reality.get("public-key"):
        security = "reality"
    elif proxy.get("tls"):
        security = "tls"

    if ptype in ("vless", "vmess"):
        user = str(proxy.get("uuid") or "")
    else:  # trojan / ss / hysteria2
        user = str(proxy.get("password") or proxy.get("auth") or "")

    ws = proxy.get("ws-opts") or {}
    headers = ws.get("headers") or {}
    alpn = proxy.get("alpn") or []
    if isinstance(alpn, str):
        alpn = [alpn]
    return {
        "scheme": ptype,
        "user": user,
        "address": address,
        "port": port,
        "security": security,
        "sni": sni,
        "network": network,
        "path": _fix_path(str(ws.get("path") or "/")),
        "host": str(headers.get("Host") or headers.get("host") or ""),
        "mode": "",
        "alpn": _uniq_low([str(a).strip() for a in alpn if str(a).strip()]),
        "fp": str(proxy.get("client-fingerprint") or ""),
        "flow": str(proxy.get("flow") or ""),
        "pbk": str(reality.get("public-key") or ""),
        "sid": str(reality.get("short-id") or ""),
        "spx": "",
        "insecure": bool(proxy.get("skip-cert-verify")),
        "ss_method": str(proxy.get("cipher") or "") if ptype == "ss" else "",
        "label": str(proxy.get("name") or ""),
        "raw": address,
    }


def parse_subscription(text: str) -> list:
    """Subscription body -> node dicts: Clash YAML, plain URI list or base64."""
    if re.search(r"^proxies\s*:", text, re.M):
        try:
            import yaml
            data = yaml.safe_load(text)
        except Exception:
            data = None
        proxies = data.get("proxies") if isinstance(data, dict) else None
        if isinstance(proxies, list):
            return [node for proxy in proxies
                    if isinstance(proxy, dict) and (node := parse_clash_proxy(proxy))]
    return [node for line in extract_uri_lines(text) if (node := parse_node(line))]


# --------------------------------------------------------------------------- #
# outbound construction
# --------------------------------------------------------------------------- #
def geo_tag(node) -> str:
    """Short region hint taken from the fragment, e.g. 'US', 'HK'."""
    label = node["label"]
    # Remarks that embed a copy of the URI (see _recover_params) end with the
    # real hint ("🇺🇸US_89|1.4MB/s|…"); the generic scan below would happily read
    # the channel name "oneclickvpnkeys" as "ON" instead.
    match = REGION_HINT_RE.search(label.split("#")[-1])
    if match:
        return match.group(1)
    idx = 0
    while idx < len(label) and not (label[idx].isascii() and label[idx].isalpha()):
        idx += 1
    code = label[idx:idx + 2].upper()
    if len(code) == 2 and code.isalpha():
        nxt = label[idx + 2:idx + 3]
        if not (nxt.isascii() and nxt.isalpha()):
            return code
    return "XX"


def build_outbound(node, tag):
    """Build the Xray outbound object for a parsed node."""
    address = node["address"]
    if node["scheme"] == "hysteria2":
        # Xray's Hysteria 2 client: proxy protocol "hysteria" + QUIC transport
        # "hysteria"; the auth string lives in hysteriaSettings.
        hysteria = {"version": 2}
        if node["user"]:
            hysteria["auth"] = node["user"]
        stream = {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {"serverName": node["sni"] or node["host"] or address},
            "hysteriaSettings": hysteria,
        }
        return {
            "protocol": "hysteria",
            "settings": {"version": 2, "address": address, "port": node["port"]},
            "streamSettings": stream,
            "tag": tag,
        }
    if node["scheme"] == "ss":
        # Xray's client protocol is "shadowsocks"; method+password live in the
        # server entry (SIP002 userinfo was split at parse time).
        settings = {"servers": [{
            "address": address, "port": node["port"],
            "method": node.get("ss_method") or "aes-128-gcm",
            "password": node["user"],
        }]}
    elif node["scheme"] == "trojan":
        settings = {"servers": [{
            "address": address, "port": node["port"], "password": node["user"],
        }]}
    else:  # vless / vmess
        user = {"id": node["user"]}
        if node["scheme"] == "vmess":
            user["security"] = "auto"
        else:
            user["encryption"] = "none"
            if node["flow"]:
                user["flow"] = node["flow"]
        settings = {"vnext": [{
            "address": address, "port": node["port"], "users": [user],
        }]}

    network = node["network"]
    stream = {"network": network}
    if network == "ws":
        ws = {"path": node["path"]}
        if node["host"]:
            ws["headers"] = {"Host": node["host"]}
        stream["wsSettings"] = ws
    elif network == "xhttp":
        xhttp = {"path": node["path"]}
        if node["host"]:
            xhttp["host"] = node["host"]
        if node["mode"]:
            # stream-up / packet-up must reach the server verbatim; "" = Xray's
            # default ("auto"), which is what the link's mode=auto means.
            xhttp["mode"] = node["mode"]
        stream["xhttpSettings"] = xhttp

    if node["security"] == "reality":
        # REALITY: TLS-shaped handshake signed with the server's key pair. The
        # client only needs publicKey (+ optional shortId); uTLS fingerprint is
        # required by Xray and defaults to chrome when the link omits fp.
        reality = {
            "serverName": node["sni"] or node["host"] or address,
            "fingerprint": node["fp"] or "chrome",
            "publicKey": node["pbk"],
        }
        if node["sid"]:
            reality["shortId"] = node["sid"]
        if node["spx"]:
            reality["spiderX"] = node["spx"]
        stream["security"] = "reality"
        stream["realitySettings"] = reality
    elif node["security"] == "tls":
        tls = {"serverName": node["sni"] or node["host"] or address}
        if node["fp"]:
            tls["fingerprint"] = node["fp"]
        if node["alpn"]:
            tls["alpn"] = node["alpn"]
        # NOTE: "allowInsecure" was removed in Xray 26.x (see pinnedPeerCertSha256),
        # so insecure=1 links are simply verified normally: if the peer's
        # certificate cannot be verified the node fails the probe and is dropped.
        stream["security"] = "tls"
        stream["tlsSettings"] = tls

    protocol = {"ss": "shadowsocks"}.get(node["scheme"], node["scheme"])
    return {
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
        "tag": tag,
    }


def outbound_key(outbound):
    """Same identity as node_key() but for an already-built outbound."""
    protocol = outbound.get("protocol", "")
    stream = outbound.get("streamSettings") or {}
    address = port = user = method = ""
    if protocol == "trojan":
        servers = (outbound.get("settings") or {}).get("servers") or []
        if servers:
            address = servers[0].get("address", "")
            port = str(servers[0].get("port", ""))
            user = servers[0].get("password", "")
    elif protocol == "shadowsocks":
        servers = (outbound.get("settings") or {}).get("servers") or []
        if servers:
            address = servers[0].get("address", "")
            port = str(servers[0].get("port", ""))
            user = servers[0].get("password", "")
            method = servers[0].get("method", "")
    elif protocol in ("vless", "vmess"):
        vnext = (outbound.get("settings") or {}).get("vnext") or []
        if vnext:
            address = vnext[0].get("address", "")
            port = str(vnext[0].get("port", ""))
            users = vnext[0].get("users") or []
            if users:
                user = users[0].get("id", "")
    elif protocol == "hysteria":
        hysteria = outbound.get("settings") or {}
        address = hysteria.get("address", "")
        port = str(hysteria.get("port", ""))
        user = (stream.get("hysteriaSettings") or {}).get("auth", "")
    network = stream.get("network", "tcp")
    sub = stream.get("wsSettings") or stream.get("xhttpSettings") or {}
    host = (sub.get("headers") or {}).get("Host") or sub.get("host", "")
    # Xray defaults an xhttp/ws path to "/" when the field is absent, and
    # node_key() always carries a leading-slash path - keep both sides equal.
    path = sub.get("path") or "/"
    if stream.get("security") == "reality":
        sec = stream.get("realitySettings") or {}
    else:
        sec = stream.get("tlsSettings") or {}
    alpn = ",".join(str(a).lower() for a in sec.get("alpn") or [])
    mode = sub.get("mode", "")
    if mode == "auto":
        mode = ""
    # Xray spells the Hysteria 2 client protocol "hysteria" and Shadowsocks
    # "shadowsocks"; node_key() uses the link's scheme names, so map both back.
    scheme = {"hysteria": "hysteria2", "shadowsocks": "ss"}.get(protocol, protocol)
    flow = ""
    if protocol in ("vless", "vmess"):
        vnext_users = ((outbound.get("settings") or {}).get("vnext") or [{}])[0].get("users") or []
        if vnext_users:
            flow = vnext_users[0].get("flow", "")
    return (
        scheme,
        address,
        port,
        user,
        sec.get("serverName", ""),
        network,
        path,
        host,
        mode,
        alpn,
        sec.get("fingerprint", ""),
        sec.get("publicKey", ""),
        sec.get("shortId", ""),
        flow,
        method,
    )


# --------------------------------------------------------------------------- #
# availability probing (real end-to-end check through each node)
# --------------------------------------------------------------------------- #
# 每个节点都会起一个临时核心进程。正常路径下 probe_once* 的 finally 会 terminate，
# 但若主进程被 SIGTERM/SIGKILL 打断（例如 pkill、Ctrl-C、systemd 停止），finally
# 不一定来得及跑，临时核心会被 init 收养、长期残留（实测泄漏过 20+ 个、每个 ~30MB）。
# 这里登记所有在跑的临时核心 PID，并在 atexit + SIGTERM/SIGINT 时统一清理，
# 这样才能安全地把并发开大而不怕中断后漏进程。
_LIVE_PROCS = set()
_LIVE_PROCS_LOCK = threading.Lock()


def _register_proc(proc):
    with _LIVE_PROCS_LOCK:
        _LIVE_PROCS.add(proc)


def _unregister_proc(proc):
    with _LIVE_PROCS_LOCK:
        _LIVE_PROCS.discard(proc)


def _kill_live_procs():
    """terminate/kill 所有还登记着的临时核心进程（幂等，可在信号/atexit 里调用）。"""
    with _LIVE_PROCS_LOCK:
        procs = list(_LIVE_PROCS)
        _LIVE_PROCS.clear()
    for proc in procs:
        try:
            proc.terminate()
        except OSError:
            pass
    deadline = time.time() + 2.0
    for proc in procs:
        try:
            proc.wait(timeout=max(0.1, deadline - time.time()))
        except Exception:
            try:
                proc.kill()
            except OSError:
                pass


def _install_cleanup_handlers():
    atexit.register(_kill_live_procs)
    for sig in (signal.SIGTERM, signal.SIGINT):
        prev = signal.getsignal(sig)

        def _handler(signum, frame, _prev=prev):
            _kill_live_procs()
            if callable(_prev) and _prev not in (signal.SIG_DFL, signal.SIG_IGN):
                _prev(signum, frame)
            else:
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # 非主线程或平台不支持，忽略


_install_cleanup_handlers()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


def _curl_dual_204(port, timeout, samples):
    """curl 两个 generate_204 站点，全部 204 才算通过，计时取较慢者。

    返回 (ok, latency, reason)。严格口径(2026-10-01)：任一样本失败即整节点
    淘汰——排名时"2次里过1次"的节点实测会带着 Google 拉黑问题混进前列(leastPing
    恰好优先选它)。误杀代价低(候选池大)，宁严勿松。
    """
    best, last_code = None, "none"
    for url in PROBE_URLS:
        url_best = None
        for _ in range(max(1, samples)):
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                 "--max-time", str(timeout), "--socks5-hostname",
                 "127.0.0.1:%d" % port, url],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            parts = (result.stdout or "").strip().split()
            code = parts[0] if parts else "000"
            last_code = code
            if code == PROBE_EXPECTED and len(parts) > 1:
                try:
                    value = float(parts[1])
                except ValueError:
                    value = None
                if value is not None:
                    url_best = value if url_best is None else min(url_best, value)
            else:
                return False, None, "HTTP %s (%s)" % (code, url.split("/")[2])
        if url_best is None:
            return False, None, "HTTP %s (%s)" % (last_code, url.split("/")[2])
        best = url_best if best is None else max(best, url_best)
    return True, best, "双204 %.2fs" % best


def probe_once(outbound, port, workdir, timeout, samples):
    """Run one throwaway Xray with a single outbound and curl through its SOCKS port.

    Returns (ok, latency_seconds, reason): ok is True when both probe sites
    returned 204, latency is the slower of the two.
    """
    config_path = os.path.join(workdir, "config.json")
    error_log = os.path.join(workdir, "error.log")
    config = {
        "log": {"loglevel": "warning", "error": error_log},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
    }
    with open(config_path, "w") as fh:
        json.dump(config, fh)

    env = dict(os.environ, XRAY_LOCATION_ASSET=ASSET_DIR)
    proc = subprocess.Popen(
        [XRAY_BIN, "run", "-config", config_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    _register_proc(proc)
    try:
        if not wait_for_port(port):
            lines = []
            if os.path.exists(error_log):
                with open(error_log, errors="replace") as fh:
                    lines = fh.read().strip().splitlines()
            detail = lines[-1] if lines else "no log"
            return False, None, "xray did not listen (%s)" % detail
        return _curl_dual_204(port, timeout, samples)
    except subprocess.TimeoutExpired:
        return False, None, "probe timeout"
    finally:
        _unregister_proc(proc)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def probe_once_singbox(sb_outbound, port, workdir, timeout, samples):
    """起一个临时 sing-box（本地 SOCKS -> 该出站）跑一遍双 204 探测。

    sing-box 侧独立测速用：它和 xray 支持的协议/传输并不完全一致（tuic 只有
    sing-box 能跑；xhttp 只有 xray 能跑），所以两边各自用自己的核心真测一遍。
    返回 (ok, latency, reason)，语义与 probe_once() 相同。
    """
    config_path = os.path.join(workdir, "config.json")
    error_log = os.path.join(workdir, "error.log")
    tag = sb_outbound.get("tag", "probe")
    config = {
        "log": {"level": "warn", "timestamp": False, "output": error_log},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [sb_outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [], "final": tag},
    }
    with open(config_path, "w") as fh:
        json.dump(config, fh)

    proc = subprocess.Popen(
        [SB_BIN, "run", "-c", config_path, "-D", workdir],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _register_proc(proc)
    try:
        if not wait_for_port(port):
            lines = []
            if os.path.exists(error_log):
                with open(error_log, errors="replace") as fh:
                    lines = fh.read().strip().splitlines()
            detail = lines[-1] if lines else "no log"
            return False, None, "sing-box did not listen (%s)" % detail
        return _curl_dual_204(port, timeout, samples)
    except subprocess.TimeoutExpired:
        return False, None, "probe timeout"
    finally:
        _unregister_proc(proc)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def probe_node(node, timeout, attempts, samples, engine="xray"):
    """Try a node up to `attempts` times; usable if any attempt returns 204.

    engine="xray"      -> 起临时 Xray 跑（build_outbound）
    engine="sing-box"  -> 起临时 sing-box 跑（to_singbox_outbound；sing-box 跑不了
                          的传输/协议直接判失败，不起进程）

    The reported latency is the fastest successful request across all attempts.
    """
    if engine == "sing-box":
        sb_outbound = to_singbox_outbound(node, "probe")
        if sb_outbound is None:
            return {"node": node, "ok": False, "reason": "sing-box 无法承载该节点",
                    "latency": None, "elapsed": 0.0, "engine": engine}
        last_reason, elapsed, best = "not tested", 0.0, None
        for _ in range(attempts):
            workdir = tempfile.mkdtemp(prefix="sb-node-sync-")
            started = time.time()
            try:
                ok, latency, reason = probe_once_singbox(
                    sb_outbound, free_port(), workdir, timeout, samples)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
            elapsed += time.time() - started
            if ok:
                best = latency if best is None else min(best, latency)
                return {"node": node, "ok": True, "reason": reason,
                        "latency": round(best, 3), "elapsed": round(elapsed, 2),
                        "engine": engine}
            last_reason = reason
        return {"node": node, "ok": False, "reason": last_reason, "latency": None,
                "elapsed": round(elapsed, 2), "engine": engine}

    outbound = build_outbound(node, "probe")
    last_reason, elapsed, best = "not tested", 0.0, None
    for _ in range(attempts):
        workdir = tempfile.mkdtemp(prefix="xray-node-sync-")
        started = time.time()
        try:
            ok, latency, reason = probe_once(
                outbound, free_port(), workdir, timeout, samples)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        elapsed += time.time() - started
        if ok:
            best = latency if best is None else min(best, latency)
            return {"node": node, "ok": True, "reason": reason,
                    "latency": round(best, 3), "elapsed": round(elapsed, 2),
                    "outbound": outbound, "engine": engine}
        last_reason = reason
    return {"node": node, "ok": False, "reason": last_reason, "latency": None,
            "elapsed": round(elapsed, 2), "outbound": outbound, "engine": engine}


def probe_all(nodes, workers, timeout, attempts, samples=DEFAULT_SAMPLES,
              early_stop=None, engine="xray", label="xray"):
    """Probe every node concurrently, keeping the input order of the results.

    early_stop: callable(usable_latencies -> bool); when it returns True the
    not-yet-started probes are cancelled and untested nodes are reported as
    "(提前结束)" failures — used to stop once we already hold enough fast nodes.
    engine 选择底层核心（xray / sing-box）；label 仅用于进度行前缀，便于区分两侧。
    """
    results = [None] * len(nodes)
    usable_lats = []
    stop_reason = None
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_node, node, timeout, attempts, samples, engine): idx
                   for idx, node in enumerate(nodes)}
        try:
            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                results[idx] = future.result()
                done += 1
                row = results[idx]
                if row["ok"]:
                    usable_lats.append(row["latency"])
                speed = "%5.2fs" % row["latency"] if row["ok"] else "  -  "
                print("  [%s %3d/%3d] %-4s %-17s %-4s %s  %s" % (
                    label, done, len(nodes), "OK" if row["ok"] else "FAIL",
                    row["node"]["address"][:17], geo_tag(row["node"]), speed,
                    row["reason"],
                ), file=sys.stderr, flush=True)
                if early_stop and early_stop(usable_lats):
                    stop_reason = ("已达 %d 个可用且延迟中位数 %.2fs ≤ 阈值，"
                                   "提前结束剩余 %d 个"
                                   % (len(usable_lats),
                                      sorted(usable_lats)[len(usable_lats) // 2],
                                      len(nodes) - done))
                    print("⚡ %s" % stop_reason, file=sys.stderr, flush=True)
                    break
        finally:
            if stop_reason:
                pool.shutdown(wait=False, cancel_futures=True)
    for idx, row in enumerate(results):
        if row is None:
            results[idx] = {"ok": False, "node": nodes[idx],
                            "latency": None, "reason": "(提前结束，未测)"}
    return results, stop_reason


def rank_usable(results, keep):
    """Return (kept, dropped) — usable nodes sorted by latency, trimmed to `keep`."""
    usable = sorted((r for r in results if r["ok"]),
                    key=lambda r: (r["latency"], r["node"]["address"]))
    if keep and len(usable) > keep:
        return usable[:keep], usable[keep:]
    return usable, []


TCP_SCAN_EXEMPT = ("hysteria2", "tuic")   # QUIC/UDP 传输，TCP 连通说明不了问题
_TCP_CACHE = {}   # (address, port) -> 握手秒数 或 None(死端点)；xray/sing-box 两池共享


def _endpoint_alive(address, port, timeout):
    """DNS 解析后逐个候选 IP 做裸 TCP 连接，返回首次握手成功的耗时(秒)；
    全部失败则返回 None（调用方据此判断存活并记录延迟）。"""
    try:
        infos = socket.getaddrinfo(address, int(port), type=socket.SOCK_STREAM)
    except OSError:
        return None
    for _fam, _typ, _proto, _canon, sa in infos:
        try:
            started = time.time()
            s = socket.create_connection(sa[:2], timeout=timeout)
            s.close()
            return time.time() - started
        except OSError:
            continue
    return None


def tcp_presize(pool, workers=500, timeout=1.5, max_candidates=0):
    """TCP 预扫描（移植自 update_nodes.py）：在为每个节点起临时 Xray 之前，
    先用裸 TCP 连接把 server:port 已死的候选过滤掉。同一 (地址, 端口) 只扫
    一次；hysteria2/tuic 豁免。扫描结果写入模块级 _TCP_CACHE，xray/sing-box
    两侧候选池共享同一批端点，第二次调用直接命中缓存、不再重扫。

    预扫描顺带记录每个端点的握手耗时。当 max_candidates > 0 时，把可扫描的
    存活节点按握手延迟升序排序、只留前 max_candidates 个进入测速池（参照
    update_nodes.py 的 --max-candidates 思路，用握手延迟做“先测最有希望的”
    预算上限）；hysteria2/tuic 无法用 TCP 握手衡量，一律保留在末尾，不受上限
    影响。max_candidates <= 0 表示不限制（默认），只做死端点过滤。

    返回留下的节点列表。"""
    endpoints = {}
    for idx, node in enumerate(pool):
        if node.get("scheme") in TCP_SCAN_EXEMPT:
            continue
        endpoints.setdefault((node["address"], node["port"]), []).append(idx)

    # 只扫缓存里没有的端点；已扫过的（含已知死端点）直接复用，两池共享一次扫描。
    pending = [ep for ep in endpoints if ep not in _TCP_CACHE]

    def scan(ep):
        addr, port = ep
        return ep, _endpoint_alive(addr, port, timeout)

    done = 0
    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for ep, lat in ex.map(scan, pending):
                _TCP_CACHE[ep] = lat
                done += 1
                if done % 500 == 0:
                    print("  TCP 预扫描 %d/%d（复用缓存 %d），可达 %d"
                          % (done, len(pending), len(endpoints) - len(pending),
                             sum(1 for e in endpoints if _TCP_CACHE.get(e) is not None)),
                          file=sys.stderr, flush=True)

    latency = {ep: _TCP_CACHE[ep] for ep in endpoints
               if _TCP_CACHE.get(ep) is not None}

    scannable = [node for node in pool
                 if node.get("scheme") not in TCP_SCAN_EXEMPT
                 and (node["address"], node["port"]) in latency]
    exempt = [node for node in pool if node.get("scheme") in TCP_SCAN_EXEMPT]
    # 握手快的排前面（真正进测速池的顺序由它决定，早停直接沿用这个顺序）。
    scannable.sort(key=lambda n: latency[(n["address"], n["port"])])
    total_alive = len(scannable) + len(exempt)
    dropped_dead = len(pool) - total_alive

    capped = False
    if max_candidates and len(scannable) > max_candidates:
        scannable = scannable[:max_candidates]
        capped = True
    kept = scannable + exempt

    msg = ("TCP 预扫描完成：端点可达 %d/%d（本次新扫 %d，复用缓存 %d），"
           "预过滤掉 %d 个死端点节点" % (
               len(latency), len(endpoints), done,
               len(endpoints) - len(pending), dropped_dead))
    if capped:
        msg += ("；按握手延迟取前 %d 个可扫描候选进入测速（另有 %d 个 QUIC 豁免节点"
                "不受上限影响），共 %d" % (max_candidates, len(exempt), len(kept)))
    print(msg)
    return kept


def refine_ranking(rows, workers, timeout, samples, engine="xray"):
    """Re-measure usable nodes at lower concurrency so the top-N cut is fair.

    The first pass runs at high concurrency, which inflates latency unevenly
    (nodes recovered by the low-concurrency retest look artificially fast
    compared to the rest). Before deciding who gets dropped we measure all
    candidates again on equal terms; a node that fails this second measurement
    simply keeps its earlier — working — latency.
    """
    fresh = probe_all([r["node"] for r in rows], workers, timeout, 1, samples,
                      engine=engine)[0]
    improved = 0
    for row, new in zip(rows, fresh):
        if new["ok"]:
            row["latency"] = new["latency"]
            row["reason"] += " [排名复测 %.2fs]" % new["latency"]
            improved += 1
    return improved


# --------------------------------------------------------------------------- #
# config merge / commit
# --------------------------------------------------------------------------- #
def make_tag(node, used_tags):
    base = "proxy_%s_%s" % (
        geo_tag(node), node["address"].replace(".", "_").replace(":", "_"),
    )
    tag, counter = base, 2
    while tag in used_tags:
        tag = "%s_%d" % (base, counter)
        counter += 1
    used_tags.add(tag)
    return tag


def merge_working(config, nodes):
    """Insert the nodes in the given (fastest-first) order before direct/blocked."""
    outbounds = config.setdefault("outbounds", [])
    known_keys = {outbound_key(o) for o in outbounds}
    used_tags = {o.get("tag") for o in outbounds if o.get("tag")}
    anchor = len(outbounds)
    for idx, existing in enumerate(outbounds):
        if existing.get("tag") in ("direct", "blocked", "freedom"):
            anchor = idx
            break
    added, duplicates = [], 0
    for node in nodes:
        if node_key(node) in known_keys:
            duplicates += 1
            continue
        outbound = build_outbound(node, make_tag(node, used_tags))
        outbounds.insert(anchor + len(added), outbound)
        known_keys.add(node_key(node))
        added.append(outbound)
    return added, duplicates


# --------------------------------------------------------------------------- #
# managed-set bookkeeping: the script replaces its own outbounds on every run
# so the config always holds only the current fastest nodes
# --------------------------------------------------------------------------- #
def load_state(path=STATE_FILE):
    """Tags recorded as script-managed in state.json (empty if missing/broken)."""
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return set()
    tags = state.get("managed_tags")
    return set(tags) if isinstance(tags, list) else set()


def save_state(state, path=STATE_FILE):
    if not path:
        return
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)


def owned_tags(config, state_tags, extra=()):
    """Tags the script is allowed to remove: its own record/pattern, plus extras.

    `extra` holds hand-written proxy_* outbounds that were successfully adopted
    (they take part in the speed test, so the slow ones must go).
    """
    owned = set(state_tags) | set(extra)
    for outbound in config.get("outbounds") or []:
        tag = outbound.get("tag") or ""
        if MANAGED_TAG_RE.match(tag):
            owned.add(tag)
    return owned


def adoptable_proxies(config):
    """Hand-written proxy_* outbounds that can be re-tested and re-ranked.

    Returns (adoptable, untouched):
      * adoptable — [(tag, node)] for outbounds whose connection parameters we
        fully understand, so they can be probed and dropped when too slow;
      * untouched — tags of proxy_* outbounds we cannot model (other protocols
        or fields); those are left exactly as they are (never deleted blindly).
    """
    adoptable, untouched = [], []
    for outbound in config.get("outbounds") or []:
        tag = outbound.get("tag") or ""
        if not PROXY_TAG_RE.match(tag) or MANAGED_TAG_RE.match(tag):
            continue
        node = outbound_to_node(outbound)
        if node is None:
            untouched.append(tag)
        else:
            adoptable.append((tag, node))
    return adoptable, untouched


def drop_managed(config, state_tags, extra=()):
    """Remove previously managed/adopted outbounds; returns their tags."""
    owned = owned_tags(config, state_tags, extra)
    outbounds = config.setdefault("outbounds", [])
    removed = [o.get("tag", "?") for o in outbounds if (o.get("tag") or "") in owned]
    outbounds[:] = [o for o in outbounds if (o.get("tag") or "") not in owned]
    return removed


def outbound_to_node(outbound):
    """Best-effort reverse mapping, used to re-test already configured nodes."""
    protocol = outbound.get("protocol")
    # Xray's config names for Hysteria 2 / Shadowsocks clients are "hysteria" /
    # "shadowsocks"; node dicts use the link scheme names.
    scheme = {"hysteria": "hysteria2", "shadowsocks": "ss"}.get(protocol, protocol)
    if scheme not in SUPPORTED_SCHEMES:
        return None
    stream = outbound.get("streamSettings") or {}
    network = stream.get("network", "tcp")
    if network not in SUPPORTED_NETWORKS:
        return None
    if protocol == "trojan":
        servers = (outbound.get("settings") or {}).get("servers") or []
        if not servers:
            return None
        address, port = servers[0].get("address", ""), servers[0].get("port", 0)
        user = servers[0].get("password", "")
        flow = ""
        ss_method = ""
    elif protocol == "shadowsocks":
        servers = (outbound.get("settings") or {}).get("servers") or []
        if not servers:
            return None
        address, port = servers[0].get("address", ""), servers[0].get("port", 0)
        user = servers[0].get("password", "")
        ss_method = servers[0].get("method", "")
        flow = ""
    elif protocol == "hysteria":
        hysteria = outbound.get("settings") or {}
        address, port = hysteria.get("address", ""), hysteria.get("port", 0)
        user = (stream.get("hysteriaSettings") or {}).get("auth", "")
        flow = ""
        ss_method = ""
    else:
        vnext = (outbound.get("settings") or {}).get("vnext") or []
        if not vnext:
            return None
        users = vnext[0].get("users") or []
        address, port = vnext[0].get("address", ""), vnext[0].get("port", 0)
        user = users[0].get("id", "") if users else ""
        flow = users[0].get("flow", "") if users else ""
        ss_method = ""
    sub = stream.get("wsSettings") or stream.get("xhttpSettings") or {}
    host = (sub.get("headers") or {}).get("Host") or sub.get("host", "")
    security = stream.get("security", "")
    if security == "reality":
        sec = stream.get("realitySettings") or {}
    else:
        sec = stream.get("tlsSettings") or {}
    mode = sub.get("mode", "")
    if mode == "auto":
        mode = ""
    return {
        "scheme": scheme, "user": user, "address": address, "port": port,
        "security": security, "sni": sec.get("serverName", ""),
        "network": network, "path": sub.get("path", "/"), "host": host,
        "mode": mode,
        "alpn": [str(a).lower() for a in sec.get("alpn") or []],
        "fp": sec.get("fingerprint", ""), "flow": flow,
        "pbk": sec.get("publicKey", ""), "sid": sec.get("shortId", ""),
        "spx": sec.get("spiderX", ""),
        "insecure": bool(sec.get("allowInsecure")),
        "ss_method": ss_method,
        "label": "", "raw": outbound.get("tag", ""),
    }


def sudo_run(args, **kwargs):
    return subprocess.run(["sudo", "-n"] + args, **kwargs)


def read_config(path):
    result = sudo_run(["cat", path], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("cannot read %s: %s" % (path, result.stderr.strip()))
    return json.loads(result.stdout)


def validate_config_text(text):
    """Run `xray -test` on the given config text; raises SystemExit if invalid."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write(text)
        tmp_path = fh.name
    try:
        env = dict(os.environ, XRAY_LOCATION_ASSET=ASSET_DIR)
        result = subprocess.run(
            [XRAY_BIN, "run", "-test", "-config", tmp_path],
            capture_output=True, text=True, env=env, timeout=60,
        )
        if result.returncode != 0:
            raise SystemExit("xray rejected the config:\n%s"
                             % (result.stdout + result.stderr).strip())
    finally:
        os.unlink(tmp_path)


def tighten_mode(path):
    """Drop group/world write bits on the config (it holds node credentials).

    Only ever tightens: a deliberately stricter mode (e.g. 600) is left alone.
    """
    mode = sudo_run(["stat", "-c", "%a", path], capture_output=True, text=True).stdout.strip()
    try:
        current = int(mode, 8)
    except ValueError:
        return None
    if current & 0o022:
        if sudo_run(["chmod", "0644", path]).returncode == 0:
            return "0644"
    return None


def write_config(path, config, keep_backup=True):
    """Validate, back up and write the config; returns the backup path."""
    text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    validate_config_text(text)
    backup = ""
    if keep_backup:
        backup = "%s.bak.%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        if sudo_run(["cp", "-p", path, backup]).returncode != 0:
            raise SystemExit("cannot create backup %s" % backup)
    result = sudo_run(["tee", path], input=text, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("cannot write %s: %s" % (path, result.stderr.strip()))
    fixed = tighten_mode(path)
    if fixed:
        print("权限已收紧: %s -> %s（原文件对所有人可写）" % (path, fixed))
    return backup


def verify_written_config(path, backup, state_path=None, state_backup=""):
    """Re-validate the config actually on disk; roll back config+state if broken.

    The bytes written are identical to the text validated before the write, so a
    failure here means something external (disk, permissions, concurrent edit).
    Restoring the backup keeps the running service consistent.
    """
    env = dict(os.environ, XRAY_LOCATION_ASSET=ASSET_DIR)
    result = subprocess.run(
        [XRAY_BIN, "run", "-test", "-config", path],
        capture_output=True, text=True, env=env, timeout=60,
    )
    if result.returncode == 0:
        print("写入后校验通过: Configuration OK")
        return True
    print("写入后校验失败:\n%s" % ((result.stdout + result.stderr).strip(),))
    if backup and sudo_run(["cp", "-p", backup, path]).returncode == 0:
        tighten_mode(path)
        print("已回滚配置到备份 %s" % backup)
        if state_path and state_backup and sudo_run(
                ["cp", "-p", state_backup, state_path]).returncode == 0:
            print("已回滚节点清单 %s" % state_path)
    return False


# --------------------------------------------------------------------------- #
# report / service helpers
# --------------------------------------------------------------------------- #
def write_report(path, report):
    if not path:
        return
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print("报告: %s" % path)


def restart_service():
    """Restart (or start) xray.service when it is active or enabled."""
    state = subprocess.run(["systemctl", "is-active", "xray"],
                           capture_output=True, text=True).stdout.strip()
    enabled = subprocess.run(["systemctl", "is-enabled", "xray"],
                             capture_output=True, text=True).stdout.strip()
    if state == "active":
        if sudo_run(["systemctl", "restart", "xray"]).returncode != 0:
            print("重启 xray.service 失败")
            return False
        print("已重启 xray.service")
        return True
    if enabled == "enabled":
        if sudo_run(["systemctl", "start", "xray"]).returncode != 0:
            print("启动 xray.service 失败")
            return False
        print("xray.service 原本未运行（已 enabled），已启动")
        return True
    print("xray.service 状态 %s / %s，未动它（如需启用: sudo systemctl enable --now xray）"
          % (state or "unknown", enabled or "unknown"))
    return False


# --------------------------------------------------------------------------- #
# sing-box 部署（2026-10-03，参考另一台机器的 update_nodes.py）
# xray 只装严格验证的最快节点；sing-box 额外承载：
#   * hysteria2（xray 出站也支持，转换过去让 urltest 统一体检）
#   * tuic（sing-box 独占协议，xray 跑不了，无法本地验证，交给 urltest 体检）
#   * 已验证节点 + TCP 存活但未过 204 的填充节点（urltest 每 3 分钟体检，
#     通不过的自动不承载流量），
# 并把整台 xray（via-xray）作为一个成员挂进 urltest，final=auto 自动选路。
# --------------------------------------------------------------------------- #
SB_ONLY_SCHEMES = ("tuic",)
SB_CONFIG = "/etc/sing-box/config.json"
SB_WORKDIR = "/var/lib/sing-box"
SB_RULESET_URLS = {
    "geosite-cn.srs": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn.srs": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
}
# sing-box 只认这组 uTLS 指纹；链接里常见的 fp=unsafe 等直接忽略（走标准 TLS）
SB_UTLS_FINGERPRINTS = {
    "", "chrome", "firefox", "safari", "ios", "android", "edge", "360",
    "qq", "random", "randomized", "randomizednoalpn", "chrome psk",
}


def to_singbox_outbound(node, tag):
    """node dict -> sing-box outbound；sing-box 跑不了的传输/协议返回 None。"""
    scheme = node["scheme"]
    ob = {"tag": tag, "server": node["address"], "server_port": int(node["port"])}

    if scheme == "vless":
        ob["type"] = "vless"
        ob["uuid"] = node["user"]
        if node.get("flow"):
            ob["flow"] = node["flow"]
    elif scheme == "vmess":
        ob["type"] = "vmess"
        ob["uuid"] = node["user"]
        ob["security"] = "auto"
    elif scheme == "trojan":
        ob["type"] = "trojan"
        ob["password"] = node["user"]
    elif scheme == "ss":
        if not node.get("ss_method"):
            return None
        ob["type"] = "shadowsocks"
        ob["method"] = node["ss_method"]
        ob["password"] = node["user"]
    elif scheme == "hysteria2":
        ob["type"] = "hysteria2"
        ob["password"] = node["user"]
        ob["tls"] = {"enabled": True,
                     "server_name": node.get("sni") or node["address"],
                     "insecure": bool(node.get("insecure"))}
        return ob
    elif scheme == "tuic":
        uuid, _, pwd = node["user"].partition(":")
        if not uuid:
            return None
        ob["type"] = "tuic"
        ob["uuid"] = uuid
        ob["password"] = pwd
        ob["congestion_control"] = "bbr"
        ob["tls"] = {"enabled": True,
                     "server_name": node.get("sni") or node["address"],
                     "insecure": bool(node.get("insecure")),
                     "alpn": node.get("alpn") or ["h3"]}
        return ob
    else:
        return None

    net = node["network"]
    if net == "xhttp":
        return None  # sing-box 没有 xhttp 出站

    sec = node["security"]
    fp = (node.get("fp") or "").lower()
    if sec == "tls":
        tls = {"enabled": True,
               "server_name": node.get("sni") or node.get("host") or node["address"],
               "insecure": bool(node.get("insecure"))}
        if fp in SB_UTLS_FINGERPRINTS and fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        ob["tls"] = tls
    elif sec == "reality":
        if not node.get("pbk"):
            return None
        tls = {"enabled": True,
               "server_name": node.get("sni") or node["address"],
               "reality": {"enabled": True, "public_key": node["pbk"],
                           "short_id": node.get("sid") or ""}}
        if fp in SB_UTLS_FINGERPRINTS and fp:
            tls["utls"] = {"enabled": True,
                           "fingerprint": fp if fp.startswith("random") else "chrome"}
        else:
            tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
        ob["tls"] = tls

    if net == "ws":
        tr = {"type": "ws", "path": node.get("path") or "/"}
        if node.get("host"):
            tr["headers"] = {"Host": node["host"]}
        ob["transport"] = tr
    elif net == "httpupgrade":
        tr = {"type": "httpupgrade", "path": node.get("path") or "/"}
        if node.get("host"):
            tr["host"] = node["host"]
        ob["transport"] = tr
    elif net == "grpc":
        tr = {"type": "grpc", "service_name": node.get("path") or ""}
        if node.get("mode") == "multi":
            tr["multi_mode"] = True
        ob["transport"] = tr
    elif net not in ("tcp", "hysteria", ""):
        return None
    return ob


def ensure_sb_rulesets():
    """下载 sing-box 的 CN 直连规则集（.srs）；失败只降级为不做 CN 分流。"""
    sudo_run(["mkdir", "-p", SB_WORKDIR])
    got = []
    for fname, url in SB_RULESET_URLS.items():
        remote_path = os.path.join(SB_WORKDIR, fname)
        if sudo_run(["test", "-s", remote_path]).returncode != 0:
            local_tmp = os.path.join(tempfile.gettempdir(), "sb-" + fname)
            try:
                result = subprocess.run(["curl", "-sL", "--max-time", "30", url],
                                        capture_output=True, timeout=40)
                if result.returncode == 0 and len(result.stdout) > 1000:
                    with open(local_tmp, "wb") as fh:
                        fh.write(result.stdout)
                    sudo_run(["cp", local_tmp, remote_path])
                    os.unlink(local_tmp)
            except Exception:
                pass
        if sudo_run(["test", "-s", remote_path]).returncode == 0:
            got.append(fname)
    print("sing-box 规则集: %s" % (", ".join(got) or "无（跳过 CN 直连分流）"))
    return set(got)


def read_singbox_config():
    """读取 /etc/sing-box/config.json（失败返回空 dict）。"""
    result = sudo_run(["cat", SB_CONFIG], capture_output=True, text=True)
    if result.returncode != 0:
        return {}
    try:
        return json.loads(result.stdout)
    except ValueError:
        return {}


def singbox_outbound_to_node(ob):
    """sing-box 出站 -> node dict（尽力反推，供守护模式体检复用）。

    只覆盖本脚本 to_singbox_outbound() 会写出的类型；认不出返回 None。
    """
    typ = ob.get("type")
    scheme = {"shadowsocks": "ss"}.get(typ, typ)
    if scheme not in ("vless", "vmess", "trojan", "ss", "hysteria2", "tuic"):
        return None
    address = ob.get("server", "")
    try:
        port = int(ob.get("server_port") or 0)
    except (TypeError, ValueError):
        return None

    if scheme in ("vless", "vmess"):
        user = ob.get("uuid", "")
    elif scheme == "trojan":
        user = ob.get("password", "")
    elif scheme == "ss":
        user = ob.get("password", "")
    elif scheme == "hysteria2":
        user = ob.get("password", "")
    else:  # tuic
        user = "%s:%s" % (ob.get("uuid", ""), ob.get("password", ""))

    tls = ob.get("tls") or {}
    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        security, sni = "reality", tls.get("server_name", "")
        pbk, sid = reality.get("public_key", ""), reality.get("short_id", "")
    elif tls.get("enabled"):
        security, sni, pbk, sid = "tls", tls.get("server_name", ""), "", ""
    else:
        security, sni, pbk, sid = "", "", "", ""
    fp = (tls.get("utls") or {}).get("fingerprint", "")

    tr = ob.get("transport") or {}
    net = tr.get("type", "tcp")
    host = (tr.get("headers") or {}).get("Host") or tr.get("host", "")
    if net == "grpc":
        path = "/" + (tr.get("service_name") or "")
    else:
        path = tr.get("path", "/")
    return {
        "scheme": scheme, "user": user, "address": address, "port": port,
        "security": security, "sni": sni, "network": net,
        "path": _fix_path(path), "host": host, "mode": "",
        "alpn": _uniq_low([str(a).lower() for a in (tls.get("alpn") or [])]),
        "fp": fp, "flow": ob.get("flow", ""), "pbk": pbk, "sid": sid, "spx": "",
        "insecure": bool(tls.get("insecure")),
        "ss_method": ob.get("method", "") if scheme == "ss" else "",
        "label": ob.get("tag", ""), "raw": ob.get("tag", ""),
    }


def build_singbox_config(outbounds, rulesets):
    rules = [{"action": "sniff"},
             {"ip_is_private": True, "action": "route", "outbound": "direct"}]
    rule_set = []
    for fname in sorted(rulesets):
        rules.append({"rule_set": [fname[:-4]], "action": "route",
                      "outbound": "direct"})
        rule_set.append({"type": "local", "tag": fname[:-4], "format": "binary",
                         "path": os.path.join(SB_WORKDIR, fname)})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "::", "listen_port": 10808},
            {"type": "http", "tag": "http-in", "listen": "::", "listen_port": 10809},
        ],
        "outbounds": [
            {"type": "urltest", "tag": "auto", "outbounds": [o["tag"] for o in outbounds],
             "url": "https://www.google.com/generate_204",
             "interval": "3m", "tolerance": 50},
            *outbounds,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": rules, "rule_set": rule_set, "final": "auto"},
    }


def deploy_singbox(sb_nodes, sb_max):
    """构建并部署 sing-box 配置；返回部署的节点数（0 = 未部署/失败保留旧配置）。

    sb_nodes 已是 sing-box 侧独立测速、按延迟从快到慢排好序的节点（含 tuic 等只有
    sing-box 能跑的协议——它们也走 sing-box 自己的探测）。这里只做去重 + 截断到
    sb_max + 追加 via-xray 成员，交给 urltest 运行时自动选路。
    """
    rulesets = ensure_sb_rulesets()
    outbounds, seen = [], set()
    for node in sb_nodes:
        if len(outbounds) >= sb_max:
            break
        key = node_key(node)
        if key in seen:
            continue
        seen.add(key)
        ob = to_singbox_outbound(node, "sb%d" % (len(outbounds) + 1))
        if ob:
            outbounds.append(ob)
    if not outbounds:
        print("sing-box: 没有可部署的节点，保留现有配置")
        return 0
    # 整台 xray 作为 urltest 的一个成员（它的 socks-in 在 127.0.0.1:54321）
    outbounds.append({"type": "socks", "tag": "via-xray", "server": "127.0.0.1",
                      "server_port": 54321, "version": "5"})

    cfg = build_singbox_config(outbounds, rulesets)
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="sb-config-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    check = subprocess.run(["sing-box", "check", "-c", tmp],
                           capture_output=True, text=True)
    if check.returncode != 0:
        print("sing-box 配置校验失败，保留现有配置:\n%s%s"
              % (check.stdout, check.stderr))
        os.unlink(tmp)
        return 0
    backup = ""
    if sudo_run(["test", "-f", SB_CONFIG]).returncode == 0:
        backup = "%s.bak.%s" % (SB_CONFIG, time.strftime("%Y%m%d-%H%M%S"))
        sudo_run(["cp", "-p", SB_CONFIG, backup])
    if sudo_run(["cp", "-p", tmp, SB_CONFIG]).returncode != 0:
        print("sing-box 配置写入失败")
        os.unlink(tmp)
        return 0
    os.unlink(tmp)
    if subprocess.run(["systemctl", "is-active", "sing-box"],
                      capture_output=True, text=True).stdout.strip() == "active":
        sudo_run(["systemctl", "restart", "sing-box"])
        print("sing-box: 部署 %d 个出站（含 via-xray），服务已重启（备份 %s）"
              % (len(outbounds), backup or "-"))
    else:
        print("sing-box: 配置已写入 %d 个出站，但服务未运行，未重启" % len(outbounds))
    return len(outbounds)




def collect_sub_urls(args):
    """汇总订阅 URL：`-s` 参数 + subscriptions.txt（每行一个，# 注释），再展开
    datepattern 模板并去重保序。

    2026-10-12 起**不再读取 node.txt** 作为数据来源（需求 1）；`-n/--node-file`
    仅为兼容旧命令行保留，不再参与取数。
    """
    urls = list(args.subscribe)
    if os.path.exists(DEFAULT_SUB_FILE):
        with open(DEFAULT_SUB_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    urls = expand_datepatterns(urls)
    return list(dict.fromkeys(urls))     # 去重保序


def fetch_all_nodes(urls):
    """并发拉取并解析全部订阅；内容相同的镜像只解析一次（SHA256 去重）。

    返回 (nodes, sub_report)。不过滤协议支持——分区/跳过交由调用方按核心判定，
    这样 tuic 等只有 sing-box 能跑的协议也能进入 sing-box 候选池。
    """
    nodes, sub_report = [], []
    if urls:
        print("订阅源 %d 个（-s / subscriptions.txt，datepattern 模板已展开）..."
              % len(urls))
    seen_bodies = {}

    def _fetch_one(url):
        return url, fetch_subscription(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for url, text in ex.map(_fetch_one, urls):
            if text is None:
                print("  ⚠️ 拉取失败: %s" % url)
                sub_report.append({"url": url, "ok": False, "nodes": 0})
                continue
            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
            if digest in seen_bodies:
                print("  = %s: 与 %s 内容相同，跳过" % (url, seen_bodies[digest]))
                sub_report.append({"url": url, "ok": True, "nodes": 0,
                                   "duplicate_of": seen_bodies[digest]})
                continue
            seen_bodies[digest] = url
            parsed = parse_subscription(text)
            sub_report.append({"url": url, "ok": True, "nodes": len(parsed),
                               "bytes": len(text)})
            print("  ✔ %s: %d 个节点" % (url, len(parsed)))
            nodes.extend(parsed)
    return nodes, sub_report


def test_engine(pool, args, engine, keep, label):
    """对一侧核心跑完整测速流水线：快速筛选 -> 精确测量 -> 失败复测 -> 排名复测 -> 排名。

    两段测速（--screen-timeout，默认开）：第一段用短超时 + 单次尝试把 ~99% 死节点
    快速淘汰（不再等满 --timeout×attempts），只有存活者进第二段用完整参数精确测延迟。
    候选池沿用 TCP 预扫描的握手延迟升序（不再洗牌），配合早停“找到够用的就停”。

    返回 dict：results / kept / dropped_slow / usable / failed / stop_reason /
    regions / reranked / elapsed / pool。engine ∈ {"xray", "sing-box"}。
    """
    # 早停目标：够用即可停。keep>0 时取 min(keep, 目标)，避免为凑够更多而多测。
    stop_target = min(keep, args.early_stop_target) if keep else args.early_stop_target
    if args.early_stop and stop_target:
        print("[%s] 已启用提前结束：可用 ≥ %d 且延迟中位数 ≤ %.2fs 即停止剩余测速"
              % (label, stop_target, args.early_stop_fast))

    def early_stop(usable_lats):
        if not args.early_stop or not stop_target:
            return False
        if len(usable_lats) < stop_target:
            return False
        lats = sorted(usable_lats)
        return lats[len(lats) // 2] <= args.early_stop_fast

    screen_timeout = args.screen_timeout if args.screen_timeout and args.screen_timeout > 0 else 0
    two_stage = bool(screen_timeout) and screen_timeout < args.timeout

    started = time.time()
    if two_stage:
        print("[%s] 两段测速：第一段 %.1fs 快速筛选（1 次尝试），存活者再用 %.1fs×%d 精确测量..."
              % (label, screen_timeout, args.timeout, max(1, args.attempts)))
        results, stop_reason = probe_all(pool, args.workers, screen_timeout, 1, 1,
                                         early_stop=early_stop, engine=engine,
                                         label=label + "-筛")
        # 第二段：只对筛选存活者用完整参数精确测延迟（并发仍为 workers，求快）。
        survivor_idx = [i for i, row in enumerate(results) if row["ok"]]
        if survivor_idx:
            print("[%s] 筛选存活 %d 个，进入精确测量..." % (label, len(survivor_idx)),
                  file=sys.stderr, flush=True)
            refined = probe_all([pool[i] for i in survivor_idx], args.workers,
                                args.timeout, args.attempts, args.samples,
                                engine=engine, label=label + "-精测")[0]
            for idx, row in zip(survivor_idx, refined):
                if row["ok"]:
                    results[idx] = row          # 用精确测量结果覆盖筛选结果
                else:
                    # 精测罕见地失败（筛选已通过）：保留筛选的可用结论，只是延迟取筛选值。
                    results[idx]["reason"] += " [精测未复现，沿用筛选]"
    else:
        print("[%s] 开始测速（每个节点起一个临时 %s + SOCKS 双204 探测，取样 %d 次）..."
              % (label, "Xray" if engine == "xray" else "sing-box", max(1, args.samples)))
        results, stop_reason = probe_all(pool, args.workers, args.timeout,
                                         args.attempts, args.samples,
                                         early_stop=early_stop, engine=engine, label=label)

    failed_idx = [i for i, row in enumerate(results) if not row["ok"]]
    if failed_idx and args.retest:
        # 只复测“软失败”：跳过 HTTP 000（隧道完全不通的真死节点）、
        # sing-box 结构性无法承载的节点，以及提前结束时根本没测过的节点
        # （(提前结束，未测) 不是失败，是未测量——把它们塞进低并发复测等于
        # 把提前结束省下的时间又还回去）。这两类低并发复测也救不回来，
        # 却占了失败的绝大多数（实测几乎全是 HTTP 000）。
        def _soft_failure(r):
            why = r.get("reason") or ""
            if "提前结束" in why:
                return False   # 未测过，非失败，不复测
            return ("HTTP 000" not in why) and ("无法承载" not in why)

        soft_idx = [i for i in failed_idx if _soft_failure(results[i])]
        hard_n = len(failed_idx) - len(soft_idx)
        if args.retest_max and len(soft_idx) > args.retest_max:
            # 极端情况下软失败也可能很多，加总量上限兜底，避免又拖慢。
            soft_idx = soft_idx[:args.retest_max]
        if soft_idx:
            print("[%s] 对 %d 个软失败节点低并发复测（跳过 %d 个 HTTP 000/结构性失败，"
                  "timeout=%ss，避免并发误判）..."
                  % (label, len(soft_idx), hard_n, args.retest_timeout))
            retest = probe_all([pool[i] for i in soft_idx],
                               max(1, args.workers // 6), args.retest_timeout, 1,
                               max(1, args.samples), engine=engine,
                               label=label + "-retest")[0]
            for idx, row in zip(soft_idx, retest):
                if row["ok"]:
                    row["reason"] += " (复测通过)"
                    results[idx] = row
        else:
            print("[%s] 失败 %d 个，全为 HTTP 000/结构性失败，跳过复测"
                  % (label, len(failed_idx)))

    usable_rows = [r for r in results if r["ok"]]
    reranked = 0
    if args.rerank and keep and len(usable_rows) > keep:
        lane = max(4, args.workers // 3)
        print("[%s] 可用 %d > 保留 %d，对全部可用节点做一轮低并发统一复测"
              "（并发 %d，timeout %ss），让取舍公平..." %
              (label, len(usable_rows), keep, lane, args.retest_timeout))
        reranked = refine_ranking(usable_rows, lane, args.retest_timeout,
                                  max(1, args.samples), engine=engine)

    kept, dropped_slow = rank_usable(results, keep)
    usable = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    print("[%s] 测速完成，用时 %.1fs：可用 %d / %d，保留 %d 个%s"
          % (label, time.time() - started, len(usable), len(pool), len(kept),
             "" if not dropped_slow else "（淘汰较慢 %d 个）" % len(dropped_slow)))
    for row in kept[:10]:
        print("  %5.2fs  %-17s %-4s %s" % (
            row["latency"], row["node"]["address"][:17], geo_tag(row["node"]),
            row["node"]["scheme"]))
    regions = {}
    for row in kept:
        regions[geo_tag(row["node"])] = regions.get(geo_tag(row["node"]), 0) + 1
    print("[%s] 保留节点地区分布: %s" % (
        label, ", ".join("%s=%d" % kv for kv in sorted(regions.items(), key=lambda kv: -kv[1])) or "-"))
    return {"results": results, "kept": kept, "dropped_slow": dropped_slow,
            "usable": usable, "failed": failed, "stop_reason": stop_reason,
            "regions": regions, "reranked": reranked,
            "elapsed": round(time.time() - started, 1), "pool": len(pool)}


def singbox_only(args):
    """--singbox-only：跳过 xray，只用 sing-box 核心独立测速并刷新 sing-box。

    数据来源同主流程（subscriptions.txt + -s，不含 node.txt）。所有 sing-box 能跑
    的候选（含 tuic 等 xray 跑不了的协议）都过一次 sing-box 双 204 探测，按延迟
    取前 --sb-max 个交给 urltest 运行时自动选路。
    """
    urls = collect_sub_urls(args)
    print("拉取 %d 个订阅源..." % len(urls))
    all_nodes, _ = fetch_all_nodes(urls)
    seen, pool = set(), []
    for n in all_nodes:
        if not singbox_supported(n):
            continue
        key = node_key(n)
        if key not in seen:
            seen.add(key)
            pool.append(n)
    print("sing-box 候选 %d 个" % len(pool))
    tcp_dropped = 0
    if args.tcpscan and pool:
        _TCP_CACHE.clear()
        before = len(pool)
        pool = tcp_presize(pool, workers=args.prescan_workers,
                           timeout=args.prescan_timeout,
                           max_candidates=args.max_candidates)
        tcp_dropped = before - len(pool)
    out = test_engine(pool, args, "sing-box", args.sb_max, "sing-box")
    deployed = deploy_singbox([r["node"] for r in out["kept"]], args.sb_max)
    print("sing-box 部署完成: %d 个出站（TCP 预过滤 %d）" % (deployed, tcp_dropped))
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def default_workers():
    """并发测试数的自适应默认值。

    测速几乎全是 IO 等待（起临时核心 + 等端口 + curl 双 204 走代理到境外），
    CPU 占用很低，所以并发可以远超核数。这里取 CPU 核数的 8 倍，并用可用内存
    做一道护栏：实测单个临时探测核心 RSS 约 30MB，按 64MB（约 2 倍余量）估，
    确保开满也不至于把内存打爆。返回一个 [16, 192] 区间内的整数。
    """
    cpu = os.cpu_count() or 4
    target = cpu * 8
    # 内存护栏：可用内存(MB) / 64MB，至少给 16，最多 192。
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    avail_mb = int(line.split()[1]) // 1024
                    target = min(target, max(16, avail_mb // 64))
                    break
    except (OSError, ValueError):
        pass
    return max(16, min(target, 192))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="从订阅源拉取节点，xray 与 sing-box 各自独立测速，"
                    "各自保留最快的前 N 个写进对应配置。")
    parser.add_argument("-n", "--node-file", default=DEFAULT_NODE_FILE,
                        help=argparse.SUPPRESS)  # 已废弃：不再从 node.txt 取数
    parser.add_argument("-s", "--subscribe", action="append", default=[], metavar="URL",
                        help="额外订阅 URL（可重复）；脚本旁的 subscriptions.txt"
                             "（每行一个 URL，# 注释）也会被当作订阅拉取")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG,
                        help="Xray 配置文件，默认 %s" % DEFAULT_CONFIG)
    parser.add_argument("-w", "--workers", type=int, default=default_workers(),
                        help="并发测试数；测速以 IO 等待为主，默认按 CPU 核数×8 并"
                             "受可用内存护栏自适应，当前默认 %d" % default_workers())
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="单个节点探测超时秒数，默认 8")
    parser.add_argument("-a", "--attempts", type=int, default=2, help="每个节点尝试次数，默认 2")
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES,
                        help="测速取样次数（取最快一次），默认 %d" % DEFAULT_SAMPLES)
    parser.add_argument("-k", "--keep", type=int, default=DEFAULT_KEEP,
                        help="xray 侧只保留最快的前 N 个节点，0 = 不限制，默认 %d" % DEFAULT_KEEP)
    parser.add_argument("--max-nodes", type=int, default=None,
                        help=argparse.SUPPRESS)  # 旧参数名，等价于 --keep
    parser.add_argument("--keep-manual", dest="adopt", action="store_false",
                        help="不接管手写的 proxy_* 出站（默认接管：和订阅节点一起"
                             "测速，快则留、慢则删）")
    parser.add_argument("--append", action="store_true",
                        help="追加模式：保留本次运行前已有的脚本节点（默认替换为最新最快的一批）")
    parser.add_argument("--no-rerank", dest="rerank", action="store_false",
                        help="关闭“保留前的低并发统一复测”（默认开启：可用数超过保留数时会复测一轮）")
    parser.add_argument("--no-retest", dest="retest", action="store_false",
                        help="关闭“失败节点串行复测”（默认开启，避免并发误判）")
    parser.add_argument("--no-tcpscan", dest="tcpscan", action="store_false",
                        help="关闭 TCP 预扫描（默认开启：裸 TCP 连不上的端点"
                             "直接淘汰，不起临时核心；hysteria2/tuic 豁免）")
    parser.add_argument("--prescan-workers", type=int, default=500, metavar="N",
                        help="TCP 预扫描并发数，默认 500（裸 TCP 连接 IO 密集，"
                             "可远高于测速并发；xray/sing-box 两池共享扫描缓存）")
    parser.add_argument("--prescan-timeout", type=float, default=1.5, metavar="SEC",
                        help="TCP 预扫描单端点握手超时秒数，默认 1.5（正常握手 200–400ms，"
                             "1.5s 足够，死端点不必等满更久）")
    parser.add_argument("--screen-timeout", type=float, default=4.0, metavar="SEC",
                         help="两段测速第一段(快速筛选)的超时秒数，默认 4；死节点在此"
                              "被快速淘汰，只有存活者进第二段用 --timeout 精确测延迟。"
                              "设为 0 关闭两段测速（退回单段 --timeout 全量测量）")
    parser.add_argument("--max-candidates", type=int, default=0, metavar="N",
                        help="TCP 预扫描后按握手延迟升序，只取前 N 个可扫描候选进入测速"
                             "（hysteria2/tuic 豁免不受限）；0 = 不限制（默认），"
                             "用来在候选很多时给测速预算封顶")
    parser.add_argument("--no-early-stop", dest="early_stop", action="store_false",
                        help="关闭提前结束（默认开启：可用数达到保留数且延迟"
                             "中位数 ≤ --early-stop-fast 时，取消剩余未开测的节点）")
    parser.add_argument("--early-stop-fast", type=float, default=1.5, metavar="SEC",
                        help="提前结束的“够快”标准：可用节点延迟中位数阈值秒数，默认 1.5")
    parser.add_argument("--early-stop-target", type=int, default=30, metavar="N",
                        help="提前结束的目标可用节点数：可用数达到此值且延迟中位数 ≤ "
                             "--early-stop-fast 就取消剩余未测节点（早停目标，默认 30，"
                             "与 --keep 分开，可独立设小以更快收尾）")
    parser.add_argument("--sb-max", type=int, default=DEFAULT_SB_MAX, metavar="N",
                        help="sing-box 侧最多保留多少个节点出站（另加 via-xray），默认 %d"
                             % DEFAULT_SB_MAX)
    parser.add_argument("--no-singbox", dest="singbox", action="store_false",
                        help="跳过 sing-box 测速与部署，只更新 xray")
    parser.add_argument("--singbox-only", action="store_true",
                        help="只用 sing-box 核心独立测速并刷新 sing-box，跳过 xray")
    parser.add_argument("--watch", action="store_true",
                        help="守护模式：循环体检已部署节点，健康数低于 --watch-min 时"
                             "自动重新跑一次完整同步（维护可用节点数量）")
    parser.add_argument("--watch-interval", type=int, default=300, metavar="SEC",
                        help="守护模式每次体检间隔秒数，默认 300")
    parser.add_argument("--watch-min", type=int, default=30, metavar="N",
                        help="守护模式：任一核心健康节点少于此值就触发重同步，默认 30")
    parser.add_argument("--watch-health-timeout", type=float, default=6.0, metavar="SEC",
                        help="守护模式单节点体检超时秒数，默认 6")
    parser.add_argument("--retest-timeout", type=float, default=15.0,
                        help="复测时的单节点超时秒数，默认 15")
    parser.add_argument("--retest-max", type=int, default=400, metavar="N",
                        help="单侧最多复测多少个软失败节点（总量兜底上限，"
                             "0 表示不限制），默认 400")
    parser.add_argument("--remove-old", action="store_true",
                        help=argparse.SUPPRESS)  # 早期参数名，默认行为已是替换式同步
    parser.add_argument("--prune-dead", action="store_true",
                        help="额外重测配置里非脚本管理的 proxy 出站，删除失效的")
    parser.add_argument("--dry-run", action="store_true", help="只测试，不修改配置文件")
    parser.add_argument("--restart", action="store_true",
                        help="写入后重启（或启动）xray.service")
    parser.add_argument("--state", default=STATE_FILE,
                        help="脚本自己的节点清单（记录它写入的 tag），默认 %s；留空则不写"
                             % STATE_FILE)
    parser.add_argument("--report", default=os.path.join(SCRIPT_DIR, "last_run.json"),
                        help="JSON 报告路径，留空则不写")
    args = parser.parse_args(argv)
    if args.max_nodes is not None:
        args.keep = args.max_nodes
    return args


def run_sync(args):
    """跑一次完整同步：拉订阅 -> 分区 -> xray / sing-box 各自独立测速 -> 写两侧配置。

    返回 (rc, report)。dry-run 与写后校验失败也返回 report，便于守护模式复用。
    """
    urls = collect_sub_urls(args)
    if not urls:
        raise SystemExit("没有订阅源：subscriptions.txt 为空且未用 -s 指定")
    all_nodes, sub_report = fetch_all_nodes(urls)

    # The config is read up front: hand-written proxy_* outbounds (proxy_sub1_…)
    # are adopted into the same pool, so they are measured and ranked next to the
    # subscription nodes instead of being kept forever.
    config = read_config(args.config)
    outbounds = config.setdefault("outbounds", [])
    total_before = len(outbounds)
    state_tags = load_state(args.state)

    adopted, untouched_manual = [], []
    if args.adopt:
        adopted, untouched_manual = adoptable_proxies(config)

    pool = []
    known = set()
    for node in all_nodes:
        key = node_key(node)
        if key in known:
            continue
        known.add(key)
        pool.append(node)
    adopted_new = []
    for tag, node in adopted:
        if node_key(node) in known:
            continue
        known.add(node_key(node))
        pool.append(node)
        adopted_new.append(tag)

    # ---- 分区：xray / sing-box 各自只测自己核心能真跑的节点（需求 3）----
    xray_pool, sb_pool, skipped = partition_pool(pool)
    for reason, label in skipped:
        print("  跳过: %-45s %s" % (reason, label))
    if adopted:
        print("接管配置里手写的 %d 个 proxy 出站一起测速（快则留、慢则删）: %s"
              % (len(adopted), ", ".join(tag for tag, _ in adopted)))
    if untouched_manual:
        print("保留（无法识别参数，未参与测速）: %s" % ", ".join(untouched_manual))
    if adopted_new:
        print("其中 %d 个是订阅里没有的，已加入候选池" % len(adopted_new))
    print("候选池共 %d 个：xray 侧 %d，sing-box 侧 %d（两边都跑不了 %d）"
          % (len(pool), len(xray_pool), len(sb_pool), len(skipped)))

    # ---- TCP 预扫描：死端点直接淘汰，省掉为它们起临时核心的开销 ----
    tcp_dropped = 0
    if args.tcpscan:
        _TCP_CACHE.clear()   # 两池共享同一批端点的扫描缓存；每次同步开始时重置
        before_x, before_s = len(xray_pool), len(sb_pool)
        if xray_pool:
            xray_pool = tcp_presize(xray_pool, workers=args.prescan_workers,
                                    timeout=args.prescan_timeout,
                                    max_candidates=args.max_candidates)
        if sb_pool and args.singbox:
            sb_pool = tcp_presize(sb_pool, workers=args.prescan_workers,
                                  timeout=args.prescan_timeout,
                                  max_candidates=args.max_candidates)
        tcp_dropped = (before_x - len(xray_pool)) + (before_s - len(sb_pool))

    # ---- xray 侧独立测速 ----
    xout = test_engine(xray_pool, args, "xray", args.keep, "xray")
    results, kept, dropped_slow = xout["results"], xout["kept"], xout["dropped_slow"]
    working, failed, regions = xout["usable"], xout["failed"], xout["regions"]
    stop_reason, reranked = xout["stop_reason"], xout["reranked"]

    # ---- sing-box 侧独立测速（需求 3：与 xray 分开跑，各自保留前 sb-max 个）----
    sout = None
    if args.singbox:
        sout = test_engine(sb_pool, args, "sing-box", args.sb_max, "sing-box")

    config = read_config(args.config)
    outbounds = config.setdefault("outbounds", [])
    total_before = len(outbounds)

    state_tags = load_state(args.state)
    pruned_tags = []
    adopted_tags = [tag for tag, _ in adopted]
    kept_keys = {node_key(r["node"]) for r in kept}
    adopted_kept = sorted(tag for tag, node in adopted if node_key(node) in kept_keys)
    adopted_dropped = [t for t in adopted_tags if t not in adopted_kept]
    if args.append:
        # Legacy behaviour: keep what is already configured, only add new nodes.
        removed = []
        print("追加模式：保留配置里已有的脚本节点")
    else:
        removed = drop_managed(config, state_tags, adopted_tags)
        print("替换模式：移除上一批脚本节点 %d 个（其余 %d 个出站保留）"
              % (len(removed), len(outbounds)))
        if adopted_tags:
            print("手写出站：%d 个速度不够被淘汰%s；%d 个进入保留名单，按统一格式重写"
                  % (len(adopted_dropped),
                     "（%s）" % ", ".join(adopted_dropped) if adopted_dropped else "",
                     len(adopted_kept)))

    if args.prune_dead:
        remaining_owned = owned_tags(config, state_tags, adopted_tags)
        pairs = [(o, outbound_to_node(o)) for o in list(outbounds)
                 if (o.get("tag") or "") not in remaining_owned]
        pairs = [(o, n) for o, n in pairs if n is not None]
        print("重测配置里非脚本管理的 %d 个 proxy 出站..." % len(pairs))
        for (outbound, _node), row in zip(pairs, probe_all(
                [n for _o, n in pairs], args.workers, args.timeout, args.attempts,
                max(1, args.samples))[0]):
            if not row["ok"]:
                pruned_tags.append(outbound.get("tag", "?"))
                outbounds.remove(outbound)
        print("失效出站 %d 个: %s" % (len(pruned_tags), ", ".join(pruned_tags) or "-"))

    added, duplicates = merge_working(config, [row["node"] for row in kept])

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": args.config,
        "candidates": len(pool),
        "subscription_sources": sub_report,
        "pool": len(pool),
        "xray_pool": len(xray_pool),
        "singbox_pool": len(sb_pool),
        "tcp_dropped": tcp_dropped,
        "early_stop": stop_reason,
        "adopted_manual": adopted_tags,
        "adopted_kept": adopted_kept,
        "adopted_dropped": adopted_dropped,
        "manual_untouched": untouched_manual,
        "usable": len(working),
        "keep": args.keep,
        "reranked": reranked,
        "kept": [{"address": r["node"]["address"], "port": r["node"]["port"],
                  "region": geo_tag(r["node"]), "latency": r["latency"],
                  "scheme": r["node"]["scheme"]} for r in kept],
        "dropped_slow": [{"address": r["node"]["address"], "port": r["node"]["port"],
                          "region": geo_tag(r["node"]), "latency": r["latency"],
                          "scheme": r["node"]["scheme"]}
                         for r in dropped_slow],
        "usable_regions": regions,
        "recovered_by_retest": sum(1 for r in results if "复测通过" in r["reason"]),
        "skipped_unsupported": [{"reason": r, "label": l} for r, l in skipped],
        "failed": [{"address": r["node"]["address"], "port": r["node"]["port"],
                    "region": geo_tag(r["node"]), "reason": r["reason"]} for r in failed],
        "removed_managed": removed,
        "added": [{"tag": o["tag"], "protocol": o["protocol"],
                   "address": o["settings"].get("servers", [{}])[0].get("address")
                   or o["settings"].get("vnext", [{}])[0].get("address"),
                   "port": o["settings"].get("servers", [{}])[0].get("port")
                   or o["settings"].get("vnext", [{}])[0].get("port")} for o in added],
        "duplicates": duplicates,
        "pruned": pruned_tags,
        "pinned": args.config,
        "backup": "",
        "applied": False,
        "singbox": None,
    }
    if sout is not None:
        report["singbox"] = {
            "pool": sout["pool"],
            "usable": len(sout["usable"]),
            "kept": len(sout["kept"]),
            "sb_max": args.sb_max,
            "regions": sout["regions"],
            "kept_nodes": [{"address": r["node"]["address"], "port": r["node"]["port"],
                            "region": geo_tag(r["node"]), "latency": r["latency"],
                            "scheme": r["node"]["scheme"]} for r in sout["kept"]],
        }

    if args.dry_run:
        print("\n[dry-run] 候选 %d，xray 可用 %d 保留 %d，sing-box 可用 %s 保留 %s，"
              "移除脚本/手写出站 %d，将写入 %d（配置未改动）"
              % (len(pool), len(working), len(kept),
                 len(sout["usable"]) if sout else 0, len(sout["kept"]) if sout else 0,
                 len(removed), len(added)))
        print("正式应用请运行: %s" % os.path.join(SCRIPT_DIR, "apply.sh"))
        write_report(args.report, report)
        return 0, report

    report["backup"] = write_config(args.config, config)
    report["applied"] = True
    state_backup = ""
    if args.state and os.path.exists(args.state):
        state_backup = "%s.bak.%s" % (args.state, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(args.state, state_backup)
    save_state({
        "updated_at": report["generated_at"],
        "managed_tags": [o["tag"] for o in added],
        "latency": {o["tag"]: r["latency"] for o, r in zip(added, kept)},
    }, args.state)
    print("\n配置已写入 %s（备份 %s）" % (args.config, report["backup"]))
    print("出站总数 %d -> %d（移除旧脚本节点 %d，新增 %d，重复跳过 %d，清理失效 %d）"
          % (total_before, len(outbounds), len(removed), len(added),
             duplicates, len(pruned_tags)))
    if args.state:
        print("节点清单已更新: %s（记录 %d 个脚本节点，下次运行整体替换）"
              % (args.state, len(added)))
    else:
        print("未写节点清单（--state 为空），下次运行按 tag 前缀识别脚本节点")

    if not verify_written_config(args.config, report["backup"],
                                 args.state, state_backup):
        report["post_write_check"] = False
        report["applied"] = False
        write_report(args.report, report)
        return 1, report
    report["post_write_check"] = True

    if args.restart:
        report["restarted"] = restart_service()

    # ---- sing-box：部署 sing-box 侧独立测速的前 sb-max 个，交给 urltest 运行时选路 ----
    if not args.dry_run and args.singbox and sout is not None:
        report["singbox_deployed"] = deploy_singbox(
            [r["node"] for r in sout["kept"]], args.sb_max)

    write_report(args.report, report)
    return 0, report


def health_check(args):
    """体检当前已部署的节点，返回 (xray_健康数, sing-box 健康数)。

    直接从两侧配置里把脚本管理的出站反推成节点，用各自核心的低成本单次探测
    量一遍（不做复测/排名），数出还能连通的数量。xray 的 observatory+leastPing、
    sing-box 的 urltest 已在运行时持续“选快汰死”；这里只是判断“够不够多”，不够
    就触发一次完整重同步（见 watch_loop）。
    """
    # xray 侧：配置里脚本管理的 proxy_* 出站
    xray_ok = 0
    try:
        config = read_config(args.config)
        owned = owned_tags(config, load_state(args.state))
        nodes = [n for n in (outbound_to_node(o) for o in config.get("outbounds", [])
                             if (o.get("tag") or "") in owned) if n]
        if nodes:
            rows = probe_all(nodes, max(4, args.workers // 2),
                             args.watch_health_timeout, 1, 1,
                             engine="xray", label="health-xray")[0]
            xray_ok = sum(1 for r in rows if r["ok"])
    except Exception as exc:  # 体检失败不致命，下次再来
        print("[health] xray 体检异常: %r" % exc)

    # sing-box 侧：配置里的 sb* 出站（tag 形如 sb1、sb2…）
    sb_ok = 0
    try:
        sb_cfg = read_singbox_config()
        sb_nodes = [n for n in (singbox_outbound_to_node(o)
                                for o in sb_cfg.get("outbounds", [])
                                if re.match(r"^sb\d+$", o.get("tag") or "")) if n]
        if sb_nodes:
            rows = probe_all(sb_nodes, max(4, args.workers // 2),
                             args.watch_health_timeout, 1, 1,
                             engine="sing-box", label="health-singbox")[0]
            sb_ok = sum(1 for r in rows if r["ok"])
    except Exception as exc:
        print("[health] sing-box 体检异常: %r" % exc)

    return xray_ok, sb_ok


def watch_loop(args):
    """守护模式：周期性体检两侧已部署节点；任一核心健康数 < --watch-min 就重跑一次
    完整同步，把最新最快的节点补上去，从而“维护可用节点数量”（需求 4）。"""
    print("守护模式启动：每 %ds 体检一次，任一核心健康数 < %d 触发完整重同步"
          % (args.watch_interval, args.watch_min))
    while True:
        xray_ok, sb_ok = health_check(args)
        print("[%s] 体检：xray 健康 %d，sing-box 健康 %d（阈值 %d）"
              % (time.strftime("%Y-%m-%d %H:%M:%S"), xray_ok, sb_ok, args.watch_min))
        if xray_ok < args.watch_min or sb_ok < args.watch_min:
            print("健康节点不足，触发完整重同步...")
            try:
                rc, report = run_sync(args)
                print("重同步完成 rc=%d：xray 保留 %d，sing-box 保留 %s"
                      % (rc, len(report.get("kept", [])),
                         (report.get("singbox") or {}).get("kept", "-")))
            except SystemExit as exc:
                print("重同步被 SystemExit 中断: %s" % exc)
        time.sleep(args.watch_interval)


def main(argv=None):
    args = parse_args(argv)
    if args.singbox_only:
        return singbox_only(args)
    if args.watch:
        watch_loop(args)
        return 0
    rc, _report = run_sync(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
