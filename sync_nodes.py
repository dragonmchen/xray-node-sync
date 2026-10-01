#!/usr/bin/env python3
"""Parse nodes from a local file (node.txt) and/or remote subscriptions, measure
which nodes actually work and how fast they are, then keep only the fastest ones
in the Xray config.

Typical workflow (run inside this directory, node.txt sits next to the script):

    ./preview.sh          # 预览：只测速排名，不改配置
    ./apply.sh            # 正式应用：写入前 100 名并重载 xray

    python3 sync_nodes.py --dry-run              # same as preview.sh
    python3 sync_nodes.py --restart              # same as apply.sh
    python3 sync_nodes.py --keep 50 --workers 32
    python3 sync_nodes.py -s https://example.com/sub.txt   # 额外拉一个订阅

Node sources are combined and de-duplicated as one pool:

  * the local node file (`-n`, default node.txt) - its `http(s)://` lines are
    themselves treated as subscription URLs;
  * every `-s/--subscribe URL` given on the command line (repeatable);
  * `subscriptions.txt` next to the script, when it exists (one URL per line,
    `#` comments allowed).

A downloaded subscription may be plain `scheme://` URI lines, a single
base64 blob of such lines, or a Clash `proxies:` YAML document; all three are
recognized (see parse_subscription()).

For every node a throwaway Xray instance is started (local SOCKS inbound plus
that single outbound) and `curl --socks5-hostname 127.0.0.1:<port>` is run
through it against both gstatic and google.com `generate_204` endpoints: only
when BOTH return 204 the node counts as usable (a gstatic-only hijack node
would otherwise poison the leastPing balancer), and the slower of the two is
used to rank its speed.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_NODE_FILE = os.path.join(SCRIPT_DIR, "node.txt")
DEFAULT_CONFIG = "/etc/xray/config.json"
STATE_FILE = os.path.join(SCRIPT_DIR, "state.json")
DEFAULT_SUB_FILE = os.path.join(SCRIPT_DIR, "subscriptions.txt")
FETCH_TIMEOUT = 20.0          # seconds allowed per subscription download
# Local Xray SOCKS inbound: tried as a fallback when a subscription URL is not
# reachable directly (GitHub raw etc. is often blocked without a proxy).
FALLBACK_PROXY = "socks5h://127.0.0.1:54321"
DEFAULT_KEEP = 100          # 只保留最快的前 N 个节点（0 = 不限制）
DEFAULT_SAMPLES = 2         # 测速时每个节点成功请求的次数（取最快一次）
XRAY_BIN = "xray"
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


def probe_once(outbound, port, workdir, timeout, samples):
    """Run one throwaway Xray with a single outbound and curl through its SOCKS port.

    Returns (ok, latency_seconds, reason): ok is True when at least one request
    returned 204, latency is the fastest successful request time.
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
    try:
        if not wait_for_port(port):
            lines = []
            if os.path.exists(error_log):
                with open(error_log, errors="replace") as fh:
                    lines = fh.read().strip().splitlines()
            detail = lines[-1] if lines else "no log"
            return False, None, "xray did not listen (%s)" % detail

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
                    # 严格口径(2026-10-01): 任一样本失败即整节点淘汰 —— 排名时
                    # "2次里过1次"的节点实测会带着 Google 拉黑问题混进前列
                    # (leastPing 恰好优先选它)。误杀代价低(候选池大), 宁严勿松。
                    return False, None, "HTTP %s (%s)" % (code, url.split("/")[2])
            if url_best is None:
                return False, None, "HTTP %s (%s)" % (last_code, url.split("/")[2])
            best = url_best if best is None else max(best, url_best)
        return True, best, "双204 %.2fs" % best
    except subprocess.TimeoutExpired:
        return False, None, "probe timeout"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def probe_node(node, timeout, attempts, samples):
    """Try a node up to `attempts` times; usable if any attempt returns 204.

    The reported latency is the fastest successful request across all attempts.
    """
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
                    "outbound": outbound}
        last_reason = reason
    return {"node": node, "ok": False, "reason": last_reason, "latency": None,
            "elapsed": round(elapsed, 2), "outbound": outbound}


def probe_all(nodes, workers, timeout, attempts, samples=DEFAULT_SAMPLES):
    """Probe every node concurrently, keeping the input order of the results."""
    results = [None] * len(nodes)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_node, node, timeout, attempts, samples): idx
                   for idx, node in enumerate(nodes)}
        for future in concurrent.futures.as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()
            done += 1
            row = results[idx]
            speed = "%5.2fs" % row["latency"] if row["ok"] else "  -  "
            print("  [%3d/%3d] %-4s %-17s %-4s %s  %s" % (
                done, len(nodes), "OK" if row["ok"] else "FAIL",
                row["node"]["address"][:17], geo_tag(row["node"]), speed,
                row["reason"],
            ), file=sys.stderr, flush=True)
    return results


def rank_usable(results, keep):
    """Return (kept, dropped) — usable nodes sorted by latency, trimmed to `keep`."""
    usable = sorted((r for r in results if r["ok"]),
                    key=lambda r: (r["latency"], r["node"]["address"]))
    if keep and len(usable) > keep:
        return usable[:keep], usable[keep:]
    return usable, []


def refine_ranking(rows, workers, timeout, samples):
    """Re-measure usable nodes at lower concurrency so the top-N cut is fair.

    The first pass runs at high concurrency, which inflates latency unevenly
    (nodes recovered by the low-concurrency retest look artificially fast
    compared to the rest). Before deciding who gets dropped we measure all
    candidates again on equal terms; a node that fails this second measurement
    simply keeps its earlier — working — latency.
    """
    fresh = probe_all([r["node"] for r in rows], workers, timeout, 1, samples)
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
# main
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="测试本地 node.txt 里的节点，测速排名后只保留最快的 N 个到 Xray 配置。")
    parser.add_argument("-n", "--node-file", default=DEFAULT_NODE_FILE,
                        help="订阅文件，默认 %s" % DEFAULT_NODE_FILE)
    parser.add_argument("-s", "--subscribe", action="append", default=[],
                        metavar="URL",
                        help="额外订阅 URL（可重复）；node.txt 里的 http(s):// 行与"
                             "脚本旁的 subscriptions.txt（每行一个 URL，# 注释）也会"
                             "被当作订阅拉取")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG,
                        help="Xray 配置文件，默认 %s" % DEFAULT_CONFIG)
    parser.add_argument("-w", "--workers", type=int, default=24, help="并发测试数，默认 24")
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="单个节点探测超时秒数，默认 8")
    parser.add_argument("-a", "--attempts", type=int, default=2, help="每个节点尝试次数，默认 2")
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES,
                        help="测速取样次数（取最快一次），默认 %d" % DEFAULT_SAMPLES)
    parser.add_argument("-k", "--keep", type=int, default=DEFAULT_KEEP,
                        help="只保留最快的前 N 个节点，0 = 不限制，默认 %d" % DEFAULT_KEEP)
    parser.add_argument("--max-nodes", type=int, default=None,
                        help=argparse.SUPPRESS)  # 旧参数名，等价于 --keep
    parser.add_argument("--keep-manual", dest="adopt", action="store_false",
                        help="不接管手写的 proxy_* 出站（默认接管：和 node.txt 节点一起"
                             "测速，快则留、慢则删）")
    parser.add_argument("--append", action="store_true",
                        help="追加模式：保留本次运行前已有的脚本节点（默认替换为最新最快的一批）")
    parser.add_argument("--no-rerank", dest="rerank", action="store_false",
                        help="关闭“保留前的低并发统一复测”（默认开启：可用数超过保留数时会复测一轮）")
    parser.add_argument("--no-retest", dest="retest", action="store_false",
                        help="关闭“失败节点串行复测”（默认开启，避免并发误判）")
    parser.add_argument("--retest-timeout", type=float, default=15.0,
                        help="复测时的单节点超时秒数，默认 15")
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


def main(argv=None):
    args = parse_args(argv)
    if not os.path.exists(args.node_file):
        raise SystemExit("找不到订阅文件: %s" % args.node_file)

    with open(args.node_file, encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.readlines()
    total_lines = sum(1 for line in raw_lines if line.strip())

    # ---- 订阅 URL 汇总: -s 参数 + subscriptions.txt + node.txt 里的 http(s) 行 ----
    sub_urls = list(args.subscribe)
    if os.path.exists(DEFAULT_SUB_FILE):
        with open(DEFAULT_SUB_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    sub_urls.append(line)
    sub_urls += [line.strip() for line in raw_lines
                 if re.match(r"https?://", line.strip())]
    sub_urls = list(dict.fromkeys(sub_urls))     # 去重保序

    nodes, skipped = load_nodes_lines(
        [line for line in raw_lines if not re.match(r"https?://", line.strip())])

    # ---- 拉取并解析全部订阅 ----
    sub_nodes, sub_report = [], []
    if sub_urls:
        print("订阅源 %d 个（-s / subscriptions.txt / node.txt 内 URL）..." % len(sub_urls))
    for url in sub_urls:
        text = fetch_subscription(url)
        if text is None:
            print("  ⚠️ 拉取失败: %s" % url)
            sub_report.append({"url": url, "ok": False, "nodes": 0})
            continue
        parsed = parse_subscription(text)
        good = []
        for node in parsed:
            reason = node_supported(node)
            if reason:
                skipped.append((reason, node["label"] or url))
                continue
            good.append(node)
        sub_report.append({"url": url, "ok": True, "nodes": len(good),
                           "bytes": len(text)})
        print("  ✔ %s: %d 个节点" % (url, len(good)))
        sub_nodes.extend(good)

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

    pool = list(nodes)
    known = {node_key(node) for node in pool}
    sub_new = 0
    for node in sub_nodes:
        key = node_key(node)
        if key in known:
            continue
        known.add(key)
        pool.append(node)
        sub_new += 1
    adopted_new = []
    for tag, node in adopted:
        if node_key(node) in known:
            continue
        known.add(node_key(node))
        pool.append(node)
        adopted_new.append(tag)

    print("节点文件: %s" % args.node_file)
    print("总行数 %d，本地节点 %d，订阅新增 %d，去重后待测 %d，不支持/跳过 %d"
          % (total_lines, len(nodes), sub_new, len(pool), len(skipped)))
    for reason, label in skipped:
        print("  跳过: %-45s %s" % (reason, label))
    if adopted:
        print("接管配置里手写的 %d 个 proxy 出站一起测速（快则留、慢则删）: %s"
              % (len(adopted), ", ".join(tag for tag, _ in adopted)))
    if untouched_manual:
        print("保留（无法识别参数，未参与测速）: %s" % ", ".join(untouched_manual))
    if adopted_new:
        print("其中 %d 个是 node.txt 里没有的，已加入候选池" % len(adopted_new))
    print("候选池共 %d 个节点" % len(pool))

    print("开始测速（每个节点起一个临时 Xray + SOCKS 探测 %s，取样 %d 次）..."
          % (PROBE_URL, max(1, args.samples)))
    started = time.time()
    results = probe_all(pool, args.workers, args.timeout, args.attempts,
                        args.samples)

    failed_idx = [i for i, row in enumerate(results) if not row["ok"]]
    if failed_idx and args.retest:
        print("对 %d 个失败节点做低并发复测（timeout=%ss，避免并发误判）..."
              % (len(failed_idx), args.retest_timeout))
        retest = probe_all([pool[i] for i in failed_idx],
                           max(1, args.workers // 6), args.retest_timeout, 1,
                           max(1, args.samples))
        for idx, row in zip(failed_idx, retest):
            if row["ok"]:
                row["reason"] += " (复测通过)"
                results[idx] = row

    usable_rows = [r for r in results if r["ok"]]
    reranked = 0
    if args.rerank and args.keep and len(usable_rows) > args.keep:
        lane = max(4, args.workers // 3)
        print("可用 %d > 保留 %d，对全部可用节点做一轮低并发统一复测"
              "（并发 %d，timeout %ss），让“最快 100”的取舍公平..." %
              (len(usable_rows), args.keep, lane, args.retest_timeout))
        reranked = refine_ranking(usable_rows, lane, args.retest_timeout,
                                  max(1, args.samples))

    kept, dropped_slow = rank_usable(results, args.keep)
    working = [r["node"] for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    print("测速完成，用时 %.1fs：可用 %d / %d"
          % (time.time() - started, len(working), len(pool)))
    print("保留最快 %d 个%s"
          % (len(kept), "" if not dropped_slow
             else "（淘汰速度较慢的 %d 个）" % len(dropped_slow)))
    for row in kept[:10]:
        print("  %5.2fs  %-17s %-4s %s" % (
            row["latency"], row["node"]["address"][:17], geo_tag(row["node"]),
            row["node"]["scheme"]))

    regions = {}
    for row in kept:
        regions[geo_tag(row["node"])] = regions.get(geo_tag(row["node"]), 0) + 1
    print("保留节点地区分布: %s" % (
        ", ".join("%s=%d" % kv for kv in sorted(regions.items(), key=lambda kv: -kv[1]))))

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
                max(1, args.samples))):
            if not row["ok"]:
                pruned_tags.append(outbound.get("tag", "?"))
                outbounds.remove(outbound)
        print("失效出站 %d 个: %s" % (len(pruned_tags), ", ".join(pruned_tags) or "-"))

    added, duplicates = merge_working(config, [row["node"] for row in kept])

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "node_file": args.node_file,
        "config": args.config,
        "total_lines": total_lines,
        "candidates": len(nodes),
        "subscription_sources": sub_report,
        "pool": len(pool),
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
    }

    if args.dry_run:
        print("\n[dry-run] 候选 %d，可用 %d，保留最快 %d，移除脚本/手写出站 %d，将写入 %d（配置未改动）"
              % (len(pool), len(working), len(kept), len(removed), len(added)))
        print("正式应用请运行: %s" % os.path.join(SCRIPT_DIR, "apply.sh"))
        write_report(args.report, report)
        return 0

    report["backup"] = write_config(args.config, config)
    report["applied"] = True
    state_backup = ""
    if args.state and os.path.exists(args.state):
        state_backup = "%s.bak.%s" % (args.state, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(args.state, state_backup)
    save_state({
        "updated_at": report["generated_at"],
        "node_file": args.node_file,
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
        return 1
    report["post_write_check"] = True

    if args.restart:
        report["restarted"] = restart_service()

    write_report(args.report, report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
