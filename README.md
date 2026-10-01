# xray-node-sync

把节点候选（本地 `node.txt` + 订阅链接）里的节点**逐个真测速度**，
按延迟排名后**只保留最快的 N 个**（默认 100）写进 Xray 的 `config.json`。

```bash
cd ~/coding/python/xray-node-sync
./preview.sh     # 预览：测速 + 排名，不改配置
./apply.sh       # 正式应用：写入最快 100 个 + 重启 xray
```

## 节点来源（自动合并去重）

* 本地 `node.txt`（每行一个分享链接；其中的 `http(s)://` 行会被当作订阅 URL 拉取）；
* `subscriptions.txt`（脚本目录下，每行一个订阅 URL，`#` 注释）——当前维护的 5 个免费订阅都在这里；
* 命令行 `-s/--subscribe URL`（可重复）。

订阅支持三种格式，自动识别：纯 URI 列表 / base64 整块 / Clash `proxies:` YAML。
拉取顺序：先直连，失败自动走本机 Xray SOCKS（`socks5h://127.0.0.1:54321`）再试一次
（GitHub raw 等直连不通时靠它兜底）。协议支持 `vless` / `trojan` / `vmess`
（base64 JSON 链接与 Clash 条目）/ `ss`（SIP002 及 legacy 整块 base64）/ `hysteria2`。

## 它是怎么判断“可用”和“快”的

不是只看端口能不能连通，而是**真跑一遍**：

1. 解析每个节点的 URI / Clash 条目（地址、端口、密码、SNI、WS path/Host、alpn、fp、reality pbk/sid…）；
2. 按「地址+端口+密码+SNI+传输+路径+Host+alpn+指纹」去重；
3. 为每个候选节点起一个**临时 Xray 实例**（本地 SOCKS inbound → 该节点 outbound），
   然后 `curl --socks5-hostname 127.0.0.1:<port> https://www.gstatic.com/generate_204`，
   并且用 `time_total` **计时**（每个节点取样 2 次，取最快一次）；
4. 返回 `204` 才算可用（走不通、密码错、SNI 错、被墙都拿不到 204）。
   **双站点严格口径（2026-10-01）**：探测 `gstatic` + `google.com` 两个 `generate_204`，
   **所有采样全部 204** 才算可用、计时取两站点较慢者。起因：实测有"假活"节点对
   gstatic 秒回 204（0.07s）却黑掉一切真实流量（劫持/白名单型），且 leastPing 恰好
   优先选它 → 真实站点全超时；另有节点只要求"2 次过 1 次"时带着 Google 拉黑混进
   前列。误杀代价低（候选池大），宁严勿松。配套：`/etc/xray/config.json` 的
   observatory `probeUrl` 也改为 google 204（脚本不碰该字段，改动持久），让
   leastPing 均衡器实时避开 Google 不通的节点；
5. 主轮次高并发跑完后，对失败节点再做一次**低并发复测**（默认 timeout 15s），
   避免并发导致的误判（例如负载高时握手超时）；
6. **按延迟升序排名，只保留最快的 `--keep` 个**（默认 100），更慢的直接不写入；
   当可用节点多于保留数时，会先对**全部可用节点**做一轮低并发（`workers/3`）
   统一复测再排名 —— 首轮是高并发跑的，延迟会被不均匀地抬高（复测救回的节点
   更是显得特别快），这一轮让“谁进前 100”的取舍尽量公平（`--no-rerank` 可关）；
7. 写入的 tag 统一为 `proxy_<地区>_<IP下划线化>`，**按速度从快到慢**插在
   `direct`/`blocked` 之前 —— 前缀 `proxy` 才能被配置里 `fastest` 均衡器
   （`leastPing`）选中（实际选谁由均衡器按实时 ping 决定，顺序只是方便你查看）；
8. 写入前先用 `xray run -test` 校验；校验不通过直接退出、**不落盘**；写入前自动备份
   `config.json.bak.<时间戳>`；**写入后再对落盘文件校验一次**，万一失败会自动回滚
   配置和 `state.json` 到写入前状态并以非 0 退出。

协议支持取决于你机器上的 Xray 二进制：当前 `xray 26.3.27` 自带 `hysteria` 出站，
所以 `hysteria2://` 节点**照常参与测速排名**（实测它时快时慢——QUIC 抖动大，
慢于前 100 名时同样会被淘汰）。若换了不带该出站的二进制，对应节点会列为“跳过”。

### 支持的传输 / 加密（以及“畸形链接”的修复）

| 维度 | 支持的值 |
| --- | --- |
| 协议 | `trojan://`、`vless://`、`hysteria2://` |
| 传输 | `ws`、`tcp`、`xhttp`（`mode=stream-up` / `packet-up` 原样透传，`mode=auto` 归一为 Xray 默认值）、`hysteria` |
| 加密 | `security=tls`、`security=none`（明文，等同于不写）、`security=reality` |

* `security=reality` 用于 `vless`/`trojan` + `tcp`：从链接取 `pbk`（publicKey，
  必需）、`sid`（shortId）、`spx`（spiderX）、`sni`、`fp`，写进
  `realitySettings`；链接没写 `fp` 时用 `chrome`。缺 `pbk` 的 reality 节点会
  列为“跳过: reality without publicKey (pbk)”。
* **备注里塞参数的畸形链接**：有些订阅（例如 `oneclickvpnkeys` 频道）把
  `sni`/`fp`/`flow`/`sid`/`pbk` 全都塞在 `#` 后面的备注里，真正的 query 只写
  `security=reality&type=tcp`。脚本会从备注里**回收缺失参数**（只补空值、绝不
  覆盖已有值；备注里嵌了完整 `vless://…?…` 的也能取），因此这类节点同样能参与
  测速。猜错了不会污染配置——测速拿不到 `204`，节点直接被淘汰。
* 由于参数可能来自备注，地区 tag 的识别也跟着改进了：优先取备注尾部的
  `US_89`、`FR|1.9MB/s` 这类真实提示，而不会把频道名 `oneclickvpnkeys`
  读成 `ON`。
* 其他跳过原因还包括 `protocol not supported by Xray (…)`、
  `transport not supported here (…)`、`security not supported here (…)`。

## 每次运行都是“替换”，不是“累加”

脚本只管理**自己写进去的**节点（`state.json` 记录 tag，另以 `proxy_XX_` 前缀兜底识别）：

* 每次运行**先移除上一批脚本节点，再写入本次最快的一批** → 配置不会无限膨胀；
* **手写的 proxy 出站也会被接管测速**（“快则留、慢则删”，和订阅节点一视同仁）：
  能从出站反推出参数的会被加入候选池一起排名，速度够快就以**统一格式重写**保留，
  速度不够的淘汰；无法反推参数的（如缺字段的 vmess）原样保留并在输出里说明；
* `direct`、`blocked`、`routing`、`balancers`、`observatory`、`inbounds`、`log`
  **一律不动**；
* 想要旧行为（保留已配置的脚本节点、只做追加）用 `--append`。

## 局域网使用

你的 socks inbound 是故意监听所有地址的，脚本**不会**把它改回 `127.0.0.1`。
当前 `/etc/xray/config.json` 里的 inbound 已被显式写清楚（并顺手修掉一个坑）：

```json
"inbounds": [{
  "tag": "socks-in",
  "listen": "0.0.0.0",          // 显式声明：局域网可用
  "port": 54321,
  "protocol": "socks",
  "settings": {
    "auth": "noauth",
    "udp": true
    // "ip": "127.0.0.1"  ← 已删除：这是 socks 入站的合法字段，
    //   开启 UDP 时会把“到我这来发 UDP 的地址”告诉客户端，
    //   写死 127.0.0.1 会让局域网客户端的 UDP 流量发给自己而失败；
    //   默认（不写）会自动用客户端建立 TCP 连接时的本地 IP，本机有两个网卡
    //   （eth0 192.168.5.15 / lima0 192.168.64.2）时这也是唯一正确的做法。
  },
  "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}
}]
```

局域网设备（浏览器/系统代理/手机）填：`socks5://192.168.5.15:54321` 或
`socks5://192.168.64.2:54321`（按设备所在网段选）。上面代码块里的 `//` 注释只为说明，
JSON 本身不支持注释。

> 安全提示：这是**无认证** SOCKS（`auth: noauth` + `udp: true`），同网段任何人都能拿它
> 当出口。若在意，可把 `auth` 改成 `password` 并加 `users: [{"user": "...", "pass": "..."}]`，
> 或只放行你自己的设备 IP。

## 用法

```bash
cd ~/coding/python/xray-node-sync

./preview.sh                     # = python3 sync_nodes.py --dry-run
./apply.sh                       # = python3 sync_nodes.py --restart
./apply.sh --keep 50             # 只保留最快的 50 个
./apply.sh --no-restart          # 写配置但不动服务
./preview.sh -w 8                # 低并发测速，排名更准（更慢）
./preview.sh -k 0                # 不限制数量，只看全部可用节点排名
```

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-n, --node-file` | 脚本同目录 `node.txt` | 节点文件 |
| `-c, --config` | `/etc/xray/config.json` | 目标配置 |
| `-w, --workers` | 24 | 并发探测数（越小测速越准、越慢） |
| `-t, --timeout` | 8 | 单节点探测超时（秒） |
| `-a, --attempts` | 2 | 每个节点尝试次数 |
| `--samples` | 2 | 测速取样次数（取最快一次） |
| `-k, --keep` | 100 | 只保留最快的前 N 个（0=不限） |
| `--no-rerank` | 关 | 关闭保留前的低并发统一复测（可用数>保留数时默认开启） |
| `--append` | 关 | 追加模式，不替换上一批脚本节点 |
| `--retest-timeout` | 15 | 失败节点复测超时（秒） |
| `--no-retest` | 关 | 关闭失败复测 |
| `--prune-dead` | 关 | 额外重测并删除**非脚本管理**的失效出站 |
| `--dry-run` | 关 | 只测不写（=`preview.sh`） |
| `--restart` | 关 | 写完后重启/启动 xray.service（=`apply.sh`） |
| `--state` | 同目录 `state.json` | 记录脚本写入的 tag（下次运行据此替换） |
| `--report` | `last_run.json` | JSON 报告路径，留空则不写 |

## 输出

* 终端：逐节点 OK/FAIL + 延迟、最快 10 个、地区分布、最终汇总；
* `last_run.json`：可用/失败/跳过清单、`kept`（保留的节点及延迟）、
  `dropped_slow`（被淘汰的慢节点）、`removed_managed`、`added`、备份路径等；
* `state.json`：脚本管理的 tag 与各自延迟，供下次运行做替换。

## 自检

```bash
./check_udp.py 127.0.0.1 54321        # 验证 SOCKS5 UDP 中继（会打印它回给你的中继地址）
./check_udp.py 192.168.5.15 54321     # 从局域网口验证：中继地址应回 192.168.5.15
curl -s -o /dev/null -w '%{http_code}\n' --socks5-hostname 192.168.5.15:54321 \
     https://www.gstatic.com/generate_204        # 期望 204
curl -s --socks5-hostname 192.168.5.15:54321 https://api.ipify.org   # 期望不是你的家宽 IP
```

## 注意

* 脚本用 `sudo -n`（免密）读写 `/etc/xray/config.json`；若 sudo 需要密码，请先 `sudo -v`。
* 写配置后会**顺手收紧权限**：如果 `config.json` 对 group/other 可写（以前就是 `666`），
  会被改成 `0644`（只会收紧，不会放宽你已经设好的更严权限）——这文件里存着所有节点密码。
* 想拿别的配置文件做试验（不动线上配置、也不覆盖真实 `state.json`）：
  `python3 sync_nodes.py -n /tmp/x.txt -c /tmp/test.json --state /tmp/test_state.json --report /tmp/r.json`。
* `xray -test` 需要 `XRAY_LOCATION_ASSET=/etc/xray` 才能找到 `geosite.dat`/`geoip.dat`，
  脚本内部已自动设置。
* 服务状态：`systemctl status xray`。`apply.sh` 会在服务已 active 时重启，
  已 enabled 但未运行时启动它；两者都不是则不动，需先
  `sudo systemctl enable --now xray`。
* 启动日志里的 `The feature Trojan (with no Flow, etc.) is deprecated ...`
  **不是要升级**：你的 Xray 已是最新（26.3.27），这是官方刻意“弃用”明文 Trojan
  协议、引导用户迁移到 VLESS 的提示。节点协议由机场订阅决定，客户端无法更改，
  该警告无害、可无视（除非哪天 Xray 真的移除 Trojan 实现，那时机场节点会全体失效，
  换订阅或换 sing-box 即可）。
