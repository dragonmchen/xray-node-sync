# xray-node-sync

从订阅源拉取节点，**xray 与 sing-box 各自独立**测速，按延迟排名后各自**只保留最快的
前 50 个**写进对应配置（xray 写 `/etc/xray/config.json`，sing-box 写
`/etc/sing-box/config.json`）。

```bash
cd ~/coding/python/xray-node-sync
./preview.sh     # 预览：两侧各自测速 + 排名，不改配置
./apply.sh       # 正式应用：各写入最快 50 个 + 重启 xray + 部署 sing-box
```

> **2026-10-12 起不再读取 `node.txt`**（需求 1）。数据来源只有 `subscriptions.txt`
> 与命令行 `-s`。`-n/--node-file` 参数保留仅为兼容，已不参与取数。

## 为什么 xray 和 sing-box 分开测（需求 3）

两个核心支持的协议 / 传输并不完全一致，所以**各自用自己的核心真测一遍、各自保留前 50**：

| 协议 / 传输 | xray | sing-box |
| --- | --- | --- |
| vless / vmess / trojan / ss / hysteria2（ws / tcp / tls / reality） | ✅ | ✅ |
| xhttp | ✅（仅 xray） | ❌（sing-box 无此出站） |
| tuic | ❌（xray 无此出站） | ✅（仅 sing-box） |
| grpc / httpupgrade | ❌（xray 侧不建模） | ✅ |

候选池按“哪个核心能真跑”分区（`partition_pool`）：`tuic` 只进 sing-box、`xhttp` 只进
xray，两边都支持的各自都进、各自测速排名。任一侧健康节点不够时由 `--watch` 守护模式
补量（见下文「动态监测与自愈」）。

## 节点来源（自动合并去重）

* `subscriptions.txt`（脚本目录下，每行一个订阅 URL，`#` 注释）；
* 命令行 `-s/--subscribe URL`（可重复）。

订阅支持三种格式，自动识别：纯 URI 列表 / base64 整块 / Clash `proxies:` YAML。
拉取是**并发**的，且内容相同的镜像文件只解析一次（按 SHA256 去重，日志里记为 `=`）。
拉取顺序：先直连，失败自动走本机 Xray SOCKS（`socks5h://127.0.0.1:54321`）再试一次
（GitHub raw 等直连不通时靠它兜底）。协议支持 `vless` / `trojan` / `vmess`
（base64 JSON 链接与 Clash 条目）/ `ss`（SIP002 及 legacy 整块 base64）/ `hysteria2`；
`tuic` 只参与 sing-box 侧。

`subscriptions.txt` 还支持 **`datepattern:` 模板行**：运行时展开成「**前天 / 昨天 /
今天**」三天 × `N=0..5` 共 18 个 URL（2026-10-12 起，由原来的“3 天前..明天”改为
就近三天）。占位符 `{year}` `{month}` `{day}`（补零）、`{ymd}`（YYYYMMDD）、`{n}`。例如：

```
datepattern:https://node.v2rayu.cc/uploads/{year}/{month}/{n}-{ymd}.txt
```

## 它是怎么判断“可用”和“快”的

不是只看端口能不能连通，而是**真跑一遍**：

0. **分区**：候选池按“哪个核心能真跑”拆成 xray 侧 / sing-box 侧（见上表），
   两侧各自独立跑下面的完整流程（需求 3）；
1. **TCP 预扫描**（`--no-tcpscan` 关闭）：默认 500 线程（`--prescan-workers`）对全部唯一
   (地址, 端口) 做 1.5 秒裸 TCP 连接（`--prescan-timeout`），连不上的死端点直接淘汰、
   不再为它们起临时核心（hysteria2 / tuic 是 QUIC/UDP，豁免预扫描）。扫描结果缓存在
   进程内，xray / sing-box 两侧候选池共享同一批端点、第二次直接命中缓存不再重扫；
   顺带记录每个端点的**握手耗时**——若指定 `--max-candidates N`（默认 0=不限），
   则按握手延迟升序只取前 N 个可扫描候选进入后续测速，给测速预算封顶；
2. 解析每个节点的 URI / Clash 条目（地址、端口、密码、SNI、WS path/Host、alpn、fp、reality pbk/sid…）；
   按「地址+端口+密码+SNI+传输+路径+Host+alpn+指纹」去重；
3. 为每个候选节点起一个**临时核心实例**——xray 侧用 `probe_once`、sing-box 侧用
   `probe_once_singbox`（本地 SOCKS inbound → 该节点出站），然后
   `curl --socks5-hostname 127.0.0.1:<port> https://www.gstatic.com/generate_204`，
   并且用 `time_total` **计时**（每个节点取样 2 次，取最快一次）。
   **两段测速（`--screen-timeout`，默认开）**：第一段先用短超时（默认 4s）+ 1 次尝试
   快速筛掉绝大多数死节点（死节点不再等满 `--timeout×attempts`），只有存活者进第二段
   用完整参数（`--timeout`/`--attempts`/`--samples`）精确测延迟。候选池沿用预扫描的
   握手延迟升序（不再洗牌），先测最有希望的；`--screen-timeout 0` 关闭两段、退回单段全量测量；
4. 返回 `204` 才算可用（走不通、密码错、SNI 错、被墙都拿不到 204）。
   **双站点严格口径（2026-10-01）**：探测 `gstatic` + `google.com` 两个 `generate_204`，
   **所有采样全部 204** 才算可用、计时取两站点较慢者。起因：实测有"假活"节点对
   gstatic 秒回 204（0.07s）却黑掉一切真实流量（劫持/白名单型），且 leastPing 恰好
   优先选它 → 真实站点全超时；另有节点只要求"2 次过 1 次"时带着 Google 拉黑混进
   前列。误杀代价低（候选池大），宁严勿松。配套：`/etc/xray/config.json` 的
   observatory `probeUrl` 也改为 google 204（脚本不碰该字段，改动持久），让
   leastPing 均衡器实时避开 Google 不通的节点；
5. 主轮次高并发跑完后，对失败节点再做一次**低并发复测**（默认 timeout 15s），
   避免并发导致的误判（例如负载高时握手超时）；复测只针对真正的“软失败”，
   跳过 HTTP 000 / sing-box 结构性无法承载的节点，也**不复测提前结束时根本没测过的节点**——
   把“未测量”当成失败再低并发复测，等于把提前结束省下的时间又还回去；
6. **按延迟升序排名，各自只保留最快的前 N 个**——xray 侧 `--keep`（默认 50）、
   sing-box 侧 `--sb-max`（默认 50），更慢的直接不写入；
   **提前结束**（`--no-early-stop` 关闭）：可用数已达到**早停目标**
   （`--early-stop-target`，默认 30，取 `min(keep, 目标)`）、且这些可用节点的
   **延迟中位数 ≤ 1.5s**（`--early-stop-fast` 可调）时，剩余未开测的节点直接取消——
   “找到够用且够快的就停”，不必把几万个慢节点测完。候选池按握手延迟升序先测
   最有希望的，早停更容易在前段命中；
   当可用节点多于保留数时，会先对**全部可用节点**做一轮低并发（`workers/3`）
   统一复测再排名 —— 首轮是高并发跑的，延迟会被不均匀地抬高（复测救回的节点
   更是显得特别快），这一轮让“谁进前 50”的取舍尽量公平（`--no-rerank` 可关）；
7. xray 侧写入的 tag 统一为 `proxy_<地区>_<IP下划线化>`，**按速度从快到慢**插在
   `direct`/`blocked` 之前 —— 前缀 `proxy` 才能被配置里 `fastest` 均衡器
   （`leastPing`）选中（实际选谁由均衡器按实时 ping 决定，顺序只是方便你查看）；
   sing-box 侧 tag 为 `sb1`、`sb2`…，交给 `urltest` 运行时自动选路；
8. 写入前先校验（xray 用 `xray run -test`、sing-box 用 `sing-box check`）；校验不通过
   直接退出、**不落盘**；写入前自动备份 `config.json.bak.<时间戳>`；xray **写入后再对
   落盘文件校验一次**，万一失败会自动回滚配置和 `state.json` 到写入前状态并以非 0 退出。

协议支持取决于你机器上的核心二进制：当前 `xray 26.3.27` 自带 `hysteria` 出站、
`sing-box 1.14` 支持 `tuic`，所以 `hysteria2://`（两边）与 `tuic://`（sing-box）
照常参与各自测速排名（QUIC 抖动大，慢于前 50 名时同样会被淘汰）。若换了不带对应
出站的二进制，对应节点会列为“跳过 / sing-box 无法承载”。

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

## sing-box 侧（2026-10-12 起：与 xray 一样独立测速）

sing-box 现在和 xray 一样**用自己的核心真测一遍**（`probe_once_singbox` 起临时
sing-box 打双 204），按延迟取前 `--sb-max` 个（默认 50）：

* **协议分工**：`tuic` 只有 sing-box 能跑（xray 无此出站），归 sing-box 独占；
  `hysteria2` 两边都测；`vless`/`vmess`/`trojan`/`ss` 两边各自测速；
* **不再有“未验证填充”**：进 sing-box 的节点都过了 sing-box 自己的 204 验证（tuic
  若本机 UDP 不通会被判失败、不进配置）；
* **via-xray**：整台 xray（socks `127.0.0.1:54321`）作为 urltest 的一个成员，
  `final=auto` 在全部成员里自动选路；
* **分流**：CN 域名/IP（geosite-cn / geoip-cn 规则集，自动下载到
  `/var/lib/sing-box/`）与私有地址直连，其余走代理；
* 配置写 `/etc/sing-box/config.json`，先过 `sing-box check`，失败保留旧配置；
  链接里非法的 uTLS 指纹（如 `fp=unsafe`）会被忽略；
* `--singbox-only`：只跑 sing-box 这一侧（跳过 xray）；`--no-singbox`：本次运行不动 sing-box。

## 动态监测与自愈（需求 4）

**运行时的“选快汰死”由两个核心自己完成**，脚本不干预：

* xray：`observatory`（每 5m 探测，`probeUrl=google 204`）+ `fastest` 均衡器
  （`leastPing`）实时挑延迟最低、且 Google 能通的 `proxy_*` 出站；
* sing-box：`auto`（`urltest`）每 3 分钟体检所有成员，只把流量给当前最快的那个，
  挂掉的成员自动不承载。

**“见底自动补量”由 `--watch` 守护模式完成**：周期性体检两侧**已部署**的节点
（各自核心单次探测，数健康数），一旦任一核心健康数低于 `--watch-min`（默认 30），
就自动重跑一次完整同步，把最新最快的一批补上去，从而维持可用节点数量。

```bash
python3 sync_nodes.py --watch                  # 守护模式（前台循环）
python3 sync_nodes.py --watch --watch-min 30 --watch-interval 300
```

可作为 systemd 服务常驻（自建一个 `oneshot` 单元或 `Restart=always` 的
`--watch` 单元即可长期自愈）。

## 每次运行都是“替换”，不是“累加”

脚本只管理**自己写进去的**节点（`state.json` 记录 tag，另以 `proxy_XX_` 前缀兜底识别）：

* 每次运行**先移除上一批脚本节点，再写入本次最快的一批** → 配置不会无限膨胀；
* **手写的 proxy 出站也会被接管测速**（“快则留、慢则删”，和订阅节点一视同仁）：
  能从出站反推出参数的会被加入候选池一起排名，速度够快就以**统一格式重写**保留，
  速度不够的淘汰；无法反推参数的（如缺字段的 vmess）原样保留并在输出里说明；
* `direct`、`blocked`、`routing`、`balancers`、`observatory`、`inbounds`、`log`
  **一律不动**；
* 想要旧行为（保留已配置的脚本节点、只做追加）用 `--append`。

## 局域网使用（2026-10-03 起：统一入口是 sing-box）

2026-10-03 装了 sing-box 前端后，入口统一为 **10808（socks5）/ 10809（http/https）**，
xray 的 54321 已收回只监听 `127.0.0.1`（变成内部后端，脚本拉订阅兜底仍走它）。
局域网设备（浏览器/系统代理/手机）填：

```
socks5://192.168.5.15:10808        # 或 http://192.168.5.15:10809
socks5://192.168.64.2:10808        # 按设备所在网段选（eth0 / lima0）
```

sing-box 的两个 inbound 都监听 `::`（所有地址），流量先过 CN 直连分流
（geosite-cn/geoip-cn），再由 `urltest` 在自己的 50 节点池 + via-xray 之间自动
选路——即局域网设备也自动享受 sing-box 的池子。

> 安全提示：sing-box 的入站是**无认证**的，同网段任何人都能拿它当出口。若在意，
> 可在 sing-box inbound 里加 `users`（socks 用户名密码），或用防火墙只放行自己的设备 IP。

## 用法

```bash
cd ~/coding/python/xray-node-sync

./preview.sh                     # = python3 sync_nodes.py --dry-run
./apply.sh                       # = python3 sync_nodes.py --restart
./apply.sh --keep 50 --sb-max 50 # 两侧各自只保留最快的 50 个（默认值）
./apply.sh --no-restart          # 写配置但不动服务
./preview.sh -w 8                # 低并发测速，排名更准（更慢）
./preview.sh -k 0                # xray 侧不限制数量，只看全部可用节点排名
./apply.sh --singbox-only        # 只刷新 sing-box 这一侧
./apply.sh --no-singbox          # 本次只更新 xray
python3 sync_nodes.py --watch    # 守护模式：见底自动重同步（需求 4）
```

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-c, --config` | `/etc/xray/config.json` | xray 目标配置 |
| `-s, --subscribe URL` | - | 额外订阅 URL（可重复）；`subscriptions.txt` 也会被拉取 |
| `-w, --workers` | 自适应（CPU×8，受可用内存护栏，区间 16~192；本机当前 43） | 并发探测数。测速以 IO 等待为主、CPU 占用低，故默认远超核数；越小测速越准、越慢。中断（SIGINT/SIGTERM）时会自动回收所有临时核心进程，不会泄漏 |
| `-t, --timeout` | 8 | 单节点探测超时（秒，两段测速第二段用） |
| `-a, --attempts` | 2 | 每个节点尝试次数 |
| `--samples` | 2 | 测速取样次数（取最快一次） |
| `--screen-timeout` | 4 | 两段测速第一段(快速筛选)超时（秒）：死节点在此快速淘汰，只有存活者进第二段精确测量；0=关闭两段测速 |
| `-k, --keep` | 50 | **xray 侧**只保留最快的前 N 个（0=不限） |
| `--sb-max` | 50 | **sing-box 侧**最多保留多少个节点出站（另加 via-xray） |
| `--no-rerank` | 关 | 关闭保留前的低并发统一复测（可用数>保留数时默认开启） |
| `--append` | 关 | 追加模式，不替换上一批脚本节点 |
| `--retest-timeout` | 15 | 失败节点复测超时（秒） |
| `--no-retest` | 关 | 关闭失败复测 |
| `--no-tcpscan` | 关 | 关闭 TCP 预扫描（默认开启，死端点不起临时核心；hysteria2/tuic 豁免） |
| `--prescan-workers` | 500 | TCP 预扫描并发数（裸 TCP 连接 IO 密集，可远高于测速并发；两池共享扫描缓存） |
| `--prescan-timeout` | 1.5 | TCP 预扫描单端点握手超时（秒；正常握手 200–400ms） |
| `--max-candidates` | 0 | TCP 预扫描后按握手延迟升序只取前 N 个可扫描候选进入测速；0=不限（hysteria2/tuic 豁免不受限） |
| `--no-early-stop` | 关 | 关闭提前结束（默认开启：可用 ≥ 早停目标 且延迟中位数 ≤ 1.5s 即停止剩余测速） |
| `--early-stop-fast` | 1.5 | 提前结束的“够快”标准（可用节点延迟中位数阈值，秒） |
| `--early-stop-target` | 30 | 提前结束的目标可用节点数（与 `--keep` 取 min；找到够用的就停，不必凑满保留数） |
| `--no-singbox` | 关 | 本次运行不动 sing-box，只更新 xray |
| `--singbox-only` | 关 | 只用 sing-box 核心独立测速并刷新 sing-box，跳过 xray |
| `--watch` | 关 | 守护模式：循环体检已部署节点，健康数低于阈值自动重跑完整同步 |
| `--watch-interval` | 300 | 守护模式每次体检间隔（秒） |
| `--watch-min` | 30 | 守护模式：任一核心健康节点少于此值就触发重同步 |
| `--watch-health-timeout` | 6 | 守护模式单节点体检超时（秒） |
| `--prune-dead` | 关 | 额外重测并删除**非脚本管理**的失效出站 |
| `--dry-run` | 关 | 只测不写（=`preview.sh`） |
| `--restart` | 关 | 写完后重启/启动 xray.service（=`apply.sh`） |
| `--state` | 同目录 `state.json` | 记录脚本写入的 tag（下次运行据此替换） |
| `--report` | `last_run.json` | JSON 报告路径，留空则不写 |

## 输出

* 终端：分区统计、两侧各自逐节点 OK/FAIL + 延迟、各自最快 10 个、地区分布、汇总；
* `last_run.json`：xray 侧可用/失败/跳过清单、`kept`/`dropped_slow`、`removed_managed`、
  `added`、备份路径，以及 `singbox` 子对象（sing-box 侧 pool/usable/kept/kept_nodes）；
* `state.json`：xray 侧脚本管理的 tag 与各自延迟，供下次运行做替换。

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
