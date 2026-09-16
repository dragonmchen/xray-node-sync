#!/usr/bin/env bash
# 正式应用：测速本地 node.txt，只保留最快的 100 个节点写入 Xray 配置并重启服务。
#
#   ./apply.sh                 # 默认保留最快 100 个
#   ./apply.sh --keep 50       # 只保留最快 50 个
#   ./apply.sh --no-restart    # 只写配置，不动服务
set -euo pipefail
cd "$(dirname "$0")"

restart=(--restart)
for arg in "$@"; do
  [ "$arg" = "--no-restart" ] && restart=()
done
filtered=()
for arg in "$@"; do
  [ "$arg" = "--no-restart" ] || filtered+=("$arg")
done

exec python3 sync_nodes.py "${restart[@]}" ${filtered[@]+"${filtered[@]}"}