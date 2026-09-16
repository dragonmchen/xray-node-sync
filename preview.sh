#!/usr/bin/env bash
# 预览：测速本地 node.txt，按速度排名，只显示结果，绝不修改 Xray 配置。
set -euo pipefail
cd "$(dirname "$0")"
exec python3 sync_nodes.py --dry-run "$@"