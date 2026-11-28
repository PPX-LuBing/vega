#!/bin/sh
# 生成 extra_config：把 AI / Google 域名分流到台湾落地（chain-tw）。
#
# 用法:
#   gen-config.sh <落地参数文件> [清单目录]
#
# 落地参数文件格式（键=值，见 README）:
#   TW_SERVER=tw.luckybyte.de5.net
#   TW_PORT=50360
#   TW_METHOD=2022-blake3-aes-128-gcm
#   TW_PASSWORD=<服务端PSK>:<用户PSK>
#
# 输出: stdout（JSON）。写法:
#   sh gen-config.sh /root/vega-tw-landing.env > /root/ai-tw.json
#
# 设计取舍:
#   - 清单里每个裸域名展开成「裸域 + .裸域」两条，共 136 条 domain_suffix。
#     不用一条 .googleapis.com 通配，是为了避免把 Google Cloud / Firebase /
#     Drive 全导去家宽（台湾只有 512MB 内存）。
#   - 密码只从参数文件读，不硬编码、不进仓库。
set -eu

usage() {
    cat >&2 <<'EOF'
Usage: gen-config.sh <落地参数文件> [清单目录]

  落地参数文件需包含 TW_SERVER / TW_PORT / TW_METHOD / TW_PASSWORD。
  清单目录默认是脚本所在目录。
EOF
    exit 2
}

[ "$#" -ge 1 ] || usage
env_file=$1
[ -r "$env_file" ] || { echo "读不到参数文件: $env_file" >&2; exit 1; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
list_dir=${2:-$script_dir}

# 只按「键=值」逐行读取，不 source。
# 生产密码是 base64（含 + / =），但用 source 读会受 shell 引号/反斜杠干扰，
# 密码里一旦出现 " 或 \ 就会语法错。逐行解析没有这个问题。
read_env() {
    key=$1
    # 取第一条匹配的键，去掉首尾空白
    sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "$env_file" |
        head -1 | sed -e 's/[[:space:]]*$//'
}

TW_SERVER=$(read_env TW_SERVER)
TW_PORT=$(read_env TW_PORT)
TW_METHOD=$(read_env TW_METHOD)
TW_PASSWORD=$(read_env TW_PASSWORD)

for pair in "TW_SERVER:$TW_SERVER" "TW_PORT:$TW_PORT" \
    "TW_METHOD:$TW_METHOD" "TW_PASSWORD:$TW_PASSWORD"; do
    name=${pair%%:*}
    value=${pair#*:}
    [ -n "$value" ] || { echo "参数文件缺少 $name" >&2; exit 1; }
done

# 端口必须是纯数字，否则生成的 JSON 会坏。
case $TW_PORT in
*[!0-9]* | '')
    echo "TW_PORT 必须是数字，当前是: $TW_PORT" >&2
    exit 1
    ;;
esac

# JSON 字符串转义：先转义反斜杠，再转义双引号。
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

collect_domains() {
    for list in "$list_dir/ai-domains.txt" "$list_dir/google-domains.txt"; do
        [ -r "$list" ] || { echo "缺清单文件: $list" >&2; exit 1; }
        sed -e 's/#.*//' -e 's/[[:space:]]//g' "$list" | sed -e '/^$/d'
    done
}

# 去重（保持首次出现顺序）。同一域名可能同时出现在两个清单里。
domains=$(collect_domains | awk '!seen[$0]++')

count=$(printf '%s\n' "$domains" | sed -e '/^$/d' | wc -l | tr -d ' ')
[ "$count" -gt 0 ] || { echo "域名清单是空的" >&2; exit 1; }

cat <<EOF
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "chain-tw",
      "server": "$(json_escape "$TW_SERVER")",
      "server_port": ${TW_PORT},
      "method": "$(json_escape "$TW_METHOD")",
      "password": "$(json_escape "$TW_PASSWORD")"
    }
  ],
  "route": {
    "rules": [
      {
        "domain_suffix": [
EOF

# 每个域名输出两条：裸域 + .裸域。用 awk 控制逗号，避免首尾多余逗号。
printf '%s\n' "$domains" | awk '
NF == 0 { next }
{
    if (!first) {
        printf "          \"%s\",\n          \".%s\"", $0, $0
        first = 1
    } else {
        printf ",\n          \"%s\",\n          \".%s\"", $0, $0
    }
}
'

cat <<'EOF'

        ],
        "action": "route",
        "outbound": "chain-tw"
      }
    ]
  }
}
EOF
