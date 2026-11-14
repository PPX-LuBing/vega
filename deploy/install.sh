#!/bin/sh
# Vega 安装脚本：只铺文件和 systemd 单元，**不启动、不启用任何服务**。
#
# 布局与生产环境一致：
#   /opt/vega/bin/{vega,vega-panel,sb-stats}
#   /opt/vega/etc/                 配置（config.json 由 vega-panel apply 生成）
#   /var/lib/vega/{panel.db,acme,certs}
#   /etc/systemd/system/vega*.{service,timer}
#
# 用法:
#   install.sh CORE_BINARY PANEL_BINARY STATS_BINARY --domain <订阅域名> [--sub-port 8443]
#
# 环境变量 DESTDIR 可把文件铺到临时目录（打包/测试用，不碰宿主）。
set -eu

usage() {
    cat >&2 <<'EOF'
Usage: install.sh CORE_BINARY PANEL_BINARY STATS_BINARY --domain <domain> [--sub-port PORT]

  --domain   订阅服务对外域名，用于 ACME 证书和订阅链接（必填）
  --sub-port 订阅服务端口，默认 8443
EOF
    exit 2
}

[ "$#" -ge 3 ] || usage
core=$1
panel=$2
stats=$3
shift 3

domain=''
sub_port=8443
while [ "$#" -gt 0 ]; do
    case "$1" in
    --domain)
        [ "$#" -ge 2 ] || usage
        domain=$2
        shift 2
        ;;
    --sub-port)
        [ "$#" -ge 2 ] || usage
        sub_port=$2
        shift 2
        ;;
    -h | --help) usage ;;
    *)
        echo "未知参数: $1" >&2
        usage
        ;;
    esac
done

[ -n "$domain" ] || {
    echo "--domain 必填：订阅服务要用它签 ACME 证书" >&2
    exit 2
}
case "$domain" in
*[!A-Za-z0-9.-]*)
    echo "--domain 不是合法域名: $domain" >&2
    exit 2
    ;;
esac
case "$sub_port" in
'' | *[!0-9]*)
    echo "--sub-port 必须是数字: $sub_port" >&2
    exit 2
    ;;
esac

root=${DESTDIR:-}
if [ -z "$root" ]; then
    [ "$(uname -s)" = Linux ] || {
        echo "Linux only; use DESTDIR for packaging." >&2
        exit 1
    }
    [ "$(id -u)" = 0 ] || {
        echo "Run installation as root." >&2
        exit 1
    }
fi
for binary in "$core" "$panel" "$stats"; do
    [ -f "$binary" ] && [ -x "$binary" ] || {
        echo "Missing executable: $binary" >&2
        exit 1
    }
done

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -d -m 755 "$root/opt/vega/bin" "$root/opt/vega/etc" "$root/etc/systemd/system"
install -d -m 700 "$root/var/lib/vega" "$root/var/lib/vega/certs" "$root/var/lib/vega/acme"

install -m 755 "$core" "$root/opt/vega/bin/vega"
install -m 755 "$panel" "$root/opt/vega/bin/vega-panel"
install -m 755 "$stats" "$root/opt/vega/bin/sb-stats"

# 单元文件是模板：把 __DOMAIN__ / __SUB_PORT__ / __SUB_BASE__ 换成实际值。
for unit in vega.service vega-sub.service vega-enforce.service vega-cert-check.service vega-cert-check.timer; do
    sed -e "s|__DOMAIN__|$domain|g" \
        -e "s|__SUB_PORT__|$sub_port|g" \
        -e "s|__SUB_BASE__|https://$domain:$sub_port|g" \
        "$here/systemd/$unit" >"$root/etc/systemd/system/$unit"
    chmod 644 "$root/etc/systemd/system/$unit"
done

if [ -z "$root" ]; then
    systemctl daemon-reload
fi

cat <<EOF
已安装到 ${root:+$root}/opt/vega/bin（vega / vega-panel / sb-stats）。
订阅域名: $domain:$sub_port
已存在的配置和数据库不会被覆盖，也没有服务被启动。

下一步：
  export SBX_PANEL_DB=/var/lib/vega/panel.db SBX_PANEL_KERNEL=/opt/vega/bin/vega
  export SBX_PANEL_CONFIG=/opt/vega/etc/config.json SBX_PANEL_SERVICE=vega
  vega-panel doctor          # 先做体检
  vega-panel apply           # 生成 /opt/vega/etc/config.json
  systemctl enable --now vega vega-sub vega-cert-check.timer
EOF
