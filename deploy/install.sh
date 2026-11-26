#!/bin/sh
# Vega 安装脚本：默认只铺文件和 systemd 单元，**不启动、不启用任何服务**。
# 加 --enable 则装完直接启用并启动服务（含 vega-enforce，否则流量统计不工作）。
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
  --enable   装完立即 enable + start 全部服务（含 vega-enforce）。
             不加则只铺文件，需要按提示手动启用。
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
enable_services=0
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
    --enable)
        enable_services=1
        shift
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

if [ "$enable_services" = 1 ] && [ -z "$root" ]; then
    # vega 需要 config.json，所以先 doctor/apply 再启动
    echo "==> 生成配置"
    apply_ok=0
    SBX_PANEL_DB=/var/lib/vega/panel.db \
    SBX_PANEL_KERNEL=/opt/vega/bin/vega \
    SBX_PANEL_CONFIG=/opt/vega/etc/config.json \
    SBX_PANEL_SERVICE=vega \
    SBX_PANEL_CERT_DIR=/var/lib/vega/certs \
    SBX_PANEL_STATS_BIN=/opt/vega/bin/sb-stats \
    SBX_PANEL_API=127.0.0.1:10085 \
        /opt/vega/bin/vega-panel apply && apply_ok=1

    if [ "$apply_ok" != 1 ]; then
        # apply 失败通常是「还没有节点/用户」。这时候**不能**启用 vega：
        # 配置不完整会被 systemd 反复重启，变成崩溃循环。
        # 订阅服务和采集服务不依赖节点，可以照常启用。
        echo "警告：apply 失败（常见原因是还没建节点），本次只启用订阅与采集服务。"
        echo "      建好节点后执行：vega-panel apply && systemctl enable --now vega"
        systemctl enable --now vega-sub vega-cert-check.timer vega-enforce
    else
        echo "==> 启用服务"
        systemctl enable --now vega vega-sub vega-cert-check.timer vega-enforce
    fi

    echo "==> 服务状态"
    for s in vega vega-sub vega-enforce vega-cert-check.timer; do
        printf '  %-24s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo unknown)"
    done
    if [ "$apply_ok" != 1 ]; then
        printf '  %-24s %s\n' "（下一歩）" "建节点 → vega-panel apply → systemctl enable --now vega"
    fi
fi

cat <<EOF
已安装到 ${root:+$root}/opt/vega/bin（vega / vega-panel / sb-stats）。
订阅域名: $domain:$sub_port
已存在的配置和数据库不会被覆盖。

下一步：
  export SBX_PANEL_DB=/var/lib/vega/panel.db SBX_PANEL_KERNEL=/opt/vega/bin/vega
  export SBX_PANEL_CONFIG=/opt/vega/etc/config.json SBX_PANEL_SERVICE=vega
  vega-panel doctor          # 先做体检
  vega-panel apply           # 生成 /opt/vega/etc/config.json
  systemctl enable --now vega vega-sub vega-cert-check.timer vega-enforce

注意 vega-enforce 不能漏：它是**唯一**会持续采集流量的组件。
不启用它，面板上的流量统计会一直是 0（手动 collect 才有数据）。
EOF
