#!/bin/sh
# 校验 install.sh：文件铺到 /opt/vega，域名正确注入，已存在的配置/数据库不被覆盖，
# 且**不会**启用任何服务（不能出现 multi-user.target.wants）。
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

root="$stage/root"
mkdir -p "$root/opt/vega/etc" "$root/var/lib/vega"
printf 'keep-config' >"$root/opt/vega/etc/config.json"
printf 'keep-database' >"$root/var/lib/vega/panel.db"
printf '#!/bin/sh\nexit 0\n' >"$stage/binary"
chmod 755 "$stage/binary"

DESTDIR="$root" sh "$here/install.sh" "$stage/binary" "$stage/binary" "$stage/binary" \
    --domain sub.example.com --sub-port 9443

# 二进制
for file in vega vega-panel sb-stats; do
    test -x "$root/opt/vega/bin/$file"
done

# 状态目录必须是 0700
# stat -c 是 GNU 专有，macOS 用 -f；用 ls 判断更可移植
test "$(ls -ld "$root/var/lib/vega" | cut -c1-10)" = drwx------
test -d "$root/var/lib/vega/certs"
test -d "$root/var/lib/vega/acme"

# 单元文件都已安装，且没有残留占位符
for unit in vega.service vega-sub.service vega-enforce.service vega-cert-check.service; do
    test -f "$root/etc/systemd/system/$unit"
done
test -f "$root/etc/systemd/system/vega-cert-check.timer"
if grep -q '__DOMAIN__\|__SUB_PORT__\|__SUB_BASE__' "$root"/etc/systemd/system/vega*.service; then
    echo "单元文件里还有未替换的占位符" >&2
    exit 1
fi

# 域名和端口确实注入到订阅服务
grep -q 'sub.example.com' "$root/etc/systemd/system/vega-sub.service"
grep -q '9443' "$root/etc/systemd/system/vega-sub.service"
grep -q 'https://sub.example.com:9443' "$root/etc/systemd/system/vega-sub.service"

# 内核单元不能再指向旧路径
if grep -q '/usr/local/bin' "$root"/etc/systemd/system/vega*.service; then
    echo "单元文件仍指向 /usr/local" >&2
    exit 1
fi

# 已有数据不能被覆盖
test "$(cat "$root/opt/vega/etc/config.json")" = keep-config
test "$(cat "$root/var/lib/vega/panel.db")" = keep-database

# 不启用服务
test ! -e "$root/etc/systemd/system/multi-user.target.wants"

# 缺少 --domain 必须失败
if DESTDIR="$root" sh "$here/install.sh" "$stage/binary" "$stage/binary" "$stage/binary" 2>/dev/null; then
    echo "缺少 --domain 竟然成功了" >&2
    exit 1
fi

echo "Staged installation passed."

# --enable 在 DESTDIR 模式下必须什么都不做（不能碰宿主服务）
DESTDIR="$root" sh "$here/install.sh" "$stage/binary" "$stage/binary" "$stage/binary" \
    --domain sub.example.com --enable >/dev/null 2>&1
test ! -e "$root/etc/systemd/system/multi-user.target.wants"

# 单元清单必须与实际文件一一对应：漏一个单元等于漏一个功能。
# （vega-enforce 就曾经这样被漏掉，导致流量统计从来不工作）
for unit in vega.service vega-sub.service vega-enforce.service \
    vega-cert-check.service vega-cert-check.timer; do
    test -f "$here/systemd/$unit" || {
        echo "缺少单元文件: $unit" >&2
        exit 1
    }
    test -f "$root/etc/systemd/system/$unit" || {
        echo "install.sh 没有铺 $unit" >&2
        exit 1
    }
done

# 没人引用的单元文件说明 install.sh 清单漏了它
for file in "$here"/systemd/*; do
    name=$(basename "$file")
    grep -q "$name" "$here/install.sh" || {
        echo "install.sh 的单元清单漏了 $name" >&2
        exit 1
    }
done

# 每个 ExecStart 指向的二进制都必须由 install.sh 铺出来
for unit in "$here"/systemd/*.service; do
    for bin in $(grep -oE '/opt/vega/bin/[a-z-]+' "$unit" | sort -u); do
        test -x "$root$bin" || {
            echo "$(basename "$unit") 引用了不存在的 $bin" >&2
            exit 1
        }
    done
done

echo "Unit inventory passed."
