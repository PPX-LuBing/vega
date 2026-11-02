#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/root/usr/local/etc/sbx" "$stage/root/var/lib/sbx-panel"
printf 'keep-config' > "$stage/root/usr/local/etc/sbx/config.json"
printf 'keep-database' > "$stage/root/var/lib/sbx-panel/panel.db"
printf '#!/bin/sh\nexit 0\n' > "$stage/binary"
chmod 755 "$stage/binary"
DESTDIR="$stage/root" sh "$here/install.sh" "$stage/binary" "$stage/binary" "$stage/binary"
test "$(cat "$stage/root/usr/local/etc/sbx/config.json")" = keep-config
test "$(cat "$stage/root/var/lib/sbx-panel/panel.db")" = keep-database
for file in sbx sbx-panel sb-stats; do test -x "$stage/root/usr/local/bin/$file"; done
for unit in sbx sbx-sub sbx-enforce; do test -f "$stage/root/etc/systemd/system/$unit.service"; done
test ! -e "$stage/root/etc/systemd/system/multi-user.target.wants"
echo "Staged installation passed."
