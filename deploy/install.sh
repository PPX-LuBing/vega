#!/bin/sh
set -eu

# Supply prebuilt binaries; installation never starts or enables services.
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 CORE_BINARY PANEL_BINARY STATS_BINARY" >&2
    echo "Optional DESTDIR stages files without touching the host system." >&2
    exit 2
fi
root=${DESTDIR:-}
if [ -z "$root" ]; then
    [ "$(uname -s)" = Linux ] || { echo "Linux only; use DESTDIR for packaging." >&2; exit 1; }
    [ "$(id -u)" = 0 ] || { echo "Run installation as root." >&2; exit 1; }
fi
for binary in "$@"; do
    [ -f "$binary" ] && [ -x "$binary" ] || { echo "Missing executable: $binary" >&2; exit 1; }
done
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 755 "$root/usr/local/bin" "$root/usr/local/etc/sbx" "$root/etc/systemd/system"
install -d -m 700 "$root/var/lib/sbx" "$root/var/lib/sbx-panel"
install -m 755 "$1" "$root/usr/local/bin/sbx"
install -m 755 "$2" "$root/usr/local/bin/sbx-panel"
install -m 755 "$3" "$root/usr/local/bin/sb-stats"
for unit in sbx.service sbx-sub.service sbx-enforce.service sbx-cert-check.service sbx-cert-check.timer; do
    install -m 644 "$here/$unit" "$root/etc/systemd/system/$unit"
done
if [ -z "$root" ]; then
    systemctl daemon-reload
fi
echo "Installed. Existing database/configuration preserved; no services started."
echo "Configure nodes/users/grants, then run sbx-panel doctor and sbx-panel apply."
echo "Explicitly enable sbx, sbx-sub and sbx-enforce only after validation."
