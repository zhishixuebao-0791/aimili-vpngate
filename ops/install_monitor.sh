#!/bin/sh
set -eu

action=${1:-install}
name=aimili-monitor
marker='# Managed by AimiliVPN installer'
app_dir=/opt/aimilivpn
case "$action" in install|uninstall) ;; *) exit 2 ;; esac

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    init=systemd
    unit=$name.service
    file=/etc/systemd/system/$unit
    fragment=$(systemctl show "$unit" --property=FragmentPath --value 2>/dev/null || true)
    if [ -n "$fragment" ] && [ "$fragment" != "$file" ]; then
        echo 'AimiliVPN monitor: keeping the existing service.'
        exit 0
    fi
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    init=openrc
    file=/etc/init.d/$name
else
    echo 'AimiliVPN monitor: no supported init system found.'
    exit 0
fi

if [ -e "$file" ] || [ -L "$file" ]; then
    if [ -L "$file" ] || ! grep -Fxq "$marker" "$file"; then
        echo 'AimiliVPN monitor: keeping the existing service.'
        exit 0
    fi
fi

if [ "$action" = uninstall ]; then
    [ -f "$file" ] || exit 0
    if [ "$init" = systemd ]; then
        systemctl disable --now "$unit"
    else
        if rc-service "$name" status >/dev/null 2>&1; then
            rc-service "$name" stop
        fi
        if rc-update show default | grep -Eq "^[[:space:]]*$name[[:space:]]"; then
            rc-update del "$name" default
        fi
    fi
    rm -f -- "$file"
    if [ "$init" = systemd ]; then systemctl daemon-reload; fi
    exit 0
fi

[ -f "$app_dir/ops/egress_monitor.py" ]
if [ "$init" = openrc ]; then command -v supervise-daemon >/dev/null; fi
temporary=$(mktemp "${file}.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
if [ "$init" = systemd ]; then
    cat > "$temporary" <<EOF
$marker
[Unit]
Description=AimiliVPN independent HTTPS egress monitor
After=network.target aimilivpn.service

[Service]
ExecStart=/usr/bin/python3 $app_dir/ops/egress_monitor.py
EnvironmentFile=-/etc/default/aimilivpn
Restart=on-failure
RestartSec=10
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$temporary"
    mv -f -- "$temporary" "$file"
    systemctl daemon-reload
    systemctl enable --now "$unit"
else
    cat > "$temporary" <<EOF
#!/sbin/openrc-run
$marker
description="AimiliVPN independent HTTPS egress monitor"
command="/usr/bin/python3"
command_args="$app_dir/ops/egress_monitor.py"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0
pidfile="/run/$name.pid"

depend() {
    use net
    after aimilivpn
}
EOF
    chmod 755 "$temporary"
    mv -f -- "$temporary" "$file"
    rc-update add "$name" default
    rc-service "$name" start
fi
