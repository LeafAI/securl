#!/bin/sh
set -eu

case "$(basename "$0"):${1:-}" in
  user-service:restart|postinst:configure) action=restart ;;
  user-service:stop|prerm:remove|prerm:deconfigure) action=stop ;;
  *) exit 0 ;;
esac

if [ ! -d /run/systemd/system ]; then
  echo 'securl: systemd is not running; the binary is installed. Start securl daemon in your own session.' >&2
  exit 0
fi

userctl() {
  runuser -u "$username" -- env XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user "$@"
}

for runtime in /run/user/[0-9]*; do
  [ -S "$runtime/bus" ] || continue
  uid="${runtime##*/}"
  case "$uid" in *[!0-9]*|'') continue ;; esac
  [ "$uid" -eq 0 ] && continue
  record="$(getent passwd "$uid")" || continue
  username="${record%%:*}"
  if ! userctl daemon-reload || ! userctl "$action" securl.service; then
    echo "securl: could not $action the user daemon for $username; run systemctl --user daemon-reload and systemctl --user $action securl.service in that user's session." >&2
    [ "$action" != stop ] || exit 1
  fi
done

if [ "$action" = restart ]; then
  echo 'securl: enabled for future user logins. The daemon starts locked; no credentials or configuration were changed.'
fi
