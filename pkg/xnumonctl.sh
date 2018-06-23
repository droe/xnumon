#!/bin/sh
if [ `id -u` -ne 0 ]; then
	exec /usr/bin/sudo "$0" "$@"
fi
case "$1" in
load|start)
	/bin/launchctl load /Library/LaunchDaemons/ch.roe.xnumon.plist
	;;
unload|stop)
	/bin/launchctl unload /Library/LaunchDaemons/ch.roe.xnumon.plist
	;;
restart|reload)
	"$0" unload
	/bin/sleep 1
	"$0" load
	;;
status)
	/bin/launchctl list ch.roe.xnumon
	;;
kextload)
	/sbin/kextload -b ch.roe.kext.xnumon
	;;
kextunload)
	/sbin/kextunload -b ch.roe.kext.xnumon
	;;
kextstat)
	/usr/sbin/kextstat -b ch.roe.kext.xnumon
	;;
reopen)
	kill -HUP `/bin/cat /var/run/xnumon.pid`
	;;
logstats)
	kill -USR1 `/bin/cat /var/run/xnumon.pid`
	;;
uninstall)
	exec /bin/sh '/Library/Application Support/ch.roe.xnumon/uninstall.sh'
	;;
logstderr)
	/usr/bin/plutil -replace StandardErrorPath -string /var/log/xnumon.stderr /Library/LaunchDaemons/ch.roe.xnumon.plist
	"$0" reload
	;;
*)
	echo "Usage: $0 load|unload|reload|start|stop|restart|status|kextload|kextunload|kextstat|reopen|logstats|uninstall" >&2
	exit 1
	;;
esac

