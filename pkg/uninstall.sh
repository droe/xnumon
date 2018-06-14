#!/bin/sh
# stop running instance and unload kernel module
if /bin/launchctl list ch.roe.xnumon >/dev/null 2>&1; then
	if [ -f /var/run/xnumon.pid ]; then
		pid=`cat /var/run/xnumon.pid`
	else
		pid=`killall -u root -s xnumon|cut -f 3 -d ' '|head -1 2>/dev/null`
	fi
	/bin/launchctl remove ch.roe.xnumon
	if [ "x$pid" != "x" ]; then
		while ps -p "$pid" -o comm= >/dev/null; do sleep 1; done
	else
		sleep 10
	fi
fi
if /usr/sbin/kextstat -l -b ch.roe.kext.xnumon|grep -q .; then
	/sbin/kextunload -b ch.roe.kext.xnumon
fi
# remove all files installed as part of the package
rm -f /Library/LaunchDaemon/ch.roe.xnumon.plist
rm -f /usr/local/sbin/xnumon
rm -f /usr/local/bin/xnumonctl
rm -rf /Library/Extensions/xnumon.kext/
rm -f /private/etc/newsyslog.d/ch.roe.xnumon.conf
# remove the package from the list of installed packages
pkgutil --forget ch.roe.kext.xnumon
pkgutil --forget ch.roe.xnumon
# remove files generated at run-time in default configuration
rm -f /var/log/xnumon.log*
rm -f /var/run/xnumon.pid
# remove uninstall script and default configuration
asdir="/Library/Application Support/ch.roe.xnumon"
if [ ! -f "$asdir/configuration.plist" ]; then
	# remove all (not using $asdir here for safety)
	rm -rf "/Library/Application Support/ch.roe.xnumon/"
else
	# remove all except custom config if it differs from default
	cmp -s "$asdir/configuration.plist-default" \
	       "$asdir/configuration.plist" && \
	 rm -f "$asdir/configuration.plist"
	rm -f "$asdir/configuration.plist-default"
	rm -f "$asdir/uninstall.sh"
	rmdir "$asdir" 2>/dev/null
fi
