### xnumon develop

-   Bumping schema version to 2.  Changes affect only eventcode 1.
    Eventcode 1 removed evtloop.pathbugs, procmon.cwdmiss, procmon.eimiss;
    added evtloop.radar38845422, evtloop.radar39267328, evtloop.radar39623812,
    evtloop.needpath, evtloop.needargv, evtloop.needcwd, procmon.eimiss.bypid,
    procmon.eimiss.forksubj, procmon.eimiss.execsubj, procmon.eimiss.execinterp,
    procmon.eimiss.chdirsubj, procmon.eimiss.getcwd.
-   Add `reload|restart` targets to `xnumonctl` to restart the daemon.
-   Add `stats_interval` config option to control how often xnumon-stats[1]
    events are generated.
-   Fix default hash if unspecified to be sha256 as documented in the default
    config.
-   Fix metrics for hackmon.
-   Minor bugfixes and improvements.


### xnumon 0.1.1 2018-06-17

-   Fix code signature extraction by using the strictest possible form of
    code signature verification.  Addresses fat binaries containing a
    combination of good and bad Mach-O binaries mistakenly being treated as
    having a good signature, as published by Josh Pitts of okta.
-   Fix installer package scripts for installing on external disks.
-   Harden permissions on default configuration file and directory.


### xnumon 0.1.0 2018-06-15

Initial release at [AREA41](//a41con.ch) 2018.
