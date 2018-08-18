### xnumon develop

-   Socket events: socket-listen[5], socket-accept[6] and socket-connect[7]
    (issue #14) including associated suppression options.
-   Also consider link(2), linkat(2), symlink(2), symlinkat(2), clonefile(2),
    clonefileat(2), fclonefileat(2), copyfile(2), fcopyfile(2) and implicit
    close on exit for file monitoring events.
-   Still produce eventcode 4 when the ProgramPath from the plist cannot be
    resolved.
-   Detect a bug in audit(4) where calls to renameat(2) lead to
    `AUE_RENAMEAT` records with missing destination path path tokens
    (radar 42770257).
-   Detect a bug in audit(4) where calls to link(2) always lead to
    `AUE_LINK` records with only three instead of four path tokens
    (radar 42783724).
-   Detect a bug in audit(4) where calls to symlink(2) or symlinkat(2) with a
    relative path always lead to `AUE_SYMLINK`/`AUE_SYMLINKAT` records with
    only one instead of two path tokens (radar 42784847).
-   Detect a bug in audit(4) where calls to \_\_mac\_execve(2) always lead to
    `AUE_MAC_EXECVE` recors without exec arg and exec env tokens
    (radar 42946744).
-   Detect a bug in audit(4) where calls to linkat(2) lead to
    `AUE_LINKAT` records with missing destination path path tokens
    (radar 43151662).
-   Work around a bug in audit(4) where ports for IPv6 sockets are in wrong
    byte order (radar 43063872).
-   The installer package now refuses to install on unsupported OS versions.
-   Initial version of an automated test framework (issue #9).

Configuration changes:

-   Added `suppress_socket_op_localhost`, `suppress_socket_op_by_subject_ident`
    and `suppress_socket_op_by_subject_path`.

Event schema changes:

-   Event schema version increased to 7.  Changes affect eventcodes 1,4,5,6,7.
-   Eventcode 1 added `evtloop.radar42770257`, `evtloop.radar42770257_fatal`,
    `evtloop.radar42783724`, `evtloop.radar42783724_fatal`,
    `evtloop.radar42784847`, `evtloop.radar42784847_fatal`,
    `evtloop.radar42946744`, `evtloop.radar42946744_fatal`,
    `evtloop.radar43151662`, `evtloop.radar43151662_fatal`,
    `sockmon.recvd`, `sockmon.procd` and `sockmon.ooms`.
-   Eventcode 4 added `program.rpath` and `program.path` is now exactly the
    unresolved ProgramPath from the plist.
-   Eventcodes 5, 6 and 7 added.

---

### xnumon 0.1.6.2 2018-08-05

-   Hotfix release fixing a rare data corruption issue in the audit(4) record
    handling (issue #41).

---

### xnumon 0.1.6.1 2018-08-01

-   Hotfix release fixing a crash in the kext event handling loop of the
    xnumon daemon (issue #36).

---

### xnumon 0.1.6 2018-07-29

-   Capability to log all environment variables at image exec (`full`),
    only log variables affecting dyld (`dyld`) or not log the environment
    (`none`) (issue #7).
-   Add `xml` log format (issue #12).
-   Add capability to omit the `sid` field of processes.
-   Rewritten event loop for improved behaviour under load (issue #33).
-   Use IOKit API instead of `kextload` to load the xnumon kext (issue #17).
-   Check global audit(4) policy settings every five minutes for clobbering
    (issue #35).

Configuration changes:

-   Added `envlevel`.
-   Added `omit_sid`.

Event schema changes:

-   Event schema version increased to 6.  Changes affect eventcodes 1 and 2.
-   Eventcode 1 added `evtloop.aupclobber`.
-   Eventcode 2 added `env`.

---

### xnumon 0.1.5 2018-07-23

-   Suppressions by ident now support optionally restricting an ident to a
    specific team ID (issue #27).
-   User and group IDs are now by default resolved to names (issues #4, #28).
-   User and group ID -1 is now logged as signed integer -1 instead of unsigned
    integer 4294967295 (issue #29).
-   Extract the `origin` of good signed binaries from the code signature:
    Apple System (`system`), Mac App Store (`appstore`),
    Developer ID (`devid`), other Apple (`generic`) or signature from CA in
    system's Trust Settings database (`trusted`) (issue #31) and align
    algorithm with Gatekeeper.
-   Report code signatures from untrusted CAs as signature `untrusted` with no
    origin instead of signature `bad`.
-   Add capability to omit somewhat less useful fields from logged events:
    file mode, size, mtime, ctime, btime, and groups (file gid and process
    egid/rgid) (issue #3).
-   Treat TTY device `/dev/null` and source address `0.0.0.0` as no device and
    no address respectively and hide the `dev` and `addr` fields accordingly
    unless an actual TTY device or source address is reported by audit(4).
-   Fix automatic configuration reloading to pick up changes to the config file
    during the first five minutes and during initialization.
-   Add metric for the number of processes successfully acquired from live
    process state as part of working around some bug or missed event.
-   Add raw log destination driver mode to facilitate fully custom logging
    within the current log driver model.
-   Add `chkcs` developer utility to extract code signatures from binaries or
    bundles on the command line.

Configuration changes:

-   Extended `suppress_image_exec_by_ident`,
    `suppress_image_exec_by_ancestor_ident` and
    `suppress_process_access_by_subject_ident` to support ident@teamid syntax.
-   Added `resolve_users_groups`.
-   Added `omit_mode`, `omit_size`, `omit_mtime`, `omit_ctime`, `omit_btime`,
    `omit_groups`.

Event schema changes:

-   Event schema version increased to 5.  Changes affect eventcodes 1-4.
-   Eventcode 1 added `procmon.liveacq`.
-   Eventcode 2 added `image.origin`.
-   Eventcode 2 renamed `image.devid` to `image.certcn`.
-   Eventcodes 2-4 added `*uname` for every `*uid` field.
-   Eventcodes 2-4 added `*gname` for every `*gid` field.

---

### xnumon 0.1.4 2018-07-15

-   Add `json-seq` log format, as defined in RFC 7464:  JSON objects are each
    prefixed by an ASCII Record Separator and terminated by an ASCII Line Feed
    character (issue #13).
-   Mark all image execs as well as subject and object processes that were
    reconstructed by pid instead of from audit events with a `reconstructed`
    field.
-   Generate an image exec event for processes that were missed during exec for
    some reason and are reconstructed by pid later on for context.
-   Make configurable whether processes already running at xnumon agent start
    should generate an image exec event (issue #8).
-   Fix text rendering of `signature` field on images.
-   Use travis-ci.com for continuous integration on supported macOS versions
    (issue #24).

Configuration changes:

-   Add `suppress_image_exec_at_start`.

Event schema changes:

-   Event schema version increased to 4.  Changes affect eventcodes 2-4.
-   Eventcode 2 added `reconstructed`.
-   Eventcode 4 added `object.reconstructed`.
-   Eventcodes 2-4 added `subject.reconstructed`.

---

### xnumon 0.1.3 2018-07-07

-   Fix ancestors default if not set from 0 back to unlimited as documented and
    omit ancestors array entirely if ancestors is 0.
-   Suppressions by path now also match the script path, not only the image or
    interpreter path.
-   Add ability to suppress child image exec events by ancestor ident or path
    in order to be able to suppress noisy things like MacPorts builds
    (issue #22).
-   Streamlined signer information from code signatures now includes
    developer ID and team ID instead of the full certificate chain, which
    results in lower heap usage and lower log volume for essentially the same
    information (issue #20).
-   Extract CDHash from code signatures (issue #21).
-   Add ability to omit hashes for Apple-signed binaries, enabled by default
    (issue #2).
-   Verify that signatures on Apple binaries are anchored at the Apple root.

Configuration changes:

-   Rename `suppress_process_access_by_ident` and
    `suppress_process_access_by_path` to
    `suppress_process_access_by_subject_ident` and
    `suppress_process_access_by_subject_path`.
-   Add `suppress_image_exec_by_ancestor_ident` and
    `suppress_image_exec_by_ancestor_path`.
-   Add `omit_apple_hashes`.

Event schema changes:

-   Event schema version increased to 3.  Changes affect eventcodes 1-4.
-   Eventcode 1 replaced `evtloop.needargv`, `evtloop.needcwd` and
    `evtloop.needpath` with `evtloop.radar38845422_fatal`,
    `evtloop.radar39267328_fatal` and `evtloop.radar39623812_fatal`.
-   Eventcode 1 added `evtloop.missingtoken` and `evtloop.radar38845784`.
-   Eventcode 2 replaced `image.codesign.result`, `image.codesign.cert`,
    `image.codesign.chain` with `image.signature`, `image.teamid` and
    `image.devid`.
-   Eventcode 2 added `image.cdhash`.
-   Eventcodes 2-4 added `subject.image.teamid` and
    `subject.ancestors[].teamid`.

---

### xnumon 0.1.2 2018-06-24

-   Fix handling of `ptrace` and `task_for_pid` audit events for pid 0 or -1.
-   Fix default hash if unspecified to be sha256 as documented in the default
    config.

Configuration changes:

-   Add `events` config option to configure the desired eventcodes (issue #1).
-   Add `stats_interval` config option to control how often xnumon-stats[1]
    events are generated.
-   Add `debug` config option to control whether debug messages are logged to
    stderr.
-   Add `reload|restart` target to `xnumonctl`, rename `logstats` to `event1`.

Event schema changes:

-   Event schema version increased to 2.  Changes affect eventcodes 0 and 1.
    Eventcode 0 added config.events, config.stats_interval, config.debug.
    Eventcode 1 removed evtloop.pathbugs, procmon.cwdmiss, procmon.eimiss;
    added evtloop.radar38845422, evtloop.radar39267328, evtloop.radar39623812,
    evtloop.needpath, evtloop.needargv, evtloop.needcwd, procmon.miss.bypid,
    procmon.miss.forksubj, procmon.miss.execsubj, procmon.miss.execinterp,
    procmon.miss.chdirsubj, procmon.miss.getcwd.

---

### xnumon 0.1.1 2018-06-17

-   Fix code signature extraction by using the strictest possible form of
    code signature verification.  Addresses fat binaries containing a
    combination of good and bad Mach-O binaries mistakenly being treated as
    having a good signature, as published by Josh Pitts of okta.
-   Fix installer package scripts for installing on external disks.
-   Harden permissions on default configuration file and directory.

---

### xnumon 0.1.0 2018-06-15

Initial release at [AREA41](//a41con.ch) 2018.
