/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef AUCLASS_H
#define AUCLASS_H

#include "attrib.h"

#include <stdint.h>

/*
 * clonefile(2) and friends are available on 10.12 Sierra and later.
 * bsd/bsm/audit_kevents.h
 */
#if __MAC_OS_X_VERSION_MIN_REQUIRED < 101200
#ifndef AUE_CLONEFILEAT
#define AUE_CLONEFILEAT         43210
#endif
#ifndef AUE_FCLONEFILEAT
#define AUE_FCLONEFILEAT        43211
#endif
#endif

/*
 * audit_class(5), /etc/security/audit_class
 */
#define AC_NONE         0x00000000
#define AC_FREAD        0x00000001
#define AC_FWRITE       0x00000002
#define AC_FATTRA       0x00000004
#define AC_FATTRM       0x00000008
#define AC_FCREAT       0x00000010
#define AC_FDELET       0x00000020
#define AC_FCLOSE       0x00000040
#define AC_PROC         0x00000080
#define AC_NET          0x00000100
#define AC_IPC          0x00000200
#define AC_NA           0x00000400
#define AC_ADMIN        0x00000800
#define AC_LOGIN        0x00001000
#define AC_AUTH         0x00002000
#define AC_APP          0x00004000
#define AC_XNUMON       0x00400000	/* non-standard */
#define AC_IOCTL        0x20000000
#define AC_EXEC         0x40000000
#define AC_MISC         0x80000000
#define AC_ALL          0xFFFFFFFF

#define AC_FILE         (AC_FREAD |AC_FWRITE|AC_FATTRA|AC_FATTRM|\
                         AC_FCREAT|AC_FDELET|AC_FCLOSE)

extern const uint16_t auclass_xnumon_events_procmon[];
extern const uint16_t auclass_xnumon_events_hackmon[];
extern const uint16_t auclass_xnumon_events_filemon[];
int auclass_addmask(unsigned int, const uint16_t[]) NONNULL(2);
int auclass_removemask(unsigned int, const uint16_t[]) NONNULL(2);

unsigned int auclass_maskparse(const char *) NONNULL(1);

#endif
