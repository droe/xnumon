# Kext version only incremented when there were actual changes in the kext, so
# effectively the kext version is the xnumon release it last changed.

KEXTNAME=	xnumon
KEXTVERSION=	0.1.7
KEXTBUILD=	0.1.7
BUNDLEDOMAIN=	ch.roe
COPYRIGHT=	Copyright (c) 2017-2018 Daniel Roethlisberger. All rights reserved.

#CFLAGS+=	-DCDEV_ALLOW_TEAMID=\"C9BFEG985N\" \
#		-DCDEV_ALLOW_IDENTITY=\"ch.roe.xnumon\"

ifndef TRAVIS
MACOSX_VERSION_MIN=	10.11
DEVELOPER_DIR=	/Applications/Xcode-7.3.1.app/Contents/Developer
endif

#CFLAGS+=	-Wno-\#warnings
#CFLAGS+=	-DUSE_PRIVATE_KPI
#KLFLAGS=	-unsupported

ifndef TRAVIS
# Developer ID Application: Daniel Roethlisberger (C9BFEG985N)
ifeq "$(KEXTVERSION)" "$(KEXTBUILD)"
DEVIDKEXT=	"6BF4C67B70848E7A0635F1F1ADC6C9F869B69CEE" # prod
else
DEVIDKEXT=	"A6D93D1FFBDBEA6157560516ADED1F9ACD6FDE89" # test
endif
endif

include Mk/kext.mk
