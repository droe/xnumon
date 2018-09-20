# macOS kernel extension makefile
# Authored 2018, Daniel Roethlisberger
# Provided under the Unlicense
# https://github.com/droe/example.kext

# Designed to be included from a Makefile which defines the following:
#
# KEXTNAME        short name of the kext (e.g. example)
# KEXTVERSION     version number, cf. TN2420 (e.g. 1.0.0)
# KEXTBUILD       build number, cf. TN2420 (e.g. 1.0.0d1)
# BUNDLEDOMAIN    the reverse DNS notation prefix (e.g. com.example)
# COPYRIGHT       human readable copyright string
#
# Optionally, the Makefile can define the following:
#
# DEVIDKEXT       label of Developer ID cert in keyring for code signing
# ARCH            x86_64 (default) or i386
# PREFIX          install/uninstall location; default /Library/Extensions/
#
# BUNDLEID        kext bundle ID; default $(BUNDLEDOMAIN).kext.$(KEXTNAME)
# KEXTBUNDLE      name of kext bundle directory; default $(KEXTNAME).kext
# KEXTMACHO       name of kext Mach-O executable; default $(KEXTNAME)
#
# DEVELOPER_DIR   select Xcode Command Line Developer Tools directory
# MACOSX_VERSION_MIN  minimal version of macOS to target
# SDK             SDK name to build against (e.g. macosx, macosx10.11, ...)
# CPPFLAGS        additional precompiler flags
# CFLAGS          additional compiler flags
# LDFLAGS         additional linker flags
# LIBS            additional libraries to link against
# KLFLAGS         additional kextlibs flags

# check mandatory vars

ifndef KEXTNAME
$(error KEXTNAME not defined)
endif

ifndef KEXTVERSION
ifdef KEXTBUILD
KEXTVERSION:=	$(KEXTBUILD)
else
$(error KEXTVERSION not defined)
endif
endif

ifndef KEXTBUILD
ifdef KEXTVERSION
KEXTBUILD:=	$(KEXTVERSION)
else
$(error KEXTBUILD not defined)
endif
endif

ifndef BUNDLEDOMAIN
$(error BUNDLEDOMAIN not defined)
endif


# defaults
BUNDLEID?=	$(BUNDLEDOMAIN).kext.$(KEXTNAME)
KEXTBUNDLE?=	$(KEXTNAME).kext
KEXTMACHO?=	$(KEXTNAME)
ARCH?=		x86_64
#ARCH?=		i386
PREFIX?=	/Library/Extensions/

CODESIGN?=	codesign

# default SDK for targeted min version
ifndef SDK
ifdef MACOSX_VERSION_MIN
SDK:=		macosx$(MACOSX_VERSION_MIN)
endif
endif

# select Xcode
ifdef DEVELOPER_DIR
ifndef SDK
SDK:=		macosx
endif
else
DEVELOPER_DIR:=	$(shell xcode-select -p)
endif

# activate the selected Xcode and SDK
ifdef SDK
SDKPATH:=	$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) --show-sdk-path||echo none)
ifeq "$(SDKPATH)" "none"
$(error SDK not found)
endif
CPPFLAGS+=	-isysroot $(SDKPATH)
LDFLAGS+=	-isysroot $(SDKPATH)
CC:=		$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) cc||echo false)
#CXX:=		$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) c++||echo false)
CODESIGN:=	$(shell DEVELOPER_DIR="$(DEVELOPER_DIR)" xcrun -find -sdk $(SDK) codesign||echo false)
endif

# standard defines and includes for kernel extensions
CPPFLAGS+=	-DKERNEL \
		-DKERNEL_PRIVATE \
		-DDRIVER_PRIVATE \
		-DAPPLE \
		-DNeXT \
		-I/System/Library/Frameworks/Kernel.framework/Headers \
		-I/System/Library/Frameworks/Kernel.framework/PrivateHeaders

# convenience defines
CPPFLAGS+=	-DKEXTNAME_S=\"$(KEXTNAME)\" \
		-DKEXTVERSION_S=\"$(KEXTVERSION)\" \
		-DKEXTBUILD_S=\"$(KEXTBUILD)\" \
		-DBUNDLEID_S=\"$(BUNDLEID)\" \
		-DBUNDLEID=$(BUNDLEID) \

# c compiler flags
ifdef MACOSX_VERSION_MIN
CFLAGS+=	-mmacosx-version-min=$(MACOSX_VERSION_MIN)
endif
CFLAGS+=	-arch $(ARCH) \
		-fno-builtin \
		-fno-common \
		-mkernel \
		-msoft-float

# warnings
CFLAGS+=	-Wall -Wextra

# linker flags
ifdef MACOSX_VERSION_MIN
LDFLAGS+=	-mmacosx-version-min=$(MACOSX_VERSION_MIN)
endif
LDFLAGS+=	-arch $(ARCH)
LDFLAGS+=	-nostdlib \
		-Xlinker -kext \
		-Xlinker -object_path_lto \
		-Xlinker -export_dynamic
LDFLAGS+=	-Xlinker -fatal_warnings

# libraries
#LIBS+=		-lkmodc++
LIBS+=		-lkmod
LIBS+=		-lcc_kext

# kextlibs flags
KLFLAGS+=	-c

# source, header, object and make files
SRCS:=		$(wildcard *.c)
HDRS:=		$(wildcard *.h)
OBJS:=		$(SRCS:.c=.o)
MKFS:=		$(wildcard Makefile GNUmakefile Mk/*.mk)


# targets

all: $(KEXTBUNDLE)

%.o: %.c $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJS): $(MKFS)

$(KEXTMACHO): $(OBJS)
	$(CC) $(LDFLAGS) -static -o $@ $(LIBS) $^
	otool -h $@

Info.plist~: Info.plist.in $(MKFS)
	cat $< \
	| sed -e 's/__KEXTNAME__/$(KEXTNAME)/g' \
	      -e 's/__KEXTMACHO__/$(KEXTMACHO)/g' \
	      -e 's/__KEXTVERSION__/$(KEXTVERSION)/g' \
	      -e 's/__KEXTBUILD__/$(KEXTBUILD)/g' \
	      -e 's/__BUNDLEID__/$(BUNDLEID)/g' \
	      -e 's/__COPYRIGHT__/$(COPYRIGHT)/g' \
	>$@

$(KEXTBUNDLE): $(KEXTMACHO) Info.plist~
	mkdir -p $@/Contents/MacOS
	cp $< $@/Contents/MacOS
	cat Info.plist~ \
	| sed -e 's/__LIBS__//g' \
	>$@/Contents/Info.plist
	cat Info.plist~ \
	| awk '/__LIBS__/ {system("kextlibs -xml $(KLFLAGS) $@");next}1' \
	>$@/Contents/Info.plist~
	mv $@/Contents/Info.plist~ $@/Contents/Info.plist
	touch $@
ifdef DEVIDKEXT
	$(CODESIGN) -s $(DEVIDKEXT) -f $@
endif

load: $(KEXTBUNDLE)
	sudo chown -R root:wheel $<
	sudo sync
	sudo kextutil $<
	sudo chown -R '$(USER):$(shell id -gn)' $<
	sudo dmesg|grep $(KEXTNAME)|tail -1

stat:
	kextstat|grep $(KEXTNAME)

unload:
	sudo kextunload $(KEXTBUNDLE)

install: $(KEXTBUNDLE) uninstall
	test -d "$(PREFIX)"
	sudo cp -pr $< "$(PREFIX)/$<"
	sudo chown -R root:wheel "$(PREFIX)/$<"

uninstall:
	test -d "$(PREFIX)"
	test -e "$(PREFIX)/$(KEXTBUNDLE)" && \
		sudo rm -rf "$(PREFIX)/$(KEXTBUNDLE)" || true

clean:
	rm -rf $(KEXTBUNDLE) $(KEXTMACHO) Info.plist~ $(OBJS)


.PHONY: all load stat unload intall uninstall clean

