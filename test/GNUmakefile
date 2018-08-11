PEERADDR6?=	2a01:7c8:aab0:1fb::1
PEERADDR4?=	149.210.147.66
PEERPORT?=	443

CPPFLAGS+=	-I$(CURDIR)/include \
		-DTESTDIR=\"$(CURDIR)\" \
		-DHOME=\"$(HOME)\" \
		-DPEERADDR4=\"$(PEERADDR4)\" \
		-DPEERADDR6=\"$(PEERADDR6)\" \
		-DPEERPORT=$(PEERPORT)

CFLAGS+=	-std=c11 \
		-Wall

#LDFLAGS+=	

#LIBS+=		

TARGETS=	$(SRCS:.c=.test)
STESTS=		$(shell cd $(CURDIR); find testcases -type f -name '*.stest')
TESTS=		$(TARGETS) $(STESTS)
SRCS=		$(shell cd $(CURDIR); find testcases -type f -name '*.c')
HDRS=		$(shell cd $(CURDIR); find . -type f -name '*.h')
MKFS=		$(wildcard Makefile GNUmakefile Mk/*.mk)
DEPS=		true.dep

all: $(TARGETS) deps

test: $(TESTS)
	sudo -v
	./testrunner.py $(TESTS)

deps: $(DEPS)

$(DEPS): %.dep: %.c $(MKFS) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(TARGETS): %.test: %.c $(MKFS) $(HDRS) $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf $(TARGETS) *.dSYM $(DEPS) trace.* logs.json
	find . -name '*.plist' -delete

copyright: $(SRCS) *.c *.py $(HDRS) $(STESTS)
	../Mk/bin/copyright.py $^

.PHONY: all clean copyright
