CPPFLAGS+=	-I$(CURDIR)/include

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
	./testrunner.py $(TESTS)

deps: $(DEPS)

$(DEPS): %.dep: %.c $(MKFS) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(TARGETS): %.test: %.c $(MKFS) $(HDRS) $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf $(TARGETS) *.dSYM $(DEPS)

copyright: $(SRCS) *.c *.py $(HDRS) $(STESTS)
	../Mk/bin/copyright.py $^

.PHONY: all clean copyright
