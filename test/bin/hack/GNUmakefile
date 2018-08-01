#CPPFLAGS+=	

CFLAGS+=	-std=c11 \
		-Wall

#LDFLAGS+=	

#LIBS+=		

TARGETS=	$(SRCS:.c=.test)
SRCS=		$(wildcard *.c)
HDRS=		$(wildcard *.h)
MKFS=		$(wildcard Makefile GNUmakefile Mk/*.mk)

all: $(TARGETS) true.unsigned

true.unsigned:
	cp /usr/bin/true $@
	codesign --remove-signature $@ || true

$(TARGETS): %.test: %.c $(MKFS) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf *.test *.dSYM true.unsigned

.PHONY: all clean
