XNU?=	../../../darwin-xnu
ifeq (,$(wildcard $(XNU)))
$(error XNU sources not found at $(XNU))
endif

CPPFLAGS+=	$(XNU)/osfmk -I $(XNU)/bsd -I $(XNU)/libkern
CFLAGS+=	-Wno-visibility

sizeof: sizeof.c
	$(CC) -I $(CPPFLAGS) $(CFLAGS) -o $@ $^

clean:
	rm -f sizeof

.PHONY: clean

