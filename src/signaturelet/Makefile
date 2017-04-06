include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

SIGNATURELET_NAMES := \
	SELoader.siglet

OBJS_SELoader := \
	SELoader.o

CFLAGS += -fpic

all: $(SIGNATURELET_NAMES) Makefile

#.siglet: %.o
SELoader.siglet: $(OBJS_SELoader) $(TOPDIR)/src/lib/libsign.so
	$(CC) $^ -o $@ $(CFLAGS) -shared -Wl,-soname,$@

clean:
	@$(RM) $(OBJS_SELoader) $(SIGNATURELET_NAMES)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)/signaturelet
	$(INSTALL) -m 644 SELoader.siglet $(DESTDIR)$(libdir)/signaturelet
