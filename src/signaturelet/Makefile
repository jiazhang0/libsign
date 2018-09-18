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
	$(CCLD) $^ -o $@ $(CFLAGS) -shared -Wl,-soname,$@

clean:
	@$(RM) $(OBJS_SELoader) $(SIGNATURELET_NAMES)

install: all
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBDIR)/signaturelet
	$(INSTALL) -m 0755 SELoader.siglet $(DESTDIR)$(LIBDIR)/signaturelet
