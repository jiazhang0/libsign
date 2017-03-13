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
	$(CC) $^ -o $@ $(CFLAGS) -shared -Wl,-soname,$(patsubst %.$(LIBSIGN_VERSION),%,$@)

clean:
	@$(RM) $(OBJS_SELoader) $(SIGNATURELET_NAMES)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	#$(INSTALL) -m 700 $(BIN_NAME) $(DESTDIR)$(bindir)
