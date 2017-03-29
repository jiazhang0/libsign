include $(TOPDIR)/version.mk
include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

CFLAGS += -DSELSIGN_KEY=\"$(TOPDIR)/key/efi_sb_keys/DB.key\" \
	  -DSELSIGN_CERT=\"$(TOPDIR)/key/efi_sb_keys/DB.pem\" \
	  -DSELSIGN_CA_CERT=\"$(TOPDIR)/key/efi_sb_keys/KEK.pem\" \

BIN_NAME := selsign

OBJS_$(BIN_NAME) := \
	selsign.o

all: $(BIN_NAME) Makefile

$(BIN_NAME): $(OBJS_$(BIN_NAME)) $(TOPDIR)/src/lib/libsign.so
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	@$(RM) $(OBJS_$(BIN_NAME)) $(BIN_NAME)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	$(INSTALL) -m 700 $(BIN_NAME) $(DESTDIR)$(bindir)
