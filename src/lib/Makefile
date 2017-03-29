include $(TOPDIR)/version.mk
include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

LIB_NAME := libsign

LIB_TARGETS := $(LIB_NAME).so $(LIB_NAME).a

OBJS_$(LIB_NAME) = \
	build_info.o \
	init.o \
	utils.o \
	digest.o \
	signaturelet.o \
	signlet.o \
	x509.o \
	key.o

CFLAGS += -fpic -ldl -DSIGNATURELET_DIR=\"$(TOPDIR)/src/signaturelet\"

all: $(LIB_TARGETS) Makefile

clean:
	@$(RM) $(LIB_TARGETS) $(OBJS_$(LIB_NAME)) \
	    $(addsuffix .*, $(LIB_TARGETS)) build_info.c

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(INSTALL) -m 755 $(LIB_NAME).a $(DESTDIR)$(libdir)
	$(INSTALL) -m 755 $(LIB_NAME).so $(DESTDIR)$(libdir)/$(LIB_NAME).so.$(LIBSIGN_VERSION)
	$(foreach x, $(LIB_NAME).so, \
	    ln -sfn $(x).$(LIBSIGN_VERSION) $(DESTDIR)$(libdir)/$(patsubst %,%.$(LIBSIGN_MAJOR_VERSION).$(LIBSIGN_MINOR_VERSION),$(x)); \
	    ln -sfn $(x).$(LIBSIGN_MAJOR_VERSION).$(LIBSIGN_MINOR_VERSION) $(DESTDIR)$(libdir)/$(patsubst %,%.$(LIBSIGN_MAJOR_VERSION),$(x)); \
	    ln -sfn $(x).$(LIBSIGN_MAJOR_VERSION) $(DESTDIR)$(libdir)/$(patsubst %,%,$(x));)

$(LIB_NAME).so: $(OBJS_$(LIB_NAME))
	$(CC) $^ -o $@ $(CFLAGS) -shared -Wl,-soname,$(patsubst %.$(LIBSIGN_VERSION),%,$@)

$(LIB_NAME).a: $(OBJS_$(LIB_NAME))
	$(AR) rcs $@ $^

build_info.c: build_info.c.in
	sed -e "s~@@LIBSIGN_GIT_COMMIT@@~$(shell if [ -d $(TOPDIR)/.git ]; then git log -1 --pretty=format:%H | tr -d '\n'; elif [ -f $(TOPDIR)/commit ]; then cat $(TOPDIR)/commit | tr -d '\n'; else echo -n ???????; fi)~" \
	    -e "s~@@LIBSIGN_BUILD_MACHINE@@~$(shell bash -c 'whoami | tr -d "\n"; echo -n @; uname=`uname -a`; echo -n $${uname//\~/_} | tr -d "\n"')~" < $^ > $@
