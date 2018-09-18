CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
CCLD := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
OBJCOPY := $(CROSS_COMPILE)objcopy
NM := $(CROSS_COMPILE)nm
INSTALL ?= install
GIT ?= git

EXTRA_CFLAGS ?=
EXTRA_LDFLAGS ?=

DEBUG_BUILD ?=
SIGNATURELET_DIR ?= $(TOPDIR)/src/signaturelet

# For the build
prefix ?= /usr
libdir ?= $(prefix)/lib
bindir ?= $(prefix)/bin
includedir ?= $(prefix)/include

# For the installation
DESTDIR ?=
BINDIR ?= $(bindir)
LIBDIR ?= $(libdir)

LDFLAGS := -Wl,--warn-common -Wl,--no-undefined -Wl,--fatal-warnings \
	   $(EXTRA_LDFLAGS)
CFLAGS := -std=gnu11 -O2 -DLIBSIGN_VERSION=\"$(LIBSIGN_VERSION)\" \
	  -Wall -Wsign-compare -Werror \
	  $(addprefix $(join -L,),$(libdir)) \
	  -lcrypto $(addprefix -I, $(TOPDIR)/src/include) \
	  $(EXTRA_CFLAGS) $(LDFLAGS)

ifneq ($(DEBUG_BUILD),)
	CFLAGS += -ggdb -DDEBUG_BUILD
endif
