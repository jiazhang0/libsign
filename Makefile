include version.mk
include env.mk

TOPDIR := $(shell pwd)
export TOPDIR

SUBDIRS := src

.DEFAULT_GOAL := all
.PHONE: all clean install tag

all clean install:
	@for x in $(SUBDIRS); do $(MAKE) -C $$x $@ || exit $?; done

tag:
	@$(GIT) tag -a $(LIBSIGN_VERSION) -m $(LIBSIGN_VERSION) refs/heads/master
