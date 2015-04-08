#!/usr/bin/env make -f

include Makefile.common

SASS_SRC = $(wildcard sass/[a-z]*.s?ss)
SASS_DEPS = $(wildcard sass/_*.s?ss) $(wildcard sass/*/*.s?ss) $(wildcard sass/*/*/*.s?ss)
SASS_OUT = $(patsubst sass/%.sass,static/css/%.css,$(patsubst %.scss,%.sass,$(SASS_SRC)))

SUBDIRS := identity # portal voting
TARGETS=all clean css html install tar test
STARGETS=backup init msg static upd valid
TEST_DEPS=

.PHONY: $(TARGETS) $(STARGETS)

all:
	@echo "make ($(subst $( ),|,$(TARGETS) $(STARGETS)))"

$(STARGETS):
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done

clean: basicclean
	rm -rf $(SASS_OUT)
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done

css: $(SASS_OUT)

html: $(JADE_OUT)

install:
	pip install --upgrade -r requirements/devel.txt
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done

test: test-local
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@ TEST_OPT=$(TEST_OPT); done

tar:
	@cd .. && $(TAR) czf ekklesia.tgz --exclude=.git "$(CURDIR)"

static/css/%.css: sass/%.sass $(SASS_DEPS)
	sassc $< $@
