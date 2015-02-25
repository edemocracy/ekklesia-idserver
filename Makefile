#!/usr/bin/env make -f

include Makefile.common

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
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done

css: $(SASS_OUT)

html: $(JADE_OUT)

install-css:
	gem install --no-ri --no-rdoc --user bootstrap-sass compass-h5bp
	compass install --force bootstrap
	compass install compass-h5bp

install:
	pip install -r requirements/devel.txt
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done

test: test-local
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@ TEST_OPT=$(TEST_OPT); done

tar:
	@cd .. && $(TAR) czf ekklesia.tgz --exclude=.git "$(CURDIR)"

$(SASS_OUT): $(SASS_SRC)
	@compass compile
	rm -rf static/css/bootstrap
