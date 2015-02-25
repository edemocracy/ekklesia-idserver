#!/usr/bin/env make -f
PROJ=identity
include ../Makefile.sub

EXCL+=oauth2_provider.accesstoken oauth2_provider.refreshtoken oauth2_provider.grant
#idapi.applicationuuid
APPS:=accounts idapi

install:
	test -f identity/settings.py || cp identity/settings-example.py identity/settings.py

runapi:
	$(MAKE) run CFG=DevelopmentAPI PORT=8091

runapic:
	$(MAKE) runcgi CFG=DevelopmentAPI SOCKNAME=idapi

runapip:
#	$(MAKE) run CFG=DevelopmentAPI PORT=8091
	$(MAKE) runcgip CFG=DevelopmentAPI PORT=8091

runapiw:
	$(MAKE) runw CFG=DevelopmentAPI SOCKNAME=idapi

runapiwp:
	$(MAKE) runwp CFG=DevelopmentAPI PORT=8091
