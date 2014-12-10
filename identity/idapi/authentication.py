# -*- coding: utf-8 -*-
#
# Authentication
#
# Copyright (C) 2013,2014 by entropy@heterarchy.net
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# For more details see the file COPYING.

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import AnonymousUser

from rest_framework import exceptions
from rest_framework.authentication import BasicAuthentication

def authenticate_sslcert(request, certs):
    if not request.is_secure():
        raise exceptions.AuthenticationFailed('Authentification requires SSL')
    authentication_status = request.META.get('X-SSL-Verified', None)
    if not authentication_status:
        authentication_status = request.META.get('HTTP_X_SSL_VERIFIED', None)
    cert = request.META.get('X-SSL-Client-Cert', None)
    if not cert:
        cert = request.META.get('HTTP_X_SSL_CLIENT_CERT', None)
    if cert is None:
        raise exceptions.AuthenticationFailed('Client Certificate missing')
    elif authentication_status != "SUCCESS":
        raise exceptions.AuthenticationFailed('SSL verification failed')
    cert = '\n'.join((line.strip() for line in cert.splitlines()))
    if not cert[-1]=='\n': cert += '\n'
    try: return certs[cert]
    except KeyError: raise exceptions.AuthenticationFailed('Certificate not authorized')

class SSLBasicAuthentication(BasicAuthentication):
    """
    Superclass of protection of views by SSL client and basic authentification.
    The subclass must specify www_authenticate_realm, which is used to look up
    the Cert/User/Password tuples from SSL_BASIC_AUTH, which are allowed
    """
    def authenticate(self, request):
        logins = getattr(settings,'SSL_BASIC_AUTH', None)
        if not logins or not self.www_authenticate_realm in logins: # disabled
            return (AnonymousUser, None)
        no_check = getattr(settings,'SSL_CLIENT_AUTH_DEBUG', False)
        certs = getattr(settings, 'SSL_CERTS', None)
        if not no_check and certs:
            cert = authenticate_sslcert(request,certs)
            found = False
            for login in logins[self.www_authenticate_realm]:
                if cert!=login[0]: continue
                found = True
                break
            if not found: raise exceptions.AuthenticationFailed('Invalid client certificate')
        auth = super(SSLBasicAuthentication,self).authenticate(request)
        if auth is None:
            raise exceptions.AuthenticationFailed('Login required')
        return auth

    def authenticate_credentials(self, userid, password):
        """
        Authenticate the userid and password against username and password.
        """
        #print 'auth login',userid,password
        logins = getattr(settings,'SSL_BASIC_AUTH', None)
        for login in logins[self.www_authenticate_realm]:
            username = login[1]
            if username is None: username = self.www_authenticate_realm
            if userid==username and password==login[2]:
                return (AnonymousUser, None)
        raise exceptions.AuthenticationFailed('Invalid username/password')

class SSLClientAuthentication(BasicAuthentication):
    """
    login an Application based on SSL Client Cert and its client_id.
    Lookup Cert in SSL_CERTS and permit corresponding cliend_id logins in SSL_CLIENT_LOGIN.
    token is the authenticated client_id
    """
    def authenticate(self, request):
        self.client_ids = None
        logins = getattr(settings, 'SSL_CLIENT_LOGIN', None)
        debug = getattr(settings,'SSL_CLIENT_AUTH_DEBUG', None)
        if debug: return (AnonymousUser, debug)
        certs = getattr(settings, 'SSL_CERTS', None)
        if logins and certs:
            cert = authenticate_sslcert(request,certs)
            try: self.client_ids = logins[cert]
            except: raise exceptions.AuthenticationFailed('client not authorized')
        auth = super(SSLClientAuthentication,self).authenticate(request)
        if auth is None:
            raise exceptions.AuthenticationFailed('Login required')
        #print 'did auth',auth
        return auth

    def authenticate_credentials(self, userid, password):
        """
        Authenticate the userid and password against username and password.
        """
        from oauth2_provider.models import get_application_model
        Application = get_application_model()
        if self.client_ids and not userid in self.client_ids:
            raise exceptions.AuthenticationFailed('Invalid client_id')
        try:
            app = Application.objects.get(client_id=userid)
        except ObjectDoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid client_id')
        if userid==app.client_id and password==app.client_secret:
            #print 'did login',userid
            return (AnonymousUser, app)
        raise exceptions.AuthenticationFailed('Invalid username/password')
