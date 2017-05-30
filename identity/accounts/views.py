# -*- coding: utf-8 -*-
#
# Views
#
# Copyright (C) 2013-2015 by Thomas T. <ekklesia@heterarchy.net>
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
from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response, render, get_object_or_404
from django.utils.translation import ugettext as _
from django.contrib.auth.decorators import login_required, permission_required
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache

from django.shortcuts import redirect, resolve_url
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.template.response import TemplateResponse
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import logout

import accounts.models as models
import accounts.forms as forms
from accounts.models import Account
from django.contrib.auth.signals import user_logged_in

def template_location(*args):
    import os
    from django.template import loader, TemplateDoesNotExist
    path = os.path.join(*args)
    if getattr(settings, 'DEBUG'):
        fname = path+'.jade'
        try:
            loader.get_template(fname)
            return fname
        except TemplateDoesNotExist: pass
    return path+'.html'

default_template = template_location('form')
message_template = template_location('message')

def get_otp_form(request, always=False, **kwargs):
    from django.contrib.auth.forms import AuthenticationForm
    from django_otp.forms import OTPTokenForm
    from django.contrib.auth import BACKEND_SESSION_KEY
    from functools import partial
    user = request.user
    form = None
    twofactor = getattr(settings, 'TWO_FACTOR_AUTH')
    kwargs['template_name'] = template_location('registration','login')
    #kwargs['template_name'] = default_template
    if user.is_anonymous() or always:
        if twofactor in ('optional','mandatory'):
            form = forms.OptionalOTPAuthenticationForm
        else:
            form = forms.AuthenticationForm
    elif not user.is_verified() and (twofactor=='mandatory' or (twofactor=='optional' and user.two_factor_auth)):
        form = partial(OTPTokenForm, user)
        # A minor hack to make django.contrib.auth.login happy
        user.backend = request.session[BACKEND_SESSION_KEY]
    if form is None: return None
    kwargs['authentication_form'] = form
    kwargs['extra_context'] = dict(title='Log in')
    #if not request.POST.get('next',request.GET.get('next','')): kwargs['extra_context'] = dict(next='/')
    return kwargs

def otp_login(request, **kwargs):
    from django.contrib.auth.views import login
    kwargs = get_otp_form(request, always=True, **kwargs)
    return login(request, **kwargs)

def notify_login(sender, user, request, **kwargs):
    if not user.notify_login: return
    #print("user %s logged in" % user.username)

user_logged_in.connect(notify_login)

def index_view(request, **kwargs):
    from django.contrib.auth.views import login
    kwargs = get_otp_form(request, always=False, **kwargs)
    if not kwargs is None:
        return login(request, **kwargs)

    from accounts.models import Account
    user = request.user
    data = dict(username = user.username,
        key_registered = bool(user.publickeys.filter(active=True).count()),
        status = dict(Account.STATUS_CHOICES)[user.status],
        verified = user.is_identity_verified(),
        eligible = user.status == Account.ELIGIBLE,
        nested_groups = user.nested_groups.all(),
        all_nested_groups = user.get_nested_groups(parents=True),
        two_factor_auth = user.two_factor_auth,
        notify_login = user.notify_login,
        secure_email = user.secure_email,
    )
    return render(request, template_location('accounts','index'), data)

from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.oauth2 import Server

from idapi.models import IDApplication

class IDAuthorizationView(OAuthLibMixin, FormView):
    template_name = 'accounts/authorize.html'
    server_class = Server
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS
    include_login = True

    def dispatch(self, request, *args, **kwargs):
        from django.contrib.auth import REDIRECT_FIELD_NAME
        from django.contrib.auth.views import redirect_to_login
        self.oauth2_data = {}
        twofactor = getattr(settings, 'TWO_FACTOR_AUTH')
        if request.method == 'GET' and twofactor=='optional' and \
             not request.user.is_verified(): # POST is protected by CRSF
            client_id = request.GET.get('client_id','')
            if client_id:
                try:
                    app = IDApplication.objects.get(client_id=client_id)
                    if app.two_factor_auth:
                        return redirect_to_login(request.get_full_path(),
                            settings.LOGIN2FAC_URL, REDIRECT_FIELD_NAME)
                except: pass
        if not self.include_login and not request.user.is_authenticated():
            return redirect_to_login(request.get_full_path(),
                settings.LOGIN_URL, REDIRECT_FIELD_NAME)
        return super(IDAuthorizationView, self).dispatch(request, *args, **kwargs)

    def error_response(self, error, **kwargs):
        """
        Handle errors either by redirecting to redirect_uri with a json in the body containing
        error details or providing an error response
        """
        redirect, error_response = super(IDAuthorizationView, self).error_response(error, **kwargs)
        if redirect:
            return HttpResponseRedirect(error_response['url'])
        status = error_response['error'].status_code
        return self.render_to_response(error_response, status=status)

    def oauth_error(self,request,error,**kwargs):
        # UGLY HACK
        from oauthlib.common import Request
        core = self.get_oauthlib_core()
        uri, http_method, body, headers = core._extract_params(request)
        orequest = Request(uri, http_method=http_method, body=body, headers=headers)
        raise OAuthToolkitError(error=error(request=orequest, state=orequest.state,**kwargs))

    def check_scopes(self, request, app, scopes):
        from oauthlib.oauth2 import InvalidScopeError
        if app.permitted_scopes:
            permitted = app.permitted_scopes.split(' ')
            for scope in scopes:
                if scope in permitted: continue
                self.oauth_error(request,InvalidScopeError,description="scope %s is not permitted for this client" % scope)
        if app.required_scopes:
            required = app.required_scopes.split(' ')
            for scope in required:
                if scope in scopes: continue
                self.oauth_error(request,InvalidScopeError,description="required scope %s for this client is missing" % scope)

    def get(self, request, *args, **kwargs):
        from oauthlib.oauth2 import AccessDeniedError
        twofactor = getattr(settings, 'TWO_FACTOR_AUTH')
        try:
            scopes, credentials = self.validate_authorization_request(request)
            auto = False
            ## first check possible restrictions and autopermit
            app = IDApplication.objects.get(client_id=credentials['client_id'])
            # at this point we know an IDApplication instance with such client_id exists in the database
            if twofactor=='optional' and app.two_factor_auth and not request.user.is_verified():
                self.oauth_error(request,AccessDeniedError,description="Two-factor authorization failed")
            self.check_scopes(request, app, scopes)
            if app.autopermit_scopes:
                autopermit = app.autopermit_scopes.split(' ')
                auto = True
                for scope in scopes:
                    if scope in autopermit: continue
                    auto = False
                    break
                if auto and request.user.is_authenticated():
                    uri, headers, body, status = self.create_authorization_response(
                        request=self.request, scopes=' '.join(scopes), credentials=credentials, allow=True)
                    return HttpResponseRedirect(uri)
            credentials['scope'] = scopes

            # Check to see if the user has already granted access and return
            # a successful response depending on 'approval_prompt' url parameter
            require_approval = request.GET.get('approval_prompt', oauth2_settings.REQUEST_APPROVAL_PROMPT)
            if require_approval == 'auto':
                tokens = request.user.accesstoken_set.filter(application=kwargs['application'],
                                                             expires__gt=timezone.now()).all()
                # check past authorizations regarded the same scopes as the current one
                for token in tokens:
                    if token.allow_scopes(scopes):
                        uri, headers, body, status = self.create_authorization_response(
                            request=self.request, scopes=" ".join(scopes),
                            credentials=credentials, allow=True)
                        return HttpResponseRedirect(uri)

            self.oauth2_data = credentials
            # following code is here only because of https://code.djangoproject.com/ticket/17795
            self.two_factor = app.two_factor_auth and twofactor =='optional'
            form = self.get_form(self.get_form_class())
            kwargs['form'] = form
            return self.render_to_response(self.get_context_data(**kwargs))
        except OAuthToolkitError as error:
            #print error
            return self.error_response(error)

    def get_initial(self):
        # TODO: move this scopes conversion from and to string into a utils function
        scopes = self.oauth2_data.get('scope', [])
        initial_data = {
            'redirect_uri': self.oauth2_data.get('redirect_uri', None),
            'scope': ' '.join(scopes),
            'client_id': self.oauth2_data.get('client_id', None),
            'state': self.oauth2_data.get('state', None),
            'response_type': self.oauth2_data.get('response_type', None),
        }
        return initial_data

    def get_form_class(self):
        from oauth2_provider.forms import AllowForm
        client_id = self.request.GET.get('client_id','')
        self.two_factor = False
        if client_id:
            try:
                app = IDApplication.objects.get(client_id=client_id)
                self.two_factor = app.two_factor_auth
            except: pass
        if self.include_login and not self.two_factor: return forms.AllowLoginForm
        return AllowForm

    def get_form_kwargs(self):
        kwargs = super(IDAuthorizationView, self).get_form_kwargs()
        if self.include_login and not self.two_factor: kwargs.update({'request': self.request})
        return kwargs

    def get_context_data(self,**kwargs):
        from oauth2_provider.settings import oauth2_settings
        import django
        kwargs = super(IDAuthorizationView, self).get_context_data(**kwargs)
        self.request.POST = {} # validate based only on GET params
        scopes, credentials = self.validate_authorization_request(self.request)
        # at this point we know an IDApplication instance with such client_id exists in the database
        app = IDApplication.objects.get(client_id=credentials['client_id'])
        kwargs['scopes_descriptions'] = [oauth2_settings.SCOPES[scope] for scope in scopes]
        kwargs['scope'] = scopes
        kwargs['application'] = app
        kwargs['login'] = self.include_login and not self.two_factor and not self.request.user.is_authenticated()
        kwargs.update(credentials)
        return kwargs

    def form_valid(self, form):
        from django.contrib.auth import login as auth_login
        from django.contrib.auth import logout as auth_logout
        from oauthlib.oauth2 import AccessDeniedError, InvalidClientIdError
        import django
        try:
            credentials = {
                'client_id': form.cleaned_data.get('client_id'),
                'redirect_uri': form.cleaned_data.get('redirect_uri'),
                'response_type': form.cleaned_data.get('response_type', None),
                'state': form.cleaned_data.get('state', None),
            }
            scopes = form.cleaned_data.get('scope')
            allow = form.cleaned_data.get('allow')
            try: app = IDApplication.objects.get(client_id=credentials['client_id'])
            except IDApplication.DoesNotExist:
                self.oauth_error(self.request,InvalidClientIdError)
            if app.two_factor_auth and not self.request.user.is_verified():
                self.oauth_error(self.request,AccessDeniedError,description="Two-factor authorization failed")
            self.check_scopes(self.request, app, scopes.split(' '))
            logout = False
            if self.include_login and not self.request.user.is_authenticated():
                # Okay, security check complete. Log the user in.
                if app.keep_login: # keep login until browser closed
                    logout = False
                    settings.SESSION_EXPIRE_AT_BROWSER_CLOSE = True
                else:
                    logout = True
                auth_login(self.request, form.get_user())
            uri, headers, body, status = self.create_authorization_response(
                request=self.request, scopes=scopes, credentials=credentials, allow=allow)
            self.success_url = uri
            if logout: auth_logout(self.request)
            #log.debug("Success url for the request: {0}".format(self.success_url))
            return super(IDAuthorizationView, self).form_valid(form)
        except OAuthToolkitError as error:
            #print error
            return self.error_response(error)

@csrf_protect
def password_reset(request,
                   email_template_name='registration/password_reset_email.txt',
                   subject_template_name='registration/password_reset_subject.txt',
                   token_generator=default_token_generator,
                   from_email=None,
                   current_app=None,
                   extra_context=None,
                   html_email_template_name=None):
    logout(request) # make sure user is logged out
    if request.method == "POST":
        form = forms.PasswordResetForm(request.POST)
        if form.is_valid():
            opts = {
                'use_https': request.is_secure(),
                'token_generator': token_generator,
                'from_email': from_email,
                'email_template_name': email_template_name,
                'subject_template_name': subject_template_name,
                'request': request,
                'html_email_template_name': html_email_template_name,
            }
            form.save(**opts)
            context = dict(
                title= _('Password reset sent'),
                message=_("We've e-mailed you instructions for setting your password to the e-mail address you submitted. You should be receiving it shortly."),
            )
            if extra_context is not None: context.update(extra_context)
            return TemplateResponse(request, message_template, context,
                                    current_app=current_app)
    else:
        form = forms.PasswordResetForm()
    context = {
        'form': form,
        'title': _('Password reset'),
    }
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, template_location('registration','password_reset'), context,
                            current_app=current_app)

# Doesn't need csrf_protect since no-one can guess the URL
@sensitive_post_parameters()
@never_cache
def password_reset_confirm(request, uidb64=None, token=None,
                           token_generator=default_token_generator,
                           current_app=None, extra_context=None):
    """
    View that checks the hash in a password reset link and presents a
    form for entering a new password.
    """
    logout(request) # make sure user is logged out
    from django.utils.http import urlsafe_base64_decode
    assert uidb64 is not None and token is not None  # checked by URLconf
    try:
        uid = urlsafe_base64_decode(uidb64)
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        initial = dict(username = user.username)
        if request.method == 'POST':
            form = forms.SetPasswordForm(user, request.POST, initial=initial)
            if form.is_valid():
                form.save()
                context = {
                    'login': resolve_url(settings.LOGIN_URL),
                    'title': _('Password reset complete'),
                }
                if extra_context is not None: context.update(extra_context)
                return TemplateResponse(request, template_location('registration','password_confirm'), context,
                                        current_app=current_app)
        else:
            form = forms.SetPasswordForm(user, initial=initial)
        context = {
            'form': form,
            'title': _('Enter new password'),
        }
        if extra_context is not None: context.update(extra_context)
        return TemplateResponse(request, default_template, context,
                                current_app=current_app)
    context = {
        'title': _('Password reset unsuccessful'),
        'message': _("""The password reset link was invalid, possibly because it has already been used.
Please request a new password reset."""),
    }
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, message_template, context,
                            current_app=current_app)

@sensitive_post_parameters()
@csrf_protect
@login_required
def username_change(request,extra_context=None):
    if request.method == "POST":
        form = forms.UsernameChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('/')
    else:
        form = forms.UsernameChangeForm(user=request.user)
    context = {
        'form': form,
        'title': _('Change user name'),
    }
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, default_template, context)

@sensitive_post_parameters()
@csrf_protect
@login_required
def email_change(request,extra_context=None):
    initial = dict(email=request.user.email)
    if request.method == "POST":
        form = forms.EMailChangeForm(user=request.user, data=request.POST, initial=initial)
        if form.is_valid():
            from django.contrib.sites.shortcuts import get_current_site
            conf = form.save()
            if conf:
                site = get_current_site(request)
                conf.send_confirmation_email(domain=site.domain, use_https=request.is_secure())
            return HttpResponseRedirect('/')
    else:
        form = forms.EMailChangeForm(user=request.user, initial=initial)
    context = {
        'form': form,
        'title': _('Change EMail'),
    }
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, default_template, context)

@login_required
def profile_view(request, extra_context=None):
    user = request.user
    context = dict(
        title= _('Public profile of %s') % user.username,
        avatar = user.avatar,
        verified_public_id = user.get_verified_public_id(),
        public_id = user.public_id,
        verified_profile = user.get_verified_profile(),
        profile = user.profile,
    )
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, template_location('accounts','profile'), context)

@sensitive_post_parameters()
@csrf_protect
@login_required
def profile_edit(request,extra_context=None):
    user = request.user
    public_id = user.get_verified_public_id()
    profile = user.get_verified_profile()
    initial = dict(
        verified_public_id = public_id,
        public_id = user.public_id or public_id,
        verified_profile = profile,
        profile = user.profile or profile,
    )
    if request.method == "POST":
        form = forms.EditProfileForm(instance=request.user, data=request.POST,
             files=request.FILES, initial=initial)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('/')
    else:
        form = forms.EditProfileForm(instance=request.user, initial=initial)
    context = {
        'form': form,
        'title': _('Edit profile'),
    }
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, default_template, context)

def show_departments(request):
    return render_to_response(template_location('accounts','departments'),
                          {'nodes':models.NestedGroup.objects.all()},
                          context_instance=RequestContext(request))

class RegistrationView(FormView):
    disallowed_url = getattr(settings, 'REGISTRATION_CLOSED_URL','/')
    form_class = forms.RegistrationForm
    http_method_names = ['get', 'post', 'head', 'options', 'trace']
    success = (_('Registration complete'),_("""
Please complete your registration by confirming your email.
A confirmation link has been sent to the email address you supplied."""))
    template_name = 'registration/registration_form.html'

    def dispatch(self, request, *args, **kwargs):
        if not self.registration_allowed():
            return render(self.request, message_template,
                dict(title=_('Registration closed'),message=_('Registration is currently closed.')))
        logout(request) # make sure user is logged out
        return super(RegistrationView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        new_user = self.register(**form.cleaned_data)
        args = dict(title=self.success[0],message=self.success[1])
        return render(self.request, message_template, args)

    def register(self, send_email=True, **cleaned_data):
        from django.db import transaction
        from django.utils import timezone
        from django.contrib.sites.shortcuts import get_current_site
        site = get_current_site(self.request)
        username, email, password = cleaned_data['username'], cleaned_data['email'], cleaned_data['password']
        with transaction.atomic():
            new_user = self.user_class.objects.create_user(username, None, password,
                status=Account.DELETED, last_login=timezone.now())
            new_user.email = None
            new_user.is_active = False
            new_user.save(update_fields=['is_active'])
            confirmation = models.EMailConfirmation.objects.create_confirmation(new_user, email)
        if send_email:
            confirmation.send_confirmation_email(domain=site.domain, use_https=self.request.is_secure())
        return new_user

    def registration_allowed(self):
        return getattr(settings, 'REGISTRATION_OPEN', True)

class MemberRegistrationView(RegistrationView):
    form_class = forms.MemberRegistrationForm
    user_class = models.Account

    def get_form_kwargs(self):
        kwargs = super(MemberRegistrationView, self).get_form_kwargs()
        code = self.request.GET.get('code')
        if code: kwargs['hide_code'] = True
        return kwargs

    def get_initial(self):
        return dict(invitation_code=self.request.GET.get('code', None))

    def register(self, **kwargs):
        from datetime import datetime
        from accounts.models import Invitation
        invitation = get_object_or_404(models.Invitation,
            code=kwargs['invitation_code'],status=Invitation.NEW)
        new_user = super(MemberRegistrationView,self).register(**kwargs)
        require_activate = getattr(settings, 'TWO_FACTOR_SIGNUP', False)
        if require_activate:
            invitation.secret = kwargs['secret']
        invitation.status = Invitation.REGISTERING
        invitation.save()
        new_user.uuid = invitation.uuid
        new_user.status = models.Account.NEWMEMBER
        new_user.save()
        return new_user

class GuestRegistrationView(RegistrationView):
    form_class = forms.GuestRegistrationForm
    user_class = models.Guest

    def register(self, **kwargs):
        new_user = super(GuestRegistrationView,self).register(**kwargs)
        new_user.status = models.Account.GUEST
        for field in ('first_name', 'last_name','address','address_prefix',
            'postal_code','city','country'): # phone
            setattr(new_user,field,kwargs[field])
        new_user.save()
        return new_user

class EMailConfirmationView(TemplateView):
    http_method_names = ['get']
    template_name = message_template

    def get_context_data(self, **kwargs):
        import django.contrib.humanize.templatetags.humanize as humanize
        context = super(EMailConfirmationView, self).get_context_data(**kwargs)
        confirmed_user = self.confirm(**kwargs)
        if confirmed_user:
            context['title'] = _("Email confirmed")
            context['message'] = _('''Your email %s has been successfully confirmed.
Your account will be activated shorlty, after which you may login.''') % confirmed_user.email
            #print type(confirmed_user), confirmed_user.is_active
        else:
            context['title'] = _("E-Mail confirmation failed")
            context['message'] = _("""
Sorry, it didn't work. Either your confirmation link was incorrect, or
the confirmation key for your account has expired; confirmation keys are
only valid for %s days.""") % humanize.apnumber(settings.EMAIL_CONFIRMATION_DAYS)
        return context

    def confirm(self, confirmation_key):
        return models.EMailConfirmation.objects.confirm(confirmation_key)

@login_required
def verification_view(request, extra_context=None):
    user = request.user
    from accounts.models import Invitation
    try:
        invitation = Invitation.objects.get(uuid=user.uuid,code=verification_key,status=Invitation.VERIFY)
        invitation.status = Invitation.VERIFIED
        invitation.save()
        context = dict(
            title= _("Account verified"),
            message= _('Your account has been successfully verified.')
            )
    except Invitation.DoesNotExist:
        context = dict(
            title= _("Account verification failed"),
            message= _("""
Sorry, it didn't work. Either your verification link was incorrect, or you account is already verified or
the verification code for your account is no longer valid.""")
            )
    if extra_context is not None: context.update(extra_context)
    return TemplateResponse(request, message_template, context)
