# -*- coding: utf-8 -*-
#
# Forms
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
from django import forms
from django.utils.translation import ugettext as _

import django.contrib.auth.forms as auth
from accounts.models import Account, Guest, Verification, EMailConfirmation
from accounts.fields import InvitationCodeField
from captcha.fields import ReCaptchaField
from django_countries.fields import CountryField
#from phonenumber_field.modelfields import PhoneNumberField

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, ButtonHolder, Submit, HTML, LayoutObject

from django_otp.forms import OTPAuthenticationForm

TEMPLATE_PACK = getattr(settings, 'CRISPY_TEMPLATE_PACK', 'bootstrap')

class Conditional(LayoutObject):
    template = None

    def __init__(self, condition, *fields, **kwargs):
        self.condition = condition
        self.fields = list(fields)
        self.template = kwargs.get('template', self.template)

    def render(self, form, form_style, context, template_pack=TEMPLATE_PACK):
        from crispy_forms.utils import render_field
        if not self.condition(form,context): return ''
        html = u''
        for field in self.fields:
            html += render_field(field, form, form_style,
                                 context, template_pack=template_pack)
        return html

class AuthenticationForm(auth.AuthenticationForm):
    def __init__(self,request, *args,**kwargs):
        super(AuthenticationForm,self).__init__(request, *args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-login'
        self.helper.layout = Layout(
            'username','password',
            ButtonHolder(
                Submit('submit', value=_('Log in')),
            )
        )

class OptionalOTPAuthenticationForm(OTPAuthenticationForm):
    otp_challenge = None
    #next = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self,request, *args,**kwargs):
        super(OptionalOTPAuthenticationForm,self).__init__(request, *args,**kwargs)
        twofactor = getattr(settings, 'TWO_FACTOR_AUTH')
        label = "OTP Token (if available)" if twofactor == 'mandatory' else "OTP Token (optional)"
        self.fields['otp_token'].label = _(label)
        if twofactor != 'mandatory':
            self.fields['otp_device'].required = False
            self.fields['otp_token'].required = False
        self.helper = FormHelper()
        #self.helper.template = 'forms/whole_uni_form.html'
        self.helper.form_id = 'id-login'
        self.helper.layout = Layout(
            'username','password',
            Conditional(lambda form,ctx: form.get_user(),'otp_device'),
                'otp_token',
            ButtonHolder(
                Submit('submit', value=_('Log in')),
                Conditional(lambda form,ctx: form.get_user(),
                    Submit('otp_challenge', _('Get challenge code'))
                ),
            )
        )

    def otp_clean(self, user):
        if user is None: return
        device = self._chosen_device(user)
        token = self.cleaned_data.get('otp_token')
        error = None
        user.otp_device = None
        if self.request.POST.get('otp_challenge'):
            error = self._handle_challenge(device)
        elif token:
            user.otp_device = self._verify_token(user, token, device)
        if user.otp_device is None:
            self._update_form(user)
            if error is None:
                error = forms.ValidationError(_('Please enter your OTP token'))
            raise error

    def clean(self):
        twofactor = getattr(settings, 'TWO_FACTOR_AUTH')
        self.cleaned_data = super(OTPAuthenticationForm, self).clean()
        user = self.get_user()
        if twofactor=='mandatory' or (twofactor=='optional' and user.is_authenticated() and user.two_factor_auth):
            self.otp_clean(user)
        return self.cleaned_data

from oauth2_provider.forms import AllowForm

class AllowLoginForm(auth.AuthenticationForm,AllowForm): pass

class PasswordResetForm(auth.PasswordResetForm):
    def __init__(self,*args,**kwargs):
        super(PasswordResetForm,self).__init__(*args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-passwordreset'
        self.helper.layout = Layout(
            'email',
            ButtonHolder(
                Submit('submit', value=_('Reset my password')),
            )
        )

class SetPasswordForm(auth.SetPasswordForm):
    username = forms.CharField(label=_('Your username'), max_length=128,
        widget=forms.TextInput(attrs=dict(readonly='True')), required=False )
    def __init__(self,*args,**kwargs):
        super(SetPasswordForm,self).__init__(*args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-passwordset'
        self.helper.layout = Layout(
            'username', 'new_password1', 'new_password2',
            ButtonHolder(
                Submit('submit', value=_('Set my password')),
            )
        )

class PasswordChangeForm(auth.PasswordChangeForm):
    field_order = ['old_password', 'new_password1', 'new_password2']

    def __init__(self,*args,**kwargs):
        super(PasswordChangeForm,self).__init__(*args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-passwordchange'
        self.helper.layout = Layout(
            'old_password', 'new_password1', 'new_password2',
            ButtonHolder(
                Submit('submit', value=_('Change my password')),
            )
        )

class UsernameChangeForm(forms.Form):
    """
    A form that lets a user change their username by entering their old
    password.
    """
    error_messages = {
        'username_exists': _("This username does already exist. "
                                "Please enter another one."),
        'password_incorrect': _("Your password was entered incorrectly. "
                                "Please enter it again."),
    }
    username = forms.RegexField(regex=r'^[\w.@+-]+$',
                                max_length=30,
                                label=_("Username"),
                                error_messages={'invalid': _("This value may contain only letters, numbers and @/./+/-/_ characters.")})
    password = forms.CharField(label=_("Current password"),
                                   widget=forms.PasswordInput)

    def __init__(self,user,*args,**kwargs):
        self.user = user
        super(UsernameChangeForm,self).__init__(*args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-usernamechange'
        self.helper.layout = Layout(
            'username', 'password',
            ButtonHolder(
                Submit('submit', value=_('Change my username')),
            )
        )

    def clean_username(self):
        existing = Account.objects.filter(username__iexact=self.cleaned_data['username'])
        if existing.exists():
            raise forms.ValidationError(
                self.error_messages['username_exists'],
                code='username_exists',
            )
        else:
            return self.cleaned_data['username']

    def clean_password(self):
        """
        Validates that the password field is correct.
        """
        password = self.cleaned_data["password"]
        if not self.user.check_password(password):
            raise forms.ValidationError(
                self.error_messages['password_incorrect'],
                code='password_incorrect',
            )
        return password

    def save(self, commit=True):
        self.user.username = self.cleaned_data['username']
        if commit: self.user.save()
        return self.user

class EMailChangeForm(forms.Form):
    """
    A form that lets a user change their EMail by entering their old
    password.
    """
    error_messages = {
        'email_exists': _("This email does already exist. "
                                "Please enter another one."),
        'password_incorrect': _("Your password was entered incorrectly. "
                                "Please enter it again."),
    }
    email = forms.EmailField(label=_("E-mail"))
    email2 = forms.EmailField(label=_("E-mail (again)"))
    password = forms.CharField(label=_("Current password"),
                                   widget=forms.PasswordInput)

    def __init__(self,user,*args,**kwargs):
        self.user = user
        super(EMailChangeForm,self).__init__(*args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-emailchange'
        self.helper.layout = Layout(
            'email', 'email2', 'password',
            ButtonHolder(
                Submit('submit', value=_('Change my email')),
            )
        )

    def clean_password(self):
        """
        Validates that the password field is correct.
        """
        password = self.cleaned_data["password"]
        if not self.user.check_password(password):
            raise forms.ValidationError(
                self.error_messages['password_incorrect'],
                code='password_incorrect',
            )
        return password

    def clean(self):
        if 'email' in self.cleaned_data and 'email2' in self.cleaned_data: pass
        else: raise forms.ValidationError(_("Invalid form."))
        email = self.cleaned_data['email'].lower()
        if email != self.cleaned_data['email2'].lower():
            raise forms.ValidationError(_("The two email fields didn't match."))
        if self.initial['email'] == email: return None
        if Account.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                self.error_messages['email_exists'],
                code='email_exists',
            )
        self.cleaned_data['email'] = email
        return self.cleaned_data

    def save(self, commit=True):
        if not commit: return None
        email = self.cleaned_data['email']
        if self.initial['email'] == email: return None
        try: EMailConfirmation.objects.get(user=self.user).delete() # delete old confirmation
        except EMailConfirmation.DoesNotExist: pass
        conf = EMailConfirmation.objects.create_confirmation(self.user, email)
        return conf

class EditProfileForm(forms.ModelForm):
    class Meta:
        model = Account
        fields = ('avatar','public_id','profile')

    verified_public_id = forms.CharField(label=_('verified public identity'), max_length=128,
        widget=forms.Textarea(attrs=dict(readonly='True')), required=False )
    verified_profile = forms.CharField(label=_('verified personal profile'),
         widget=forms.Textarea(attrs=dict(readonly='True')), required=False )

    def __init__(self, *args,**kwargs):
        super(EditProfileForm,self).__init__(*args,**kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-editprofile'
        self.helper.layout = Layout(
            'avatar', 'verified_public_id', 'public_id', 'verified_profile', 'profile',
            ButtonHolder(
                Submit('submit', value=_('Change my profile')),
            )
        )

    def clean_public_id(self):
        if self.instance.get_verified_public_id() == self.cleaned_data['public_id']:
            return None
        return self.cleaned_data['public_id']

    def clean_profile(self):
        if self.instance.get_verified_profile() == self.cleaned_data['profile']:
            return None
        return self.cleaned_data['profile']

guest_extras_fields = ('address','address_prefix','postal_code','city','country') # phone

class GuestProfileForm(forms.ModelForm):
    class Meta:
        model = Guest
        fields = ('username','first_name','last_name')+guest_extras_fields+(
                    'fingerprint','profile',
                    #password, last_login, is_superuser, groups, user_permissions
                    #email, is_staff, is_active, date_joined,
                    #status,uuid,nested_groups,staff_notes,verified_by
                 )

class VerificationForm(forms.ModelForm):
    class Meta:
        model = Verification
        fields = ('user','date_verified','identity','fingerprint','profile'
                 #verifier
                 )

class RegistrationForm(forms.Form):
    required_css_class = 'required'

    username = forms.RegexField(regex=r'^[\w.@+-]+$',
                                max_length=30,
                                label=_("Username"),
                                error_messages={'invalid': _("This value may contain only letters, numbers and @/./+/-/_ characters.")})
    email = forms.EmailField(label=_("E-mail"))
    email2 = forms.EmailField(label=_("E-mail (again)"))
    password = forms.CharField(widget=forms.PasswordInput,
                                label=_("Password"))
    password2 = forms.CharField(widget=forms.PasswordInput,
                                label=_("Password (again)"))

    tos = forms.BooleanField(widget=forms.CheckboxInput,
         label=_(u'I have read and agree to the <a href="%s" target="_blank">Terms of Service</a>' % \
                             getattr(settings, 'TOS_URL','')),
                             error_messages={'required': _("You must agree to the terms to register")})
    captcha = ReCaptchaField(attrs={'theme' : 'clean'})

    field_order = None

    def __init__(self, *args, **kwargs):
        from collections import OrderedDict
        super(RegistrationForm, self).__init__(*args, **kwargs)
        if self.field_order is None: return
        fields = OrderedDict()
        for key in self.field_order:
            try: fields[key] = self.fields[key]
            except KeyError: continue
        self.fields = fields

        if not settings.RECAPTCHA_PRIVATE_KEY:
            del self.fields['captcha']

        self.helper = FormHelper()
        self.helper.form_id = 'id-register'
        self.helper.add_input(Submit('submit', 'Register'))

    def clean_username(self):
        existing = Account.objects.filter(username__iexact=self.cleaned_data['username'])
        if existing.exists():
            raise forms.ValidationError(_("A user with that username already exists."))
        else:
            return self.cleaned_data['username']

    def clean(self):
        if 'email' in self.cleaned_data and 'email2' in self.cleaned_data and \
            'password' in self.cleaned_data and 'password2' in self.cleaned_data: pass
        else: raise forms.ValidationError(_("Invalid form."))
        email = self.cleaned_data['email'].lower()
        if email != self.cleaned_data['email2'].lower():
            raise forms.ValidationError(_("The two email fields didn't match."))
        if Account.objects.filter(email__iexact=email):
            raise forms.ValidationError(_("This email address is already in use. Please supply a different email address."))
        self.cleaned_data['email'] = email
        if self.cleaned_data['password'] != self.cleaned_data['password2']:
            raise forms.ValidationError(_("The two password fields didn't match."))
        return self.cleaned_data

class MemberRegistrationForm(RegistrationForm):

    invitation_code = InvitationCodeField(required=True, label=_(u"Invitation code"))

    secret = forms.CharField(widget=forms.PasswordInput,required=True,
                                label=_("Activation secret"))

    field_order = ['invitation_code', 'secret', 'username', 'email', 'email2',
         'password', 'password2', 'captcha', 'tos']

    def __init__(self, *args, **kwargs):
        from django.forms.widgets import HiddenInput
        hide_code = kwargs.pop('hide_code',False)
        super(MemberRegistrationForm, self).__init__(*args, **kwargs)
        if hide_code:
            self.fields['invitation_code'].widget = HiddenInput()
        if not getattr(settings, 'TWO_FACTOR_SIGNUP', False):
            del self.fields['secret']

guest_req = settings.GUEST_MANDATORY_FIELDS

class GuestRegistrationForm(RegistrationForm):
    first_name = forms.CharField(label=_("First name"),max_length=30,required=guest_req)
    last_name = forms.CharField(label=_("Last name"),max_length=30,required=guest_req)
    address = forms.CharField(label=_("Street/no or POBox"),max_length=50,required=guest_req)
    address_prefix = forms.CharField(label=_("Address prefix"),max_length=50)
    city = forms.CharField(label=_("City"),max_length=30,required=guest_req)
    postal_code = forms.RegexField(regex=r'^\d{5}$', max_length=5, label=_("Postal code"), required=guest_req,
                                error_messages={'invalid': _("This value may contain only digits.")})
    country = CountryField(_("Country"),default='DE')
    #phone = PhoneNumberField(_("Phone number"))

    field_order = ['username', 'email', 'email2', 'password', 'password2',
            'first_name', 'last_name', 'address', 'address_prefix', 'city',
            'postal_code', 'city', 'country', #'phone',
            'captcha', 'tos']
