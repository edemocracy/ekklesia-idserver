# -*- coding: utf-8 -*-
#
# Admin interface
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

from accounts import models
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth import get_user_model
User = get_user_model()
from django.utils.translation import ugettext_lazy as _
from mptt.admin import MPTTModelAdmin
from mptt.models import TreeForeignKey,TreeManyToManyField
from ekklesia.admin import UserAdminSite

#admin.site.disable_action('delete_selected')

@admin.register(models.NestedGroup)
class NestedGroupAdmin(MPTTModelAdmin):
    fields = ['syncid','name', 'parent','depth','description']
    mptt_level_indent = 20
    mptt_indent_field = 'name'
    list_display = ('name','depth')
    formfield_overrides = {
        TreeForeignKey: {'level_indicator': u'+-'},
    }
    actions = ['delete_nested_group']

    def get_actions(self, request):
        actions = super(NestedGroupAdmin, self).get_actions(request)
        del actions['delete_selected']
        return actions

    def delete_nested_group(self, request, obj):
        self.message_user(request,'not yet implemented') 
        for o in obj.all():
            o.delete()
    delete_nested_group.short_description = 'Delete nested group and update references'

class AccountCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = models.Account
        #fields = UserCreationForm.Meta.fields+('uuid',)

    def clean_email(self):
        return self.cleaned_data['email'] or None

    def clean_username(self):
        from django import forms
        username = self.cleaned_data["username"]
        try:
            # Not sure why UserCreationForm doesn't do this in the first place,
            # or at least test to see if _meta.model is there and if not use User...
            self._meta.model._default_manager.get(username=username)
        except self._meta.model.DoesNotExist:
            return username
        raise forms.ValidationError(self.error_messages['duplicate_username'])

class AccountChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = models.Account
        #fields = UserChangeForm.Meta.fields+('uuid',)
    def clean_email(self):
        return self.cleaned_data['email'] or None

class VerificationInline(admin.StackedInline):
    model = models.Verification
    fk_name = 'user'
    extra=1
    can_delete = False
    #FIXME: default verifier

class AccountAdmin(UserAdmin):
    add_form = AccountCreationForm
    form = AccountChangeForm
    inlines=[VerificationInline]
    fieldsets = (
        (None, {'fields': ('username', 'password','email','last_login')}),
        (_('Membership'), {'fields': ('status','uuid','nested_groups','staff_notes')}),
        (_('Profile'), {'fields': ('avatar','public_id','profile','fingerprint',
            'secure_email','two_factor_auth','notify_login')}),
        (_('Permissions'), {'classes':('collapse',),
            'fields': ('is_active', 'is_staff', 'is_superuser','groups', 'user_permissions')}),
    )
    readonly_fields = ('last_login','verified')
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2','email','uuid','nested_groups')}
        ),
    )
    """original:
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)
    filter_horizontal = ('groups', 'user_permissions',)
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)
    filter_horizontal = ('groups', 'user_permissions',)
    """
    actions = ['verify_user','convert_to_guest','convert_to_verifier']
    list_display = ('username','status','uuid','is_identity_verified')
    #list_editable = ('is_active',)
    list_filter = ('is_staff', 'nested_groups__name','groups')
    filter_horizontal = ('groups', 'user_permissions',)#'nested_group',
    #readonly_fields = ('my_summary',)
    search_fields = ('=username','uuid')

    formfield_overrides = {
        TreeForeignKey: {'level_indicator': u'+-'},
        TreeManyToManyField: {'level_indicator': u'+-'},
    }

    def verify_user(self, request, queryset):
        self.message_user(request,'not yet implemented') 
        for account in queryset: pass
    verify_user.short_description = "Mark user as verified by current user"

    def convert_to_member(self, request, queryset):
        for account in queryset: account.convert_to_member()
    convert_to_member.short_description = "Convert account to member"

    def convert_to_guest(self, request, queryset):
        for account in queryset: account.convert_to_guest()
    convert_to_guest.short_description = "Convert account to guest"

    def convert_to_verifier(self, request, queryset):
        for account in queryset: account.convert_to_verifier()
    convert_to_verifier.short_description = "Convert account to verifier"

    def activate(self, request, queryset):
        for account in queryset:
            account.is_active=True
            account.save(update_fields=['is_active'])
    activate.short_description = _("Activate accounts")

    def deactivate(self, request, queryset):
        for account in queryset:
            account.is_active=False
            account.save(update_fields=['is_active'])
    deactivate.short_description = _("Deactivate accounts")

    """
    In addition to showing a user's username in related fields, show their full
    name too (if they have one and it differs from the username).
    source http://djangosnippets.org/snippets/1642/
    """
    always_show_username = True

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        field = super(AccountAdmin, self).formfield_for_foreignkey(
                                                db_field, request, **kwargs)
        if db_field.rel.to == User and field:
            field.label_from_instance = self.get_user_label
        return field

    def formfield_for_manytomany(self, db_field, request=None, **kwargs):
        field = super(AccountAdmin, self).formfield_for_manytomany(
                                                db_field, request, **kwargs)
        if db_field.rel.to == User and field:
            field.label_from_instance = self.get_user_label
        return field

    def get_user_label(self, user):
        name = user.get_full_name()
        username = user.username
        if not self.always_show_username:
            return name or username
        return (name and name != username and '%s (%s)' % (name, username)
                or username)

admin.site.register(models.Account, AccountAdmin)

class GuestCreationForm(AccountCreationForm):
    class Meta(UserCreationForm.Meta):
        model = models.Guest
        #fields = UserCreationForm.Meta.fields+('default_privacy',)

class GuestChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = models.Guest

class GuestAdmin(AccountAdmin):
    add_form = GuestCreationForm
    form = GuestChangeForm

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email',
            'address','address_prefix','postal_code','city','country')}), # phone
        (_('User'), {'fields': ('status','staff_notes')}),
        (_('Profile'), {'fields': ('public_id','profile','fingerprint')}),
        (_('Permissions'), {'classes':('collapse',),
            'fields': ('is_active', 'is_staff', 'is_superuser','groups', 'user_permissions')}),
        (_('Important dates'), {'classes':('collapse',),
            'fields': ('last_login',)}),#'date_joined'
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2')}
        ),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email',
            'address','address_prefix','postal_code','city','country')}), # phone
    )
    actions = ['verify_user','convert_to_member']

    list_display = ('username','uuid','full_name','is_active','is_staff')
    search_fields = ('=username','=email','uuid','=last_name','=first_name')

    def full_name(self,obj):
        return obj.get_full_name()
    full_name.short_description = 'Full name'

admin.site.register(models.Guest, GuestAdmin)

class VerifierCreationForm(AccountCreationForm):
    class Meta(UserCreationForm.Meta):
        model = models.Verifier
        #fields = UserCreationForm.Meta.fields+('default_privacy',)

class VerifierChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = models.Verifier

@admin.register(models.Verifier)
class VerifierAdmin(AccountAdmin):
    add_form = VerifierCreationForm
    form = VerifierChangeForm

    fieldsets = AccountAdmin.fieldsets + (
        (_('Verifier'), {'fields': ('parent','for_nested_groups','delegation','expires')}),
    )

    add_fieldsets = AccountAdmin.add_fieldsets + (
        (_('Verifier'), {'fields': ('parent','for_nested_groups','delegation','expires')}),
    )

    readonly_fields = ('last_login',)
    actions = ['verify_user','convert_to_member']

@admin.register(models.Verification)
class VerificationAdmin(admin.ModelAdmin):
    list_display = ('user_name','user_member','verifier_name','identity')
    #list_display = ('subject__name','subject__uuid','verifier__name','verifier__uuid','identity')
    list_filter = ('identity',)
    search_fields = ('=user__username','=user__email','user__uuid','=user__last_name','verifier__username')

    def user_name(self,obj):
        return obj.user.username
    user_name.short_description = 'User name'
    def user_member(self,obj):
        return obj.user.uuid
    user_member.short_description = 'User member#'
    def verifier_name(self,obj):
        return obj.verifier.username
    verifier_name.short_description = 'Verifier name'

verification_site = UserAdminSite(name='verificationadmin',perm='accounts.account_verify')
# Run user_admin_site.register() for each model we wish to register
# for our admin interface for users
verification_site.register(models.Guest, GuestAdmin)

@admin.register(models.Account,site=verification_site)
class RestrictedAccountAdmin(AccountAdmin):
    add_form = None
    form = AccountChangeForm
    readonly_fields = ('username','status','uuid','nested_groups','last_login')
    fieldsets = (
        (None, {'fields': ('username','last_login')}),
        (_('Membership'), {'fields': ('status','uuid','nested_groups','staff_notes')}),
        (_('Profile'), {'fields': ('public_id','profile','fingerprint')}),
    )
    list_editable = ()

@admin.register(models.Verification,site=verification_site)
class RestrictedVerificationAdmin(VerificationAdmin):
    fieldsets = (
        (None, {'fields': ('user', 'date_verified')}),
        (_('Verification'), {
            'fields': ('identity', 'public_id', 'profile', 'fingerprint')}),
    )
    #readonly_fields = ('verifier',)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'verifier':
            kwargs['initial'] = request.user.id
            return db_field.formfield(**kwargs)
        return super(RestrictedVerificationAdmin, self).formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(models.Invitation)
class InvitationAdmin(admin.ModelAdmin):
    fields = ('code', 'uuid', 'status', 'secret')
    list_display = ('code', 'status', 'uuid')
    list_filter = ('status', )

@admin.register(models.EMailConfirmation)
class EMailConfirmationAdmin(admin.ModelAdmin):
    actions = ['confirm_emails', 'resend_confirmation_email']
    list_display = ('user', 'confirmation_key_expired')
    raw_id_fields = ['user']
    search_fields = ('user__username', 'user__first_name', 'user__last_name')

    def confirm_emails(self, request, queryset):
        for confirmation in queryset:
            models.EMailConfirmation.objects.confirm_user(confirmation.confirmation_key)
    confirm_emails.short_description = _("Confirm emails")

    def resend_confirmation_email(self, request, queryset):
        """
        Re-sends confirmation emails for the selected users.
        """
        from django.contrib.sites.shortcuts import get_current_site
        site = get_current_site(request)
        for confirmation in queryset:
            if not confirmation.confirmation_key_expired():
                profile.send_confirmation_email(domain=site.domain, use_https=self.request.is_secure())
    resend_confirmation_email.short_description = _("Re-send confirmation emails")
