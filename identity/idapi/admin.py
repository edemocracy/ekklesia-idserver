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

from idapi import models
from django.contrib import admin
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.decorators import user_passes_test

@admin.register(models.ShareObject)
class ShareObjectAdmin(admin.ModelAdmin):
    fields = ('share','no','version','last_modified','last_client','data')
    readonly_fields = ('share','no','version','last_modified')
    list_display = ('share', 'no')
    ordering = ['share','no']
    search_fields = ['share__name','no']

@admin.register(models.ShareChange)
class ShareChangeAdmin(admin.ModelAdmin):
    readonly_fields = ('share','no','version','action','time','client')
    list_display = ('share', 'no','action')
    list_filter = ['action']
    ordering = ['share','no']
    search_fields = ['share__name','no']

class ShareObjectInline(admin.TabularInline):
    model = models.ShareObject
    fields = ShareObjectAdmin.fields
    readonly_fields = ShareObjectAdmin.readonly_fields
    extra =  1

@admin.register(models.Share)
class ShareAdmin(admin.ModelAdmin):
    fields = ('name','count','maxno','version',
        'last_push','last_modified','ref_counting')
    readonly_fields = ('count','maxno','version','last_push','last_modified')
    list_display = ('name','count')
    search_fields = ['name']
    ordering = ['name']
    inlines = [ShareObjectInline]

    def count(self, share):
        return len(share)
    count.short_description = 'Number of objects in the share'

@admin.register(models.ApplicationUUID)
class ApplicationUUIDAdmin(admin.ModelAdmin):
    fields = ('uuid','user','application')
    list_display = ('uuid', 'user','application')
    list_filter = ['application__client_id']
    search_fields = ['^uuid','user__username','^user__uuid','^user__email',
        'application__client_id','application__name']

    def get_readonly_fields(self, request, obj=None):
        if not obj: return ('uuid',)
        return self.fields # editing an existing object

@admin.register(models.UserListMember)
class UserListMemberAdmin(admin.ModelAdmin):
    readonly_fields = ('userlist', 'member', 'no')
    list_display = ('userlist','no', 'member')
    ordering = ['userlist','no']
    search_fields = ['member__username','^member__uuid','^member__email']

class UserListMemberInline(admin.TabularInline):
    model = models.UserListMember
    readonly_fields = UserListMemberAdmin.readonly_fields
    extra = 1

@user_passes_test(lambda u: u.is_superuser) # only admin
def export_list(request, ulid):
    from django.http import HttpResponse
    from django.shortcuts import get_object_or_404
    import csv
    userlist = get_object_or_404(models.UserList,ulid=ulid)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="%s.csv"' % ulid
    writer = csv.writer(response)
    writer.writerow(['userlist',userlist.ulid,userlist.name])
    no = 1
    for member in userlist.members.order_by('no'):
        while member.no > no:
            writer.writerow([no,''])
            no += 1
        writer.writerow([member.no, member.member.uuid])
        no += 1
    return response

@admin.register(models.UserList)
class UserListAdmin(admin.ModelAdmin):
    fields = ('ulid','name','count','info','owner',
        'maxno','version','last_push','last_modified')
    readonly_fields = ('ulid','count','maxno','version','last_push','last_modified')
    actions = ['export_list']
    list_display = ('name', 'count','owner','export_link')
    search_fields = ['name','^ulid','owner__name','owner__client_id']
    inlines = [UserListMemberInline]

    def count(self, userlist):
        return len(userlist)
    count.short_description = 'Number of users in the list'

    def export_link(self, obj):
        from django.core.urlresolvers import reverse
        return "<a href='%s'>Export UUIDs</a>" % reverse('v1:export_list', args=(obj.ulid,))
    export_link.allow_tags = True 

def user_email(obj):
    if not obj.user: return ''
    return obj.user.email

@admin.register(models.Message)
class MessageAdmin(admin.ModelAdmin):
    fields = ('user',user_email,'application',
        'identity','status','outgoing','email','crypto','locked','time','data')

    list_display = ('id','identity', 'user', 'outgoing')
    list_filter = ['outgoing','email','status','identity','application__client_id']
    search_fields = ['identity','id','user__username','^user__uuid','^user__email',
        'application__client_id','application__name']

    def get_readonly_fields(self, request, obj=None):
        if not obj: return (user_email,)
        return (user_email,'outgoing','email') # editing an existing object

@admin.register(models.PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    fields = ('user',user_email,'user_fingerprint',
        'trust','active','keytype','expires','data')
    readonly_fields = (user_email,'user_fingerprint')
    list_display = ('user', user_email,'trust','expires','active')
    list_filter = ['active','trust','keytype']
    search_fields = ['^fingerprint','user__username','^user__uuid','^user__email']

    def user_fingerprint(self, key):
        return key.user.fingerprint or '<not set>'

admin.site.unregister(models.IDApplication)

@admin.register(models.IDApplication)
class IDApplicationAdmin(admin.ModelAdmin):
    list_display = ('client_id', 'name')
