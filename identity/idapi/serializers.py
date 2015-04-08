# -*- coding: utf-8 -*-
#
# URL definitions
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

from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
User = get_user_model()
from rest_framework import serializers
from idapi import models
from accounts.models import NestedGroup, Verification

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ('url', 'name')

class NestedGroupSerializer(serializers.HyperlinkedModelSerializer):
    parent = serializers.HyperlinkedRelatedField(read_only=True, view_name='v1:nestedgroup-detail')
    class Meta:
        model = NestedGroup
        fields = ('id', 'name', 'parent', 'level','description')
        #extra_kwargs = {'parent': {'view_name': 'v1:nestedgroup-detail'}}

class AccountSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('username','password','email','status','uuid','nested_groups','public_id','profile')

class VerificationSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Verification
        fields = ('user','verifier','identity', 'public_id', 'profile')

class UserListSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.UserList
        fields = ('uuid', 'name', 'constraint', 'members')
