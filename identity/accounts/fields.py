# -*- coding: utf-8 -*-
#
# Fields
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

from django import forms
from django.utils.translation import ugettext_lazy as _

class InvitationCodeField(forms.CharField):
    """Invitation code field"""

    def validate(self, value):
        """Validate against invitation code table"""
        super(InvitationCodeField, self).validate(value)

        from accounts.models import Invitation
        try:
            invitation_code = Invitation.objects.get(code=value,status=Invitation.NEW)
        except Invitation.DoesNotExist:
            raise forms.ValidationError(_("Invalid invitation code."))
