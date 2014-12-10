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

from django.db import models
import six

@six.add_metaclass(models.SubfieldBase)
class EmailNullField(models.EmailField):
     # from http://stackoverflow.com/a/1934764
    # metaclass ensures to_python will be called
    description = "EmailField that stores NULL but returns ''"
    def to_python(self, value):  #this is the value right out of the db, or an instance
       if isinstance(value, models.EmailField): return value #if an instance, just return the instance
       if value==None: return "" #if the db has a NULL (==None in Python) convert it into the Django-friendly '' string
       else: return value #otherwise, return just the value
    def get_prep_value(self, value):  #catches value right before sending to db
       if self.null and value=="": return None #if Django tries to save '' string, send the db None (NULL)
       elif isinstance(value, six.string_types): return value.lower() # if str, lower
       else: return value #otherwise, just pass the value
