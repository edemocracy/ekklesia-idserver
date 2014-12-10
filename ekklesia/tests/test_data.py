#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Data unit tests, based on kryptomime tests
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

from __future__ import absolute_import
from pytest import raises

from six.moves import cStringIO as StringIO
from ekklesia.data import json_decrypt, json_encrypt, DataTable

sender='foo@localhost'
passphrase='mysecret'
receiver='bar@localhost'

def test_object():
    from ekklesia.data import init_object, repr_object, extract_object, objects_equal
    class Sample(object):
        c = 3
        def __init__(self):
            self.a = 1
            self.b = 2
        def some(self): pass
    x,y = Sample(),Sample()
    assert objects_equal(x,y)
    assert objects_equal(x,y,('a','c'))
    y.c = 4
    assert not objects_equal(x,y)
    assert not objects_equal(x,y,('a','c'))
    assert objects_equal(x,y,('a','b'))
    assert repr_object(x,('a','b','c'))=='Sample(1,2,3)'
    init_object(x,a=11,c=33)
    assert x.a==11 and x.c==33
    assert repr_object(x,('a','b','c'))=='Sample(11,2,33)'
    assert extract_object(x,('a','b'))=={'a':11,'b':2}
    assert extract_object(x,('a','b'),{'a':1,'c':3})=={'a':1,'b':2}

json_data = {'a':1,'b':3.14,'s':'foo\nbar','n':None,'b':True}
class Obj:
    def __init__(self,a=1,b=2,c=3): self.a,self.b,self.c=a,b,c

class TestData:
    def json(self,ids,encrypt,sign):
        plain = not encrypt and not sign
        c, result = json_encrypt(json_data,ids['id1'],receiver if encrypt else False,sign)
        assert c and plain or result
        d, encrypted, signed, result = json_decrypt(c,ids['id2'])
        assert encrypted==encrypt and signed==sign and (result is None)==plain
        assert plain or result.valid==sign
        assert d==json_data
    def test_json_plain(self,bilateral):
        self.json(bilateral,False,False)
    def test_json_sign(self,bilateral):
        self.json(bilateral,False,True)
    def test_json_encrypt(self,bilateral):
        self.json(bilateral,True,False)
    def test_json_both(self,bilateral):
        self.json(bilateral,True,True)

    def test_json_bad_sign(self,bilateral,gpgreceiver):
        # id1 sign for id2, but id2 doesn't know id1
        c, result = json_encrypt(json_data,bilateral['id1'],False,True)
        assert c and result
        d, encrypted, signed, result = json_decrypt(c,gpgreceiver)
        assert (d, encrypted, signed, result.valid) == (None, False, True, False)
    def test_json_bad_signenc(self,bilateral,gpgreceiver):
        # id1 encrypt+sign for id2, but id2 doesn't know id1
        c, result = json_encrypt(json_data,bilateral['id1'],receiver,True)
        assert c and result
        d, encrypted, signed, result = json_decrypt(c,gpgreceiver)
        assert (d, encrypted, signed, result.valid) == (None, True, True, False)
    def test_json_bad_enc(self,bilateral):
        # id1 encrypt for id1, but id2 cant decrypt id1
        c, result = json_encrypt(json_data,bilateral['id1'],sender,False)
        assert c and result
        d, encrypted, signed, result = json_decrypt(c,bilateral['id2'])
        assert (d, encrypted, signed, result.valid) == (None, True, False, False)
    def test_json_bad_encsign(self,bilateral):
        # id1 encrypt+sign for id1, but id2 cant decrypt id1
        c, result = json_encrypt(json_data,bilateral['id1'],sender,True)
        assert c and result
        d, encrypted, signed, result = json_decrypt(c,bilateral['id2'])
        assert (d, encrypted, signed, result.valid) == (None, True, True, False)
    def test_json_bad_encsign2(self,bilateral,gpgreceiver):
        # id1 encrypt+sign for id1, but id2 doesn't know id1
        c, result = json_encrypt(json_data,bilateral['id1'],sender,True)
        assert c and result
        d, encrypted, signed, result = json_decrypt(c,gpgreceiver)
        assert (d, encrypted, signed, result.valid) == (None, True, True, False)

    def table_io(self,ids,fmt,encrypt=False,sign=False,obj=False,
        missing=False,ignore=True,required=False,extra=False):
        from ekklesia.data import objects_equal
        columns = ('a','b','c')
        coltypes = {'a':int,'b':int,'c':int}
        t = DataTable(columns,coltypes=coltypes,gpg=ids['id1'],fileformat=fmt,ignore=ignore,required=required)
        if fmt in ('json','jsondict'): f = {}
        else: f = StringIO()
        t.open(f,'w',receiver if encrypt else False,sign)
        if obj:
            t.write(Obj(a=0))
            t.write(Obj(a=1))
        elif missing:
            try:
                t.write({'a':0,'b':2})
                assert ignore
            except:
                assert not ignore
                return
        elif extra:
            try:
                t.write({'a':0,'b':2,'c':3,'d':4})
                assert ignore
            except:
                assert not ignore
                return
        else:
            for i in range(3): t.write({'a':i,'b':2,'c':3})
        if fmt in ('json','jsondict'):
            f2 = t.close()
            assert f is f2
        else:
            t.close()
            f.seek(0)
        t = DataTable(columns,coltypes=coltypes,gpg=ids['id2'],fileformat=fmt)
        t.open(f,'r',encrypt,sender if sign else False)
        i = 0
        for row in t:
            if obj:
                assert objects_equal(Obj(**row),Obj(a=i))
            else:
                if missing: assert row == {'a':0,'b':2,'c':None}
                else: assert row == {'a':i,'b':2,'c':3}
            i+=1
        t.close()

    def test_table_json_plain(self,bilateral):
        self.table_io(bilateral,'json',encrypt=False,sign=False)
    def test_table_jsondict_plain(self,bilateral):
        self.table_io(bilateral,'jsondict',encrypt=False,sign=False)
    def test_table_json(self,bilateral):
        self.table_io(bilateral,'json',encrypt=True,sign=True)
    def test_table_jsonf_plain(self,bilateral):
        self.table_io(bilateral,'json-file',encrypt=False,sign=False)
    def test_table_jsondictf_plain(self,bilateral):
        self.table_io(bilateral,'jsondict-file',encrypt=False,sign=False)
    def test_table_jsonf(self,bilateral):
        self.table_io(bilateral,'json-file',encrypt=True,sign=True)
    def test_table_csv_plain(self,bilateral):
        self.table_io(bilateral,'csv',encrypt=False,sign=False)
    def test_table_csv_sign(self,bilateral):
        self.table_io(bilateral,'csv',encrypt=False,sign=True)
    def test_table_csv(self,bilateral):
        self.table_io(bilateral,'csv',encrypt=True,sign=True)

    def test_table_bad_init(self,bilateral):
        with raises(AssertionError): t = DataTable(('a',),fileformat='bad')

    def test_table_bad_open(self,bilateral):
        t = DataTable(('a',))
        with raises(AssertionError): t.open(StringIO(),'x')

    def test_table_bad_read(self,bilateral):
        t = DataTable(('a',))
        t.open(StringIO(),'w')
        with raises(AssertionError):
            for row in t: pass

    def test_table_bad_write(self,bilateral):
        t, f = DataTable(('a',)), StringIO()
        t.open(f,'w')
        t.write({'a':0})
        t.close()
        f.seek(0)
        t = DataTable(('a',))
        t.open(f,'r')
        with raises(AssertionError): t.write({'a':1})

    def test_table_obj(self,bilateral):
        self.table_io(bilateral,'json-file',obj=True)
    def test_table_obj_dict(self,bilateral):
        self.table_io(bilateral,'jsondict-file',obj=True)

    def test_table_miss(self,bilateral):
        self.table_io(bilateral,'csv',missing=True,ignore=True,required=False)
    def test_table_miss_ign(self,bilateral):
        self.table_io(bilateral,'csv',missing=True,ignore=False,required=False)
    def test_table_miss_req(self,bilateral):
        self.table_io(bilateral,'csv',missing=True,ignore=False,required=True)
    def test_table_extra(self,bilateral):
        self.table_io(bilateral,'csv',extra=True,ignore=False)
    def test_table_extra_ign(self,bilateral):
        self.table_io(bilateral,'csv',extra=True,ignore=True)

    #TODO: read string, bad version/format