# -*- coding: utf-8 -*-
#
# Data import/export
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

import csv
import contextlib

def tmpfname():
    "name of a permanent temporary file. don't forget to unlink!"
    import tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False)
    name = tmp.name
    tmp.close()
    return name

def init_object(obj, **kwargs):
    "set object attributes from args"
    from six import iteritems
    for key,value in iteritems(kwargs): setattr(obj,key,value)

def extract_object(obj,keys,replace={}):
    "get object attributes (keys), optionally overwrite with values in 'replace'"
    result = {}
    for key in keys:
        if key in replace: value=replace[key]
        else: value = getattr(obj,key)
        result[key] = value
    return result

def repr_object(obj,keys,replace={}):
    "repr for attributes 'keys', optionally replaced by value in 'replace'"
    result = obj.__class__.__name__+"("
    for key in keys:
        if key in replace: value=replace[key]
        else: value = getattr(obj,key)
        result += '%s=%s,' % (key,repr(value))
    return result[:-1]+')'

def objects_equal(a,b,keys=None):
    """check whether two objects share the same attributes objects.
    limit to 'keys' if specified, otherwise compares all except _*,special,methods etc"""
    if keys is None: # shallow equal
        import types
        special = (types.MethodType, types.FunctionType, types.BuiltinMethodType) #types.TypeType
        keysa, keysb = dir(a), dir(b)
        for key in keysa:
            value = getattr(a,key)
            if key[0]=='_' or isinstance(value,special): continue
            if not key in keysb or getattr(b,key) != value: return False
        for key in keysb:
            if key[0]=='_' or key in keysa: continue
            value = getattr(b,key)
            if not isinstance(value,special): return False
    else:
        a, b = vars(a), vars(b)
        for key in keys:
            if not key in a:
                if key in b: return False
            elif not key in b or a[key] != b[key]: return False
    return True

def human_token(length=6,chars="234679ADEFGHJKLMNPRTUW"):
    import random
    return ''.join(random.choice(chars) for _ in xrange(length))

def json_decrypt(data, gpg):
    "decodes a JSON PGP container and returns: data (None if error), encrypted, signed, gpgresult"
    if not data or not 'format' in data or not 'version' in data or data['format']!='pgp-container':
        return data, False, False, None
    version = data['version']
    if type(version) not in (tuple,list) or len(version)<2 or data['version'][0]>1:
        return None, False, False, None
    encrypted = data.get('encrypted',False)
    signed = data.get('signed',False)
    if not encrypted and not signed:
        return data.get('data',None), False, False, None
    if not encrypted and signed:
        sdata = data.get('signed_data',None)
        signature = data.get('signature',None)
        if not sdata or not signature: return None, False, True, None
        result = gpg.verify_str(sdata,signature)
        if result: data = sdata
        else: data = None
    else: # encrypt, opt. sign
        edata = data.get('encrypted_data',None)
        if not edata: return None, True, False, None
        result = gpg.decrypt_str(edata)
        if result and (not signed or result.valid): data = str(result)
        else: data = None
    import json
    if data: data = json.loads(data)
    return data, encrypted, signed, result

def json_encrypt(data, gpg, encrypt=False,sign=True, output=None):
    "return a JSON GPG container and result object, encrypt=bool or receivers keyid"
    import json
    if output is None: output = {}
    output.update({'format':'pgp-container','version':[1,0],'encrypted':bool(encrypt),'signed':sign})
    if not encrypt and not sign:
        output['data'] = data
        return output, None
    data = json.dumps(data) # nested JSON
    if not encrypt and sign:
        output['signed_data'] = data
        result = gpg.sign_str(data, clearsign=False, detach=True)
        if not result: return None, result
        output['signature'] = str(result)
    else: # encrypt, opt. sign
        result = gpg.encrypt_str(data, encrypt, sign=sign)
        if not result: return None, result
        output['encrypted_data'] = str(result)
    return output, result

def special_open(filename=None,mode='r'): # pragma: no cover
    import sys
    if filename and filename != '-':
        return open(filename, mode)
    elif 'w' in mode:
        return sys.stdout
    else:
        return sys.stdin

@contextlib.contextmanager
def special_openwith(filename=None,mode='r'): # pragma: no cover
    import sys
    special = True
    if filename and filename != '-':
        f = open(filename, mode)
        special = False
    elif 'w' in mode:
        f = sys.stdout
    else:
        f = sys.stdin
    try:
        yield f
    finally:
        if not special: f.close()

TIME_ISO8601 = "%H:%M:%S"
DATE_ISO8601 = "%Y-%m-%d"
DATETIME_ISO8601 = DATE_ISO8601+"T"+TIME_ISO8601

def decode_field(data,ftype):
    import datetime, time
    if data is None or data=='': return None
    if type(data)==ftype: return data
    if ftype==bool:
        if type(data)!=str: return bool(data)
        data = data.lower()
        if data in ('1','y','t','+','yes','true'): return True
        elif data in ('0','n','f','-','no','false'): return False
        return None
    elif ftype==int: return int(data)
    elif ftype==float: return float(data)
    elif ftype==datetime.date: return ftype(*time.strptime(data,DATE_ISO8601)[0:3])
    elif ftype==datetime.time: return ftype(*time.strptime(data,TIME_ISO8601)[3:6])
    elif ftype==datetime.datetime: return ftype(*time.strptime(data,DATETIME_ISO8601)[0:6])
    return data

def encode_field(data,ftype,format='csv'):
    import datetime
    if data is None: return None
    elif ftype==datetime.date: return data.strftime(DATE_ISO8601)
    elif ftype==datetime.time: return data.strftime(TIME_ISO8601)
    elif ftype==datetime.datetime: return data.strftime(DATETIME_ISO8601)
    elif ftype==str: return str(data)
    return data

class DataTable(object):
    """
    import/export for a database table with encryption support.

    parameters:
    columns = names of supported columns
    coltypes = and their Python types
    required = names of required columns or False/True for none/all
    remap = optional remapping (dict) of objfield->column name
    gpg = GPGMIME instance with default key
    dataformat = name of data format
    fileformat = csv (file), json (list), jsondict (key/value), json-file,jsondict-file
    version = the major version is required version for reading, 
        the minor version is the (backwards-compatible) version of the writer
    dialect = dialect for csv format (None=autodetect)
    ignore = write: fill missing data (except required) with '', read: ignore unknown fields

    import: open in 'r' mode, for row in table
    export: open in 'w' mode: table.write(row) 

    CSV based table file format:
    format major.minor
    field1,field2,...
    data1.1,data1.2,...
    data2.1,data2.2,...
    ...

    JSON: fields, data=[row1,row2,...]
    JSONdict: fields, data=[{key=value,...},...]
    """

    def __init__(self,columns,coltypes=None,required=True,ignore=True,remap=None,gpg=None,
        dataformat='data',fileformat='csv',version=(1,0),pretty=True,dialect=csv.excel):
        self.columns = columns # supported columns
        assert not coltypes or type(coltypes)==dict, 'invalid coltypes'
        assert fileformat in ('csv','json','jsondict','json-file','jsondict-file'), 'invalid fileformat'
        self.coltypes = coltypes # and their types
        self.required = required # required columns
        self.ignore = ignore # whether to ignore unknown fields
        if not remap: remap = {}
        self.remap = remap # optional remapping {field:objfield}
        self.gpg = gpg
        self.dialect = dialect # csv format
        self.pretty = pretty
        self.dataformat = dataformat
        self.fileformat = fileformat
        self.version = version
        self.mode = '' # r or w
        self.csv = None # csv reader/writer
        self.file = None # the file to read/write unencrypted data
        self.origfile = None # the actual input/output file
        self.encrypt = False # recipients or False
        self.sign = False # False=no, True=default_key, other=sender
        self.fields = None # fields provided by input
        self.read_columns = None # (fields to read, and to ignore)
        self.rows = None # tmp store for JSON

    def get_columns(self): return self.read_columns

    def open(self,f=None,mode='r',encrypt=False,sign=False):
        """write: encrypt = list of recipients, sign = sender or bool(default_key)
        read: encrypt = encrypted data expected, sign= expected key or True=defaultkey
        """
        from six.moves import StringIO
        from six import next, PY3, BytesIO
        self.mode,self.encrypt,self.sign = mode,encrypt,sign
        if self.required==True: self.required = self.columns
        if encrypt or sign: assert self.gpg, 'gpg not intialized'
        self.origfile = self.file = f
        assert mode in ('r','w'), 'invalid mode'
        if mode=='r':
            if sign:
                if sign==True:
                    fingerprint = self.gpg.default_key
                    if type(fingerprint) == tuple: fingerprint = fingerprint[0]
                else:
                    if type(sign) == tuple: sign = sign[0]
                    fingerprint = self.gpg.find_key(sign)
                assert fingerprint, "sender key not found"
            if self.fileformat=='csv':
                import re
                if encrypt:
                    if PY3 and isinstance(f,StringIO):
                        result = self.gpg.decrypt_str(f.getvalue())
                    else:
                        result = self.gpg.decrypt_file(f)
                    assert result.ok, "decryption failed"
                    if sign: assert result.valid and result.fingerprint==fingerprint, 'invalid signature'
                    f = StringIO(str(result))
                elif sign:
                    if PY3 and isinstance(f,StringIO):
                        result = self.gpg.verify_str(f.getvalue())
                        f = StringIO(self.gpg.without_signature(f.getvalue()))
                    else:
                        result = self.gpg.verify_file(f)
                        f.seek(0)
                        f = StringIO(self.gpg.without_signature(f.read()))
                    assert result.valid and result.fingerprint==fingerprint, 'invalid signature'
                self.file = f
                dialect = self.dialect
                if not dialect:
                    pos = f.tell()
                    dialect = csv.Sniffer().sniff(f.read(1024))
                    f.seek(pos) # rewind
                reader = csv.reader(f,dialect=dialect)
                preamble = next(reader)
                assert len(preamble), 'invalid file format'
                assert preamble[0]==self.dataformat, "file format not supported"
                preamble = re.match(r'^(\d+).(\d+)',preamble[1])
                assert int(preamble.group(2))<=self.version[0], "format version not supported"
                fields = next(reader)
                self.csv = reader
            else: # self.fileformat in ('json','jsondict','json-file','jsondict-file'):
                import json
                if self.fileformat in ('json-file','jsondict-file'):
                    self.file = f = json.load(f)
                data, encrypted, signed, result = json_decrypt(f,self.gpg)
                assert data, 'invalid input'
                if encrypt: assert encrypted==bool(encrypt), 'encryption expected'
                if sign:
                    assert signed==bool(sign), 'signature expected'
                    assert result.valid and result.fingerprint==fingerprint, 'invalid signature'
                assert 'format' in data and data['format']==self.dataformat, "file format not supported"
                assert 'version' in data and data['version'][0]<=self.version[0], "file version not supported"
                assert 'fields' in data , "fields missing"
                fields = data['fields']
                self.rows = data['data']
            columns, unknown = [], []
            for field in fields:
                if field in self.columns: columns.append(field)
                elif self.ignore: unknown.append(field)
                else: assert False, "unknown field '%s'" % field
            if self.required:
                for field in self.required:
                    assert field in columns, "missing required field '%s'" % field
            self.fields = fields
            self.read_columns = (columns,unknown)
        elif mode=='w':
            assert self.fileformat in ('json','jsondict') or self.file, 'file missing'
            if self.fileformat=='csv':
                if encrypt or sign: self.file = StringIO()
                else: self.file = f
                self.csv = csv.writer(self.file,lineterminator='\n',dialect=self.dialect)
                self.csv.writerow((self.dataformat,'%i.%i' % tuple(self.version)))
                self.csv.writerow(self.columns)
            else: # self.fileformat in ('json','jsondict'):
                self.rows = []

    def close(self):
        "close input/output. StringIO output is left open"
        if not self.mode: return
        if self.mode=='r':
            if self.fileformat=='csv' and self.encrypt: self.file.close() # close tmp buffer
            elif self.fileformat in ('json','jsondict'): return
        elif self.fileformat in ('json','jsondict','json-file','jsondict-file'):
            import json
            data = {'format':self.dataformat,'version':self.version,
                'fields':list(self.columns),'data':self.rows}
            if self.fileformat in ('json','jsondict'): output = self.file
            else: output = None
            if self.encrypt or self.sign:
                data, result = json_encrypt(data, self.gpg, output=output,
                     encrypt=self.encrypt,sign=self.sign)
                assert data and result,'encryption failed'
            elif not output is None:
                output.update(data)
                data = output
            if self.fileformat in ('json','jsondict'): return data
            if self.pretty:
                json.dump(data,self.file, sort_keys=True, indent=2, separators=(',', ': '))
            else:
                json.dump(data,self.file)
        elif self.encrypt or self.sign:
            from six import PY3, BytesIO, StringIO
            if PY3 and isinstance(self.file,StringIO):
                data = self.file.getvalue()
                if self.encrypt:
                    result = self.gpg.encrypt_str(data,self.encrypt,default_key=self.sign)
                else: #sign
                    result = self.gpg.sign_str(data)
            else:
                self.file.seek(0)
                if self.encrypt:
                    result = self.gpg.encrypt_file(self.file,self.encrypt,default_key=self.sign)
                else: #sign
                    result = self.gpg.sign_str(self.file)
            assert result, "encryption failed"
            self.origfile.write(str(result))
            self.file.close()
        from six.moves import cStringIO
        import sys
        if type(self.origfile) == type(cStringIO()): return
        if self.origfile == sys.stdout: return
        self.origfile.close()

    def __iter__(self):
        assert self.mode=='r', 'file not opened for reading'
        if self.fileformat=='csv': rows = self.csv
        else: rows = self.rows
        for row in rows:
            if self.fileformat=='csv':
                assert len(row) == len(self.fields),\
                 "invalid number of columns in line %i" % self.csv.line_num
            else:
                assert len(row) == len(self.fields), "invalid number of columns"
            data = {}
            for i,field in enumerate(self.fields):
                if not field in self.read_columns[0]: continue
                if self.fileformat in ('jsondict','jsondict-file'): x = row[field]
                else: x = row[i]
                if self.coltypes and field in self.coltypes:
                     x = decode_field(x,self.coltypes[field])
                ofield = self.remap.get(field,field)
                data[ofield] = x
            yield data

    def write(self,data,extra={}):
        "extra has precedence"
        assert self.mode=='w', 'file not opened for writing'
        if self.fileformat in ('jsondict','jsondict-file'): row = {}
        else: row = []
        for field in self.columns:
            x = None
            ofield = self.remap.get(field,field)
            if type(data)==dict: 
                if ofield in extra: x = extra[ofield]
                elif ofield in data: x = data[ofield]
                else: assert self.ignore or not field in self.required, "field '%s' missing"
            else:
                if ofield in extra: x = extra[ofield]
                elif hasattr(data,ofield): x = getattr(data,ofield)
                else: assert self.ignore or not field in self.required, "field '%s' missing"
            if self.coltypes and field in self.coltypes:
                x = encode_field(x,self.coltypes[field],self.fileformat)
            if self.fileformat in ('jsondict','jsondict-file'): row[field] = x
            else: row.append(x)
        if self.fileformat=='csv': self.csv.writerow(row)
        else: self.rows.append(row)
