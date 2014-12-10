#!/usr/bin/env python
# coding: utf-8
#
# generic database template
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

"""
Requirements: Python >=2.7, sqlalchemy, gnupg, requests
"""

from __future__ import print_function, absolute_import
from ekklesia.mail import gpg_defaults, gpg_init
from ekklesia import FormattedWarning
import six

class FileMissingWarning(FormattedWarning): pass
class UnknownFieldsWarning(FormattedWarning): pass

def spec_defaults(spec):
    import configobj, validate
    cfg = configobj.ConfigObj(spec.splitlines(), encoding='UTF8', list_values=False, _inspec=True)
    val = validate.Validator()
    defaults = {}
    for section,items in cfg.iteritems():
        sdefaults = {}
        for k,v in items.iteritems():
            try: d = val.get_default_value(v)
            except KeyError: d = None
            sdefaults[k] = d
        defaults[section] = sdefaults
    return defaults

from collections import namedtuple

api_spec="""
[api]
user = string
password = string
digest = boolean(default=False)
url = string
format = string(default='json')
ca_certs = string
cert = stringlist
encrypt = boolean(default=False)
sign = boolean(default=False)
receiver = string
"""

api_defaults = spec_defaults(api_spec)['api']
APIConfig = namedtuple("APIConfig", api_defaults.keys())

def api_init(config,**kwargs):
    import requests
    tmp = api_defaults.copy()
    tmp.update(config)
    config = tmp
    api = requests.Session(**kwargs)
    if config['user']:
        if config['digest']:
            api.auth = requests.auth.HTTPDigestAuth(config['user'], config['password'])
        else:
            api.auth = (config['user'], config['password'])
    cacerts = config['ca_certs']
    if cacerts == '': api.verify = False
    elif cacerts: api.verify = str(cacerts)
    cert = config['cert']
    if cert and (type(cert)==str or len(cert)==2): api.cert = cert
    return api

def reflect_class(cls):
    "get columns names (excluding primary and foreign keys) and types"
    columns = cls.__table__.columns
    allcols = [c.name for c in columns]
    ctypes = []
    for c in columns:
        try: t = c.type.python_type
        except: t = str # fails for ENUM
        ctypes.append(t)
    types = dict(zip(allcols,ctypes))
    cols = [c.name for c in columns if not c.foreign_keys]
    return cols, types

class AbstractDatabase(object):

    def __init__(self,config={},gpgconfig=gpg_defaults,logger=None):
        self.gpgconfig = gpgconfig
        self.log = logger
        self.gpgbackend = None
        self.gpg = None
        self.verbose = True
        self.debugging = False
        self.session = None
        self.database = config.get('database','sqlite:///:memory:')
        self.column_map = config.get('column_map',{}) # {table:{dbkey:appkey}}

    def debug(self, msg, *args, **kwargs):
        if self.log: self.log.debug(msg, *args, **kwargs)
        elif self.debugging: print('DEBUG:',msg % args)

    def info(self, msg, *args, **kwargs):
        if self.log: self.log.info(msg, *args, **kwargs)
        elif self.verbose: print('INFO:',msg % args)

    def warn(self, msg, *args):
        if self.log: self.log.warning(msg, *args)
        else:
            import warnings
            warnings.warn(msg, *args)

    def error(self, msg, *args, **kwargs):
        if self.log: self.log.error(msg, *args, **kwargs)
        else: print('ERROR:',msg % args)

    def critical(self, msg, *args, **kwargs):
        if self.log: self.log.critical(msg, *args, **kwargs)
        else: print('CRITICAL:',msg % args)

    def exception(self, msg, *args):
        import sys
        if self.log: self.log.exception(msg, *args)
        else: print('EXCEPTION:',msg % args, sys.exc_info())

    def init_parser_main(self,name,description):
        import argparse, logging
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("-d", "--debug", metavar='LEVEL', action="store", default=logging.NOTSET, help="set logging level (debug,info,warning,error,critical,none)")
        parser.add_argument("-l","--logfile",metavar='LOG',help='logfile (appended)')
        parser.add_argument("-n", "--dry-run", action="store_true", dest="dryrun", default=False, help="simulate and don't modify the database")
        parser.add_argument("-v", "--verbose", action="store_const", dest='debug', const=logging.INFO, help="be verbose")
        subparsers = parser.add_subparsers(dest='command',help='sub-command help')
        return parser, subparsers

    def init_parser_init(self,subparsers):
        parser = subparsers.add_parser('init', help='initialize the database')
        parser.add_argument("-i","--initial",metavar='INIT',help='file with initial data')
        return parser

    def init_parser_drop(self,subparsers):
        parser = subparsers.add_parser('drop', help='delete all database contents')
        return parser

    def init_parser_import(self,subparsers):
        parser = subparsers.add_parser('import', help='import data')
        parser.add_argument("-a", "--all", action="store_true", default=False, help="require import of all fields")
        parser.add_argument("-d", "--decrypt", action="store_true", default=False, help="decrypt data")
        parser.add_argument("-v", "--verify", action="store_true", default=False, help="verify signature of data (required if signed)")
        parser.add_argument("-s", "--sync", action="store_true", default=False, help="keep only imported data")
        parser.add_argument("file",help='file with data')
        return parser

    def init_parser_export(self,subparsers):
        parser = subparsers.add_parser('export', help='export data')
        parser.add_argument("-e", "--encrypt", action="store_true", default=False, help="encrypt data")
        parser.add_argument("-s", "--sign", action="store_true", default=False, help="sign data")
        parser.add_argument("-a", "--all", action="store_true", default=False, help="export all fields")
        parser.add_argument("file",help='output file')
        return parser

    def init_parser_sync(self,subparsers):
        parser = subparsers.add_parser('sync', help='sync with server')
        parser.add_argument("-d", "--download", action="store_false", default=True, help="don't download members to sync, but sync all")
        parser.add_argument("-u", "--upload", action="store_false", default=True, help="don't upload member data")
        parser.add_argument("-i","--input",metavar='IN',help='file with uuids to sync')
        parser.add_argument("-o","--output",metavar='OUT',nargs='+',help='output file(s)')
        return parser

    def init_parsers(self,name,description):
        parser, subparsers = self.init_parser_main(name,description)
        self.init_parser_init(subparsers)
        self.init_parser_drop(subparsers)
        self.init_parser_import(subparsers)
        self.init_parser_export(subparsers)
        self.init_parser_sync(subparsers)
        return parser, subparsers

    def declare(self,reflect=True): pass

    def reflect_classes(self): pass

    def open_db(self,engine,mode='open'):
        "mode: create, open, drop"
        from sqlalchemy.ext.declarative import declarative_base, DeferredReflection
        from sqlalchemy.schema import MetaData, DropConstraint
        from sqlalchemy import event, Table
        if mode!='open':
            # Clear out any existing tables
            metadata = MetaData(engine)
            metadata.reflect()
            if engine.name != 'sqlite':
                for table in metadata.tables.values():
                    for fk in table.foreign_keys:
                        engine.execute(DropConstraint(fk.constraint))
            metadata.drop_all(engine)
            if mode=='drop': return
        self.Base = declarative_base(cls=DeferredReflection)
        self.Base.metadata.bind = engine
        if mode=='open':
            @event.listens_for(Table, "column_reflect")
            def column_reflect(inspector, table, column_info):
                if table.metadata is self.Base.metadata:
                    if self.column_map and table.name in self.column_map:
                        column_info['key'] = self.column_map[table.name][column_info['name']]
                    else:
                        column_info['key'] = column_info['name']
        self.declare(reflect= mode=='open')
        if mode=='create': self.Base.metadata.create_all(engine)
        from sqlalchemy.orm import sessionmaker
        self.Base.prepare(engine)
        self.reflect_classes()
        Session = sessionmaker(bind=engine)
        self.session = Session()

    def setlogger(self,name,level=None,logfile=None):
        import logging
        if not level: level = logging.NOTSET
        elif type(level)==str:
            slevel = getattr(logging, level.upper(), None)
            if slevel is None:
                try: slevel = int(level)
                except ValueError: raise "invalid debug level %s" % level
            level = slevel
        #self.verbose = args.debug >= logging.INFO
        self.debugging = level == logging.DEBUG

        logging.captureWarnings(level <= logging.WARNING)
        if logfile:
            import logging.handlers
            h = logging.handlers.WatchedFileHandler(logfile) # support rotation
        else:
            h = logging.StreamHandler()
        fmt = '%(asctime)s %(levelname)s %(name)s %(message)s' #logging.BASIC_FORMAT
        h.setFormatter(logging.Formatter(fmt))
        h.setLevel(level)
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(h)
        self.log = logger
        logger = logging.getLogger('sqlalchemy')
        logger.addHandler(h)
        logger.setLevel(level)
        logger = logging.getLogger('gnupg')
        #print(logging.Logger.manager.loggerDict,logger.handlers)
        logger.addHandler(h)
        logger.setLevel(level)
        logger = logging.getLogger('py.warnings')
        logger.addHandler(h)

        if not self.debugging: return
        import requests
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1
        # You must initialize logging, otherwise you'll not see debug output.
        logger = logging.getLogger("requests.packages.urllib3")
        logger.addHandler(h)
        logger.setLevel(level)
        logger.propagate = True

    def init_run(self,name,description,args=None):
        from sqlalchemy import create_engine
        import gnupg
        parser, subparsers = self.init_parsers(name,description)
        args = parser.parse_args(args)
        self.setlogger(name,args.debug,args.logfile)
        try:
            self.gpgbackend, self.gpg = gpg_init(self.gpgconfig,verbose='basic' if self.debugging else False)
            #if self.debugging: gnupg._logger.create_logger(10)
        except:
            self.gpgbackend, self.gpg = None, None
        if not self.gpg:
            self.warn('GnuPG not available')
        engine = create_engine(self.database,echo=False) #, echo=self.debugging
        return args, engine, parser

# from http://stackoverflow.com/questions/2676133/best-way-to-do-enum-in-sqlalchemy
from sqlalchemy.types import SchemaType, TypeDecorator, Enum
from sqlalchemy.util import set_creation_order, OrderedDict

class EnumSymbol(object):
    """Define a fixed symbol tied to a parent class."""

    def __init__(self, value, description=None):
        self.value = value
        self.description = description
        set_creation_order(self)

    def bind(self, cls, name):
        """Bind symbol to a parent class."""
        self.cls = cls
        self.name = name
        setattr(cls, name, self)

    def __reduce__(self):
        """Allow unpickling to return the symbol linked to the DeclEnum class."""
        return getattr, (self.cls, self.name)

    def __iter__(self):
        return iter([self.value, self.description])

    def __repr__(self):
        return "<%s>" % self.name
        #return repr(self.name)

    def __eq__(self,other):
        return self.name == str(other)

    def __ne__(self,other):
        return self.name != str(other)

    def __str__(self):
        return self.name

    def __unicode__(self):
        return self.name

class DeclEnumMeta(type):
    """Generate new DeclEnum classes."""

    def __init__(cls, classname, bases, dict_):
        reg = cls._reg = cls._reg.copy()
        for k in sorted(dict_):
            if k.startswith('__'):
                continue
            v = dict_[k]
            if isinstance(v, six.string_types):
                v = EnumSymbol(v)
            elif isinstance(v, tuple) and len(v) == 2:
                v = EnumSymbol(*v)
            if isinstance(v, EnumSymbol):
                v.bind(cls, k)
                reg[k] = v
        reg.sort(key=lambda k: reg[k]._creation_order)
        return type.__init__(cls, classname, bases, dict_)

    def __iter__(cls):
        return iter(cls._reg.values())


class DeclEnum(six.with_metaclass(DeclEnumMeta,object)):
    """Declarative enumeration.

    Attributes can be strings (used as values),
    or tuples (used as value, description) or EnumSymbols.
    If strings or tuples are used, order will be alphabetic,
    otherwise order will be as in the declaration.

    """
    _reg = OrderedDict()

    @classmethod
    def names(cls):
        return cls._reg.keys()

    @classmethod
    def db_type(cls):
        return DeclEnumType(cls)


class DeclEnumType(SchemaType, TypeDecorator):
    """DeclEnum augmented so that it can persist to the database."""

    def __init__(self, enum):
        import re
        self.enum = enum
        self.impl = Enum(*enum.names(), name="ck%s" % re.sub(
            '([A-Z])', lambda m: '_' + m.group(1).lower(), enum.__name__))

    def _set_table(self, table, column):
        self.impl._set_table(table, column)

    def copy(self):
        return DeclEnumType(self.enum)

    def process_bind_param(self, value, dialect):
        if isinstance(value, EnumSymbol):
            value = value.name
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return getattr(self.enum, value.strip())
