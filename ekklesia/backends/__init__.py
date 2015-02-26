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
from collections import namedtuple
import six, contextlib

class FileMissingWarning(FormattedWarning): pass
class UnknownFieldsWarning(FormattedWarning): pass

def spec_defaults(spec):
    "get default values form a ConfigObj specification"
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

def api_spec(name='api'):
    "return specification for a REST API access"
    return """
[%s]
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
""" % name

api_defaults = spec_defaults(api_spec())['api']
APIConfig = namedtuple("APIConfig", api_defaults.keys())

def api_init(config,**kwargs):
    "setup requests session for a REST API. kwargs= extra options"
    import requests
    tmp = api_defaults.copy()
    tmp.update(config)
    config = tmp
    api = requests.Session(**kwargs)
    if config['user']:
        if config['digest']: # pragma: no cover
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
        if isinstance(c.type,DeclEnumType): t = str
        else: t = c.type.python_type
        ctypes.append(t)
    types = dict(zip(allcols,ctypes))
    cols = [c.name for c in columns if not c.foreign_keys]
    return cols, types

@contextlib.contextmanager
def dummy_context(): yield

class session_context(object):
    def __init__(self,db): self.db = db
    def __enter__(self): pass
    def __exit__(self, et, ev, t): # pragma: no cover
        if self.db.session: self.db.session.close()
        if not et: return False
        self.db.error('exception raised',exc_info=(et, ev, t))
        return True

def _drop_all(metadata):
    "drop all tables in metadata from database"
    from sqlalchemy.schema import DropConstraint
    engine = metadata.bind
    if engine.name != 'sqlite': # pragma: no cover
        for table in metadata.tables.values():
            for fk in table.foreign_keys:
                engine.execute(DropConstraint(fk.constraint))
    metadata.drop_all(engine)

class AbstractDatabase(object):
    "a template for database apps"

    def __init__(self, *args, **kwargs):
        self.log = None # logger
        self.handler = None # logging handler
        self.gpgconfig = None
        self.gpgbackend = None # gnupg
        self.gpg = None # GPGMime
        self.verbose = True
        self.debugging = False
        self.session = None # db session
        self.database = None # engine url
        self.column_map = {}
        self.connection = None # amqp connection
        self.terminated = False # for push

    def configure(self,config={},gpgconfig=gpg_defaults):
        "basic configuration"
        self.gpgconfig = gpgconfig
        self.database = config.get('database') or 'sqlite:///:memory:'
        self.column_map = config.get('column_map',{}) # {table:{dbkey:appkey}}
        return self

    def get_configuration(self,spec,args,fname=None):
        "load configuration from file or defaults"
        import os, configobj, validate
        cfgfile = args.config
        if not cfgfile:
            cfgfile = fname
            if not os.path.exists(cfgfile):
                cfgfile = os.path.join(os.getenv('HOME'),'.'+fname)
                if not os.path.exists(cfgfile):
                    self.warn('configuration file not found')
                    cfgfile = None
        if cfgfile:
            config = configobj.ConfigObj(cfgfile, configspec=spec.split('\n'),encoding='UTF8')
            config.validate(validate.Validator())
        else:
            config = spec_defaults(spec)
        if not config['gnupg']['home']:
            config['gnupg']['home'] = os.path.join(os.getenv('HOME'),'.gnupg')
        else:
            config['gnupg']['home'] = os.path.expanduser(config['gnupg']['home'])
        return config

    def terminate(self, signal, frame): # pragma: no cover
        "signal handler for push termination"
        self.info('terminating: signal %s',signal)
        if self.connection: self.connection.close()
        self.terminated = True

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
            if isinstance(msg,Warning):
                warnings.warn(msg, *args)
            else:
                print('WARNING:',msg % args)

    def error(self, msg, *args, **kwargs):
        if self.log: self.log.error(msg, *args, **kwargs)
        else:
            print('ERROR:',msg % args)
            exc_info = kwargs.get('exc_info')
            if not exc_info: return
            import traceback
            for line in traceback.format_exception(*exc_info):
                print ('ERROR:',line.rstrip())

    def critical(self, msg, *args, **kwargs):
        if self.log: self.log.critical(msg, *args, **kwargs)
        else: print('CRITICAL:',msg % args)

    def exception(self, msg, *args):
        import sys
        if self.log: self.log.exception(msg, *args)
        else:
            print('EXCEPTION:',msg % args)
            import traceback
            for line in traceback.format_exception(*sys.exc_info()):
                print ('EXCEPTION:',line.rstrip())

    def init_parser_main(self,name,description):
        import argparse, logging
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("-C", "--config",metavar='CONFIG',help='configuration file')
        parser.add_argument("-d", "--debug", metavar='LEVEL', action="store", default=logging.NOTSET, help="set logging level (debug,info,warning,error,critical,none)")
        parser.add_argument("-l", "--logfile",metavar='LOG',help='logfile (appended)')
        parser.add_argument("-n", "--dry-run", action="store_true", dest="dryrun", default=False, help="simulate and don't modify the database")
        parser.add_argument("-v", "--verbose", action="store_const", dest='debug', const=logging.INFO, help="be verbose")
        subparsers = parser.add_subparsers(dest='command',help='sub-command help')
        return parser, subparsers

    def init_parser_init(self,subparsers):
        parser = subparsers.add_parser('init', help='initialize the database')
        parser.add_argument("-d", "--drop", action="store_true", default=False, help="drop tables before init")
        parser.add_argument("-a", "--all", action="store_true", default=False, help="drop all tables in the database")
        parser.add_argument("-i","--initial",nargs="+",metavar='INIT',help='file(s) with initial data')
        return parser

    def init_parser_import(self,subparsers, withfile=True):
        parser = subparsers.add_parser('import', help='import data')
        parser.add_argument("-a", "--all", action="store_true", default=False, help="require import of all fields")
        parser.add_argument("-d", "--decrypt", action="store_true", default=False, help="decrypt data")
        parser.add_argument("-v", "--verify", action="store_true", default=False, help="verify signature of data (required if signed)")
        parser.add_argument("-s", "--sync", action="store_true", default=False, help="keep only imported data")
        if withfile:
            parser.add_argument("file",help='file with data')
        return parser

    def init_parser_export(self,subparsers, withfile=True):
        parser = subparsers.add_parser('export', help='export data')
        parser.add_argument("-e", "--encrypt", action="store_true", default=False, help="encrypt data")
        parser.add_argument("-s", "--sign", action="store_true", default=False, help="sign data")
        parser.add_argument("-a", "--all", action="store_true", default=False, help="export all fields")
        if withfile:
            parser.add_argument("file",help='output file')
        return parser

    def init_parser_push(self,subparsers):
        parser = subparsers.add_parser('push', help='push sync on updates')
        parser.add_argument("-u", "--upload", action="store_false", default=True, help="don't upload member data")
        parser.add_argument("-D", "--daemon", action="store_true", help="run as background daemon")
        parser.add_argument("-p", "--pid",metavar='PID',help='pid file')
        parser.add_argument("-w", "--wait",metavar='DELAY',type=int, default=0,help='minimum delay between syncs')
        return parser

    def init_parser_sync(self,subparsers):
        parser = subparsers.add_parser('sync', help='sync with server')
        parser.add_argument("-d", "--download", action="store_false", default=True,
             help="don't download members to sync, but sync all")
        parser.add_argument("-u", "--upload", action="store_false", default=True, help="don't upload member data")
        parser.add_argument("-i", "--input",metavar='IN',help='file with uuids to sync')
        parser.add_argument("-o", "--output",metavar='OUT',nargs='+',help='output file(s)')
        parser.add_argument("-q", "--quick", action="store_true", help="synchronize only updates")
        return parser

    def init_parsers(self,name,description):
        parser, subparsers = self.init_parser_main(name,description)
        self.init_parser_init(subparsers)
        self.init_parser_import(subparsers)
        self.init_parser_export(subparsers)
        self.init_parser_push(subparsers)
        self.init_parser_sync(subparsers)
        return parser, subparsers

    def declare(self,reflect=True):
        "declare or reflect tables"

    def reflect_classes(self):
        "get column names and types of the tables"

    def drop_db(self):
        "drop the tables"
        if not self.session: return
        _drop_all(self.Base.metadata)

    def open_db(self,engine,mode='open'):
        """open the database with engine URL. possible modes:
        drop - drop own tables
        dropall - drop all tables
        create - create the tables
        open - reflect the existing tables
        """
        from sqlalchemy.ext.declarative import declarative_base, DeferredReflection
        from sqlalchemy.schema import MetaData
        from sqlalchemy import event, Table
        metadata = None
        @event.listens_for(Table, "column_reflect")
        def column_reflect(inspector, table, column_info):
            if table.metadata is metadata:
                if self.column_map and table.name in self.column_map:
                    column_info['key'] = self.column_map[table.name][column_info['name']]
                else:
                    column_info['key'] = column_info['name']
        if mode=='dropall':
            # Clear out any existing tables
            metadata = MetaData(engine)
            metadata.reflect()
            _drop_all(metadata)
            return
        self.Base = declarative_base(bind=engine, cls=DeferredReflection)
        metadata = self.Base.metadata
        self.declare(reflect= mode=='open')
        if mode=='drop':
            _drop_all(metadata)
            return
        if mode=='create':
            metadata.create_all(engine,checkfirst=False)
        from sqlalchemy.orm import sessionmaker
        self.Base.prepare(engine)
        self.reflect_classes()
        Session = sessionmaker(bind=engine)
        self.session = Session()

    def setlogger(self,name,level=None,logfile=None):
        "initialize the loggers and create one for app name"
        import logging
        if not level: level = logging.NOTSET
        elif type(level)==str:
            slevel = getattr(logging, level.upper(), None)
            if slevel is None:
                try: slevel = int(level)
                except ValueError: raise "invalid debug level %s" % level
            level = slevel
        self.verbose = level >= logging.INFO
        self.debugging = level == logging.DEBUG

        logging.captureWarnings(level <= logging.WARNING)
        if logfile:
            import logging.handlers
            h = logging.handlers.WatchedFileHandler(logfile) # support rotation
        else:
            h = logging.StreamHandler()
        self.handler = h
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
        logger.addHandler(h)
        if self.debugging: logger.setLevel(level)
        else: logger.setLevel(logging.ERROR) # gnupg is too noisy
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
        logger = logging.getLogger("requests.packages.urllib3")
        logger.addHandler(h)
        logger.setLevel(level)
        logger.propagate = True

    def stoplogger(self):
        "remove handlers. use when setlogger is called more than once (testing)"
        import logging
        if not self.handler or not self.log: return
        h = self.handler
        self.log.removeHandler(h)
        for name in ('sqlalchemy','gnupg','py.warnings'):
            logging.getLogger(name).removeHandler(h)
        if not self.debugging: return
        logging.getLogger("requests.packages.urllib3").removeHandler(h)

    def prepare_daemon(self,pidfile): # pragma: no cover
        "setup daemon context and signal handlers"
        import signal, daemon, daemon.pidfile, logging, os
        pidfile = daemon.pidfile.PIDLockFile(pidfile) if pidfile else None
        context = daemon.DaemonContext(pidfile=pidfile, working_directory=os.getcwd())
        context.signal_map = {signal.SIGTERM: self.terminate, signal.SIGHUP: self.terminate}
        if self.log:
            context.files_preserve = []
            for handler in self.log.handlers:
                if not isinstance(handler,logging.StreamHandler): continue
                context.files_preserve.append(handler.stream)
        return context

    def get_broker(self): # pragma: no cover
        "get broker url and options"
        assert self.broker and self.broker_exchange and self.broker_queue, "broker not configured"
        from ekklesia.amqp import parse_broker
        url, opts = parse_broker(self.broker)
        return url, opts, self.broker_exchange, self.broker_queue

    def process_update(self,msg):
        "process push message"

    def push_sync(self,upload=True,delay=0,dryrun=False,timeout=None): # pragma: no cover
        "wait for push messages"
        from kombu import Connection, Exchange, Queue, Consumer
        import socket, ssl
        url, opts, exchange, queue = self.get_broker()
        def callback(body, message):
            self.process_update(body)
            message.ack()
        with Connection(url,**opts) as conn:
            self.connection = conn
            queue = Queue(queue, channel=conn)
            queue.queue_declare()
            queue.bind_to(exchange)
            with conn.Consumer(queue, accept=['json'], callbacks=[callback]) as consumer:
                while True:
                    try: conn.drain_events(timeout=timeout)
                    except socket.timeout: pass
                    except (socket.error, ssl.SSLZeroReturnError): break

    def init_run(self,name,description,args=None):
        "prepare run: set up arg parsers, parse args, set logger"
        import gnupg
        parser, subparsers = self.init_parsers(name,description)
        args = parser.parse_args(args)
        self.setlogger(name,args.debug,args.logfile)
        return args, parser

    def init_gnupg(self):
        "setup gnupg from gpgconfig"
        try:
            self.gpgbackend, self.gpg = gpg_init(self.gpgconfig,verbose='basic' if self.debugging else False)
            #if self.debugging: gnupg._logger.create_logger(10)
        except:
            self.exception('GnuPG not available')
            self.gpgbackend, self.gpg = None, None
        if not self.gpg:
            self.warn('GnuPG not available')

# based on http://stackoverflow.com/questions/2676133/best-way-to-do-enum-in-sqlalchemy
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
