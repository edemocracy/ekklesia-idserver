from __future__ import with_statement
from alembic import context
from sqlalchemy import create_engine, pool
from logging.config import fileConfig
import logging
import re
import os

USE_TWOPHASE = False

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# gather section names referring to different
# databases.  These are named "engine1", "engine2"
# in the sample .ini file.
db_names = config.get_main_option('databases')

# add your model's MetaData objects here
# for 'autogenerate' support.  These must be set
# up to hold just those tables targeting a
# particular database. table.tometadata() may be
# helpful here in case a "copy" of
# a MetaData is needed.
# from myapp import mymodel
# target_metadata = {
#       'engine1':mymodel.metadata1,
#       'engine2':mymodel.metadata2
#}
databases = {}

from sqlalchemy.ext.declarative import declarative_base, DeferredReflection
args = context.get_x_argument(as_dictionary=True)

if 'members' in db_names:
    from ekklesia.backends.members import MemberDatabase
    db = MemberDatabase()
    db.load_config(args.get('memberconfig'))
    if not db.database:
        db.database = config.get_section_option('members',"sqlalchemy.url")
    db.Base = declarative_base() #cls=DeferredReflection
    db.declare(False)
    databases['members'] = db

if 'invitations' in db_names:
    from ekklesia.backends.invitations import InvitationDatabase
    db = InvitationDatabase()
    db.load_config(args.get('invconfig'))
    if not db.database:
        db.database = config.get_section_option('invitations',"sqlalchemy.url")
    db.Base = declarative_base()
    db.declare(False)
    databases['invitations'] = db

if 'joint' in db_names:
    from ekklesia.backends.joint import MemberInvDatabase
    db = MemberInvDatabase()
    db.load_config(args.get('jointconfig'))
    if not db.database:
        db.database = config.get_section_option('joint',"sqlalchemy.url")
    db.Base = declarative_base()
    db.declare(False)
    databases['joint'] = db

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    # for the --sql use case, run migrations for each URL into
    # individual files.

    version_file = os.path.join(os.path.dirname(config.config_file_name), "version.txt")
    if os.path.exists(version_file):
        current_version = open(version_file).read()
    else:
        current_version = None

    for name, db in databases.items():
        logger.info("Migrating database %s" % name)
        file_ = "%s.sql" % name
        logger.info("Writing output to %s" % file_)
        with open(file_, 'w') as buffer:
            context.configure(url=db.database, output_buffer=buffer,
                                target_metadata=db.Base.metadata,
                                starting_rev=current_version,
                                render_as_batch=True,
            )
            with context.begin_transaction():
                context.run_migrations(engine_name=name)

    end_version = context.get_revision_argument()
    if end_version and end_version != current_version:
        open(version_file, 'w').write(end_version)

def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # for the direct-to-DB use case, start a transaction on all
    # engines, then run all migrations, then commit all transactions.

    engines = {}
    for name, db in databases.items():
        engines[name] = rec = {}
        rec['engine'] = create_engine(db.database, poolclass=pool.NullPool)

    for name, rec in engines.items():
        engine = rec['engine']
        rec['connection'] = conn = engine.connect()

        if USE_TWOPHASE:
            rec['transaction'] = conn.begin_twophase()
        else:
            rec['transaction'] = conn.begin()

    try:
        for name, db in databases.items():
            logger.info("Migrating database %s" % name)
            rec = engines[name]
            context.configure(
                        connection=rec['connection'],
                        upgrade_token="%s_upgrades" % name,
                        downgrade_token="%s_downgrades" % name,
                        target_metadata=db.Base.metadata,
                        render_as_batch=True,
                    )
            context.run_migrations(engine_name=name)

        if USE_TWOPHASE:
            for rec in engines.values():
                rec['transaction'].prepare()

        for rec in engines.values():
            rec['transaction'].commit()
    except:
        for rec in engines.values():
            rec['transaction'].rollback()
        raise
    finally:
        for rec in engines.values():
            rec['connection'].close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
