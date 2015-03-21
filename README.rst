.. image:: https://travis-ci.org/edemocracy/ekklesia.png?branch=master
    :target: https://travis-ci.org/edemocracy/ekklesia
    :alt: Build status

.. image:: https://coveralls.io/repos/edemocracy/ekklesia/badge.png
    :target: https://coveralls.io/r/edemocracy/ekklesia
    :alt: Coverage

Ekklesia
========

Ekklesia is a framework for building large-scale, deliberative, direct and electronic democracies.

Its focus are privacy, security and deliberation.

This project is in an early state and not yet fully implemented.
So far is the main audience are developers.

The code is licensed under the Affero GNU Public License.
For other licenses please contact the authors.

This repository contains only (mostly) fully implemented and/or tested components.
Further components will be added as soon as their are stable.

Some client applications compatible with the Ekklesia ID server are:

- `Portal <https://github.com/basisentscheid/portal>`_
- `Anonymous voting <https://github.com/pfefffer/vvvote>`_

Disclaimer
~~~~~~~~~~

This software comes with ABSOLUTELY NO WARRANTY. USE THIS SOFTWARE AT YOUR OWN RISK.

Authors
~~~~~~~
Thomas T.    ekklesia at heterarchy.net

Installation
~~~~~~~~~~~~

From this git repository
^^^^^^^^^^^^^^^^^^^^^^^^

To install this package from this git repository, do::

    git clone https://github.com/edemocracy/ekklesia.git
    cd ekklesia
    make install

To test this package, do::

    make test


Bug Reports & Feature Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is a `bugtracker <https://github.com/edemocracy/ekklesia/issues>`__ on Github.

For direct WSGI with manage.py runserver behind a SSL proxy you need to
fix Python 2.7 lib/wsgiref/simple_server.py line 99-100 with

    for k,v in self.headers.dict.items():
        k=k.replace('-','_').upper(); v=v.strip()
