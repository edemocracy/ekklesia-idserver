# -*- coding: utf-8 -*-
#
# AMQP
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

def parse_broker(broker):
    from six.moves.urllib.parse import urlsplit, urlunsplit, parse_qs
    from six import iteritems
    import ssl
    parsed = urlsplit(broker)
    query = parse_qs(parsed.query)
    url = list(parsed)
    if parsed.scheme=='amqps':
        if not parsed.port: url[1] += ':5671'
        url[0] = 'pyamqp'
        sslopt, opts = {}, {}
        for key,value in iteritems(query):
            value = value[0]
            if key=='ssl_version':
                value = dict(TLSv1=ssl.PROTOCOL_TLSv1,TLSv1_1=ssl.PROTOCOL_TLSv1_1,
                    TLSv1_2=ssl.PROTOCOL_TLSv1_2)[value]
            elif key=='ssl_validation':
                value = dict(ignore=ssl.CERT_NONE,optional=ssl.CERT_OPTIONAL,
                    required=ssl.CERT_REQUIRED)[value]
                key = 'cert_reqs'
            else:
                 k = dict(ssl_cacert='ca_certs',ssl_cert='certfile',ssl_key='keyfile').get(key)
                 if not k:
                    opts[key] = value
                    continue
                 key = k
            sslopt[key] = value
        opts['ssl'] = sslopt
        query = opts
    elif parsed.scheme=='amqp':
        url[0] = 'pyamqp'
    url[3] = None
    return urlunsplit(url), query
