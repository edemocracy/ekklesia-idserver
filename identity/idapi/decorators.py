# -*- coding: utf-8 -*-
#
# Views
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

"""
Decorators for views based on HTTP headers.
"""

import logging
from calendar import timegm
from functools import wraps

from django.utils.decorators import available_attrs
from django.utils.http import http_date, parse_http_date_safe, parse_etags, quote_etag
from django.http import HttpResponseNotModified, HttpResponse

logger = logging.getLogger('django.request')

def condition(etag_func=None, last_modified_func=None, update=("PATCH", "PUT")):
    """
    Decorator to support conditional retrieval (or change) for a view
    function.

    The parameters are callables to compute the ETag and last modified time for
    the requested resource, respectively. The callables are passed the same
    parameters as the view itself. The Etag function should return a string (or
    None if the resource doesn't exist), whilst the last_modified function
    should return a datetime object (or None if the resource doesn't exist).

    If both parameters are provided, all the preconditions must be met before
    the view is processed.
    see http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.24

    This decorator will either pass control to the wrapped view function or
    return an HTTP 304 response (unmodified) or 412 response (preconditions
    failed), depending upon the request method.

    Any behavior marked as "undefined" in the HTTP spec (e.g. If-none-match
    plus If-modified-since headers) will result in the view function being
    called.

    The update parameter specifies for which methods (default: PATCH and PUT)
    the response header should be updated with the latest values.
    Otherwise the initial values are kept.
    see http://tools.ietf.org/id/draft-reschke-http-etag-on-write-09.txt
    """
    def decorator(func):
        @wraps(func, assigned=available_attrs(func))
        def inner(request, *args, **kwargs):
            # Get HTTP request headers
            if_modified_since = request.META.get("HTTP_IF_MODIFIED_SINCE")
            if if_modified_since:
                if_modified_since = parse_http_date_safe(if_modified_since)
            if_unmodified_since = request.META.get("HTTP_IF_UNMODIFIED_SINCE")
            if if_unmodified_since:
                if_unmodified_since = parse_http_date_safe(if_unmodified_since)
            if_none_match = request.META.get("HTTP_IF_NONE_MATCH")
            if_match = request.META.get("HTTP_IF_MATCH")
            etags = []
            if if_none_match or if_match:
                # There can be more than one ETag in the request, so we
                # consider the list of values.
                try:
                    etags = parse_etags(if_none_match or if_match)
                except ValueError:
                    # In case of invalid etag ignore all ETag headers.
                    # Apparently Opera sends invalidly quoted headers at times
                    # (we should be returning a 400 response, but that's a
                    # little extreme) -- this is Django bug #10681.
                    if_none_match = None
                    if_match = None

            def get_etag():
                # Compute values (if any) for the requested resource.
                if etag_func:
                    return etag_func(request, *args, **kwargs)
            def get_last_modified():
                if last_modified_func:
                    dt = last_modified_func(request, *args, **kwargs)
                    if dt:
                        return timegm(dt.utctimetuple())

            res_etag = get_etag()
            res_last_modified = get_last_modified()

            response = None
            if not ((if_match and if_modified_since) or
                    (if_none_match and if_unmodified_since) or
                    (if_modified_since and if_unmodified_since) or
                    (if_match and if_none_match)):
                # We only get here if no undefined combinations of headers are
                # specified.
                if ((if_none_match and (res_etag in etags or
                        "*" in etags and res_etag)) and
                        (not if_modified_since or
                            (res_last_modified and if_modified_since and
                            res_last_modified <= if_modified_since))):
                    if request.method in ("GET", "HEAD"):
                        response = HttpResponseNotModified()
                    else:
                        logger.warning('Precondition Failed: %s', request.path,
                            extra={
                                'status_code': 412,
                                'request': request
                            }
                        )
                        response = HttpResponse(status=412)
                elif (if_match and ((not res_etag and "*" in etags) or
                        (res_etag and res_etag not in etags) or
                        (res_last_modified and if_unmodified_since and
                        res_last_modified > if_unmodified_since))):
                    logger.warning('Precondition Failed: %s', request.path,
                        extra={
                            'status_code': 412,
                            'request': request
                        }
                    )
                    response = HttpResponse(status=412)
                elif (not if_none_match and request.method == "GET" and
                        res_last_modified and if_modified_since and
                        res_last_modified <= if_modified_since):
                    response = HttpResponseNotModified()
                elif (not if_match and
                        res_last_modified and if_unmodified_since and
                        res_last_modified > if_unmodified_since):
                    logger.warning('Precondition Failed: %s', request.path,
                        extra={
                            'status_code': 412,
                            'request': request
                        }
                    )
                    response = HttpResponse(status=412)

            if response is None:
                response = func(request, *args, **kwargs)

            # Set relevant headers on the response if they don't already exist.
            if not response.has_header('Last-Modified'):
                if request.method in update:
                    res_last_modified = get_last_modified()
                if res_last_modified:
                    response['Last-Modified'] = http_date(res_last_modified)

            if not response.has_header('ETag'):
                if request.method in update:
                    res_etag = get_etag()
                if res_etag:
                    response['ETag'] = quote_etag(res_etag)

            return response

        return inner
    return decorator
