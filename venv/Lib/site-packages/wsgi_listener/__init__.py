# -*- coding: utf-8 -*-

"""
WSGI listener middleware for WSGI Web Applications inspired by the
original wsgi-request-logger by Philipp Klaus and L. C. Rees.

Provides hooks during the request and response cycle by adding an extra level of indirection.

Instead of directly logging the response, this middleware provides an
interface to easily inspect the request and response. The default
behavior logs the response similarly to the original project. However, now
additional listeners can be added to both the request and response cycle. Additionally,
the request and response body content is part of the interface.

Original Homepage: https://github.com/pklaus/wsgi-request-logger

Copyright (c) 2019 Jonathan Fuller. All rights reserved.
Copyright (c) 2013, Philipp Klaus. All rights reserved.
Copyright (c) 2007-2011 L. C. Rees. All rights reserved.

License: BSD (see LICENSE for details)
"""
import logging
import time
from abc import ABC, abstractmethod
from io import BytesIO

from wsgi_listener.formatters import ApacheFormatter
from .formatters import ApacheFormatter
from .timehacks import Local

__all__ = ['WSGIListenerMiddleware', 'AbstractBaseRequestListener', 'AbstractBaseResponseListener']

__version__ = '0.1'

try:
    clock = time.perf_counter
except AttributeError:
    clock = time.time


DEFAULT_LISTENER_LOG_NAME = 'wsgilistener'


class AbstractBaseRequestListener(ABC):
    @abstractmethod
    def handle(self, environ: dict, request_body: bytes, **kwargs) -> None:
        """Defines the interface for Request listeners.

        Args:
            environ: The WSGI envion dictionary
            request_body: The bytes content of the request, if any
            **kwargs: Optional hook for additional data
        """
        pass


class AbstractBaseResponseListener(ABC):
    @abstractmethod
    def handle(self, status_code: int, environ: dict, content_length: int, response_body: bytes,
               processing_time: float, **kwargs) -> None:
        """Defines the interface for Response listeners.

        Args:
            status_code: HTTP status code as integer
            environ: WSGI environ dictionary
            content_length: Number of bytes returned as int
            response_body: The response content, if any
            processing_time: The time in miliseconds to process the request
            **kwargs: Extensible hook
        """
        pass


class WSGIListenerMiddleware(object):
    """Easily add request and response listeners as middleware.

    The :attr:`response_listeners` must implement the :class:`AbstractBaseRequestHandler` interface
    and the :attr:`response_listeners` must implement the :class:`AbstractBaseResponseListener` interface.

    These listeners DO NOT modify the request, but do receive the WSGI context per the above interfaces

    By default, requests are ignored and only responses are logged with the Apache formatter to std.err
    just like the original project. See :class:`DefaultResponseListener`.

    Attributes:
        app: The WSGI application to wrap, aka Flask
        request_listeners (:class:`AbstractBaseRequestListener`): An iterable of request handler objects.
            If none are provided the default behavior is do nothing.
        response_listeners (:class:`AbstractBaseResponseListener`): An iterable of response handler objects.
            If none are provided the default behavior is to log info messages using the Apache log format
            from the original wsgi-request-logger project.
    """

    def __init__(self, app, request_listeners=None, response_listeners=None, **kwargs):
        self.app = app
        self.request_listeners = request_listeners or []
        self.response_listeners = response_listeners or [DefaultResponseListener()]

    def __call__(self, environ, start_response):
        start = clock()
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size)
        environ['wsgi.input'] = BytesIO(request_body)  # reset request body for the nested app
        self._handle_request(environ, request_body)

        status_code = None
        content_length = None

        def custom_start_response(status, response_headers, exc_info=None):
            nonlocal content_length, status_code
            status_code = int(status.split()[0])

            for key, value in response_headers:
                if key.lower() == 'content-length':
                    content_length = int(value)
                    break
            return start_response(status, response_headers, exc_info)

        rv = self.app(environ, custom_start_response)
        processing_time = int((clock() - start) * 10 ** 6)
        response_body = b''.join(rv)
        content_length = content_length if content_length is not None else len(response_body)
        # noinspection PyTypeChecker
        self._handle_response(status_code, environ, content_length, response_body, processing_time)
        return BytesIO(response_body)  # rest response body for the wsgi interface

    def _handle_request(self, environ: dict, request_body: bytes, **kwargs):
        """Calls handle on all of the :attr:`self.request_listeners` passing the WSGI request data."""
        for handler in self.request_listeners:
            handler.handle(environ=environ, request_body=request_body, **kwargs)

    def _handle_response(self, status_code: int, environ: dict, content_length: int, response_body: bytes,
                         processing_time: float, **kwargs):
        """Calls handle on all of the :attr:`self.request_listeners` passing the WSGI request data."""
        for handler in self.response_listeners:
            handler.handle(status_code=status_code, environ=environ, content_length=content_length,
                           response_body=response_body, processing_time=processing_time, **kwargs)

    def add_request_listener(self, listener: AbstractBaseRequestListener):
        """Adds a listener to the :attr:`request_listeners` collection.

        Args:
            listener:
        """
        for handler in self.request_listeners:
            if handler is listener:
                logging.warning(f'A request listener, {listener}, has been added twice. Are you sure you wanted do that?')
                break
        self.request_listeners.append(listener)

    def add_response_listener(self, listener: AbstractBaseResponseListener):
        """Adds a listener to the :attr:`response_listeners` collection.

        Args:
            listener
        """
        for handler in self.response_listeners:
            if handler is listener:
                logging.warning(f'A response listener, {listener}, has been added twice. Are you sure you wanted do that?')
                break
        self.response_listeners.append(listener)


class DefaultListenerMixin:
    def __init__(self, logger: logging.Logger = None, handlers: logging.Handler = None,
                 formatter=ApacheFormatter(with_response_time=False),
                 ip_header=None):
        """Init for the default Listener object. The default behavior is to log info messages
        to the :attr:`logger` or if not provided create a new one called `wsgilistener`.

        If no log handlers are provided a default Stream handler is created (messages go to std.err).

        The formatter is a Callable whose interface matches the original
        :class:`wsgilistener.formatters.ApacheFormatters`

        Args:
            logger: The logger, defaults to 'wsgiinspector'
            handlers: Any handlers to add to the logger, defaults to stream handler
            formatter: The formatting callable
            ip_header: Optional additional kwarg for the formatter.
        """
        logger = logger or logging.getLogger(DEFAULT_LISTENER_LOG_NAME)
        handlers = handlers or [logging.StreamHandler()]
        for handler in handlers:
            logger.addHandler(handler)
        self.ip_header = ip_header
        self.logger = logger
        self.formatter = formatter or ApacheFormatter(with_response_time=False)


class DefaultRequestListener(DefaultListenerMixin, AbstractBaseRequestListener):
    """
    Logs requests with a bogus status code of 0 so we can use the original Apache Response formatter.
    See :class:`DefaultListenerMixin` for init signature.

    :class:`WSGIListenerMiddleware` does not use this request listener bey default.
    However, this object is defined here so clients can optionally apply it.
    """
    def handle(self, environ: dict, request_body: bytes, **kwargs):
        content_length = len(request_body)
        msg = self.formatter(0, environ, content_length, ip_header=self.ip_header, **kwargs)
        self.logger.info(msg)


class DefaultResponseListener(DefaultListenerMixin, AbstractBaseResponseListener):
    """Behaves identically to the original logger. Logs the response in Apache format
    with the response time as the rt_us key. See :class:`DefaultListenerMixin`."""
    def __init__(self, logger: logging.Logger = None, handlers: logging.Handler = None,
                 formatter=ApacheFormatter(with_response_time=True),
                 ip_header=None):
        # The only difference is we include the response times and the status code is legit.
        super().__init__(logger=logger, handlers=handlers, formatter=formatter, ip_header=ip_header)

    def handle(self, status_code: int, environ: dict, content_length: int, response_body: bytes,
               processing_time: float, **kwargs):
        msg = self.formatter(status_code, environ, content_length, ip_header=self.ip_header,
                             rt_us=processing_time, **kwargs)
        self.logger.info(msg)
