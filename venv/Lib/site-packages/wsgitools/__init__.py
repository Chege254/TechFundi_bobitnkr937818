"""
wsgitools is meant to be used as a toolbox when working with wsgi. Everything
should fit together like lego bricks. Almost everything contained implements
the wsgi interface.

The toolbox provides:
 - a set of wsgi applications in L{wsgitools.applications}
 - an interface to filter wsgi applications and some filters in
   L{wsgitools.filters}
 - a set of middlewares that could not be implemented using the filter interface
   in L{wsgitools.middlewares}
 - digest authentication (RFC2617) in L{wsgitools.digest}
 - servers for the scgi protocol in L{wsgitools.scgi}
 - adapter classes for an interface that might in distant future be the second
   version of wsgi in L{wsgitools.adapters}
"""
