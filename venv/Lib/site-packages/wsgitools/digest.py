"""
This module contains an C{AuthDigestMiddleware} for authenticating HTTP
requests using the method described in RFC2617. The credentials are to be
provided using an C{AuthTokenGenerator} or a compatible instance. Furthermore
digest authentication has to preserve some state across requests, more
specifically nonces. There are three different C{NonceStoreBase}
implementations for different needs. While the C{StatelessNonceStore} has
minimal requirements it only prevents replay attacks in a limited way. If the
WSGI server uses threading or a single process the C{MemoryNonceStore} can be
used. If that is not possible the nonces can be stored in a DBAPI2 compatible
database using C{DBAPI2NonceStore}.
"""

__all__ = []

import base64
import hashlib
import time
import os
try:
    from secrets import randbits, compare_digest
except ImportError:
    import random
    sysrand = random.SystemRandom()
    randbits = sysrand.getrandbits
    def compare_digest(a, b):
        return a == b

from wsgitools.internal import bytes2str, str2bytes, textopen
from wsgitools.authentication import AuthenticationRequired, \
        ProtocolViolation, AuthenticationMiddleware

def md5hex(data):
    """
    @type data: str
    @rtype: str
    """
    return hashlib.md5(str2bytes(data)).hexdigest()

def gen_rand_str(bytesentropy=33):
    """
    Generates a string of random base64 characters.
    @param bytesentropy: is the number of random 8bit values to be used
    @rtype: str

    >>> gen_rand_str() != gen_rand_str()
    True
    """
    randnum = randbits(bytesentropy*8)
    randstr = ("%%0%dX" % (2*bytesentropy)) % randnum
    randbytes = str2bytes(randstr)
    randbytes = base64.b16decode(randbytes)
    randbytes = base64.b64encode(randbytes)
    randstr = bytes2str(randbytes)
    return randstr

def parse_digest_response(data):
    """internal
    @raises ValueError:

    >>> parse_digest_response('foo=bar')
    {'foo': 'bar'}
    >>> parse_digest_response('foo="bar"')
    {'foo': 'bar'}
    >>> sorted(parse_digest_response('foo="bar=qux",spam=egg').items())
    [('foo', 'bar=qux'), ('spam', 'egg')]
    >>> try:
    ...     parse_digest_response('spam')
    ... except ValueError:
    ...     print("ValueError")
    ValueError
    >>> try:
    ...     parse_digest_response('spam="egg"error')
    ... except ValueError:
    ...     print("ValueError")
    ValueError
    >>> # backslashes: doc string, eval => two backslashes
    >>> parse_digest_response('backslash="\\\\\\\\"')
    {'backslash': '\\\\'}
    >>> parse_digest_response('foo="quo\\\\"te"')
    {'foo': 'quo"te'}
    """
    assert isinstance(data, str)
    result = dict()
    while True:
        data = data.strip()
        key, data = data.split('=', 1) # raises ValueError
        if data.startswith('"'):
            data = data[1:]
            value = ""
            while True:
                part, data = data.split('"', 1) # raises ValueError
                # how many consecutive backslashes did we see?
                escape = -1 # the first iteration does not indicate a backslash
                for part in part.split('\\'):
                    escape += 1 # backslash before part
                    if escape > 2:
                        value += "\\"
                        escape -= 2
                    if part:
                        escape = 0
                        value += part
                if escape == 2:
                    value += "\\"
                elif escape == 1:
                    value += '"'
                    continue
                break
            result[key] = value
            if not data:
                return result
            if data[0] != ",":
                raise ValueError("invalid digest response")
            data = data[1:]
        else:
            if ',' not in data:
                result[key] = data
                return result
            value, data = data.split(',', 1)
            result[key] = value

def format_digest(mapping):
    """internal

    @type mapping: {str: (str, bool)}
    @param mapping: a mapping of keys to values and a boolean that
        determines whether the value needs quoting.
    @rtype: str
    @note: the RFC specifies which values must be quoted and which must not be
        quoted.
    """
    assert isinstance(mapping, dict)
    result = []
    for key, (value, needsquoting) in mapping.items():
        assert isinstance(key, str)
        assert isinstance(value, str)
        if needsquoting:
            value = '"%s"' % value.replace('\\', '\\\\').replace('"', '\\"')
        else:
            assert '"' not in value
            assert ',' not in value
        result.append("%s=%s" % (key, value))
    return ", ".join(result)

class StaleNonce(AuthenticationRequired):
    pass

__all__.append("AbstractTokenGenerator")
class AbstractTokenGenerator(object):
    """Interface class for generating authentication tokens for
    L{AuthDigestMiddleware}.

    @ivar realm: is a string according to RFC2617.
    @type realm: str
    """
    def __init__(self, realm):
        """
        @type realm: str
        """
        assert isinstance(realm, str)
        self.realm = realm

    def __call__(self, username, algo="md5"):
        """Generates an authentication token from a username.
        @type username: str
        @type algo: str
        @param algo: currently the only value supported by
                L{AuthDigestMiddleware} is "md5"
        @rtype: str or None
        @returns: a valid token or None to signal that authentication should
                fail
        """
        raise NotImplementedError

    def check_password(self, username, password, environ=None):
        """
        This function implements the interface for verifying passwords
        used by L{BasicAuthMiddleware}. It works by computing a token
        from the user and comparing it to the token returned by the
        __call__ method.

        @type username: str
        @type password: str
        @param environ: ignored
        @rtype: bool
        """
        assert isinstance(username, str)
        assert isinstance(password, str)
        token = "%s:%s:%s" % (username, self.realm, password)
        return compare_digest(md5hex(token), self(username))

__all__.append("AuthTokenGenerator")
class AuthTokenGenerator(AbstractTokenGenerator):
    """Generates authentication tokens for L{AuthDigestMiddleware}. The
    interface consists of beeing callable with a username and having a
    realm attribute being a string."""
    def __init__(self, realm, getpass):
        """
        @type realm: str
        @param realm: is a string according to RFC2617.
        @type getpass: str -> (str or None)
        @param getpass: this function is called with a username and password is
                expected as result. C{None} may be used as an invalid password.
                An example for getpass would be C{{username: password}.get}.
        """
        AbstractTokenGenerator.__init__(self, realm)
        self.getpass = getpass

    def __call__(self, username, algo="md5"):
        assert isinstance(username, str)
        assert algo.lower() in ["md5", "md5-sess"]
        password = self.getpass(username)
        if password is None:
            return None
        a1 = "%s:%s:%s" % (username, self.realm, password)
        return md5hex(a1)

__all__.append("HtdigestTokenGenerator")
class HtdigestTokenGenerator(AbstractTokenGenerator):
    """Reads authentication tokens for L{AuthDigestMiddleware} from an
    apache htdigest file.
    """
    def __init__(self, realm, htdigestfile, ignoreparseerrors=False):
        """
        @type realm: str
        @type htdigestfile: str
        @param htdigestfile: path to the .htdigest file
        @type ignoreparseerrors: bool
        @param ignoreparseerrors: passed to readhtdigest
        @raises IOError:
        @raises ValueError:
        """
        AbstractTokenGenerator.__init__(self, realm)
        self.users = {}
        self.readhtdigest(htdigestfile, ignoreparseerrors)

    def readhtdigest(self, htdigestfile, ignoreparseerrors=False):
        """
        @type htdigestfile: str
        @type ignoreparseerrors: bool
        @param ignoreparseerrors: do not raise ValueErrors for bad files
        @raises IOError:
        @raises ValueError:
        """
        assert isinstance(htdigestfile, str)
        self.users = {}
        with textopen(htdigestfile, "r") as htdigest:
            for line in htdigest:
                parts = line.rstrip("\n").split(":")
                if len(parts) != 3:
                    if ignoreparseerrors:
                        continue
                    raise ValueError("invalid number of colons in htdigest file")
                user, realm, token = parts
                if realm != self.realm:
                    continue
                if user in self.users and not ignoreparseerrors:
                    raise ValueError("duplicate user in htdigest file")
                self.users[user] = token

    def __call__(self, user, algo="md5"):
        assert algo.lower() in ["md5", "md5-sess"]
        return self.users.get(user)

__all__.append("UpdatingHtdigestTokenGenerator")
class UpdatingHtdigestTokenGenerator(HtdigestTokenGenerator):
    """Behaves like L{HtdigestTokenGenerator}, checks the htdigest file
    for changes on each invocation.
    """
    def __init__(self, realm, htdigestfile, ignoreparseerrors=False):
        assert isinstance(htdigestfile, str)
        # Need to stat the file before calling parent ctor to detect
        # modifications.
        try:
            self.statcache = os.stat(htdigestfile)
        except OSError as err:
            raise IOError(str(err))
        HtdigestTokenGenerator.__init__(self, realm, htdigestfile,
                                        ignoreparseerrors)
        self.htdigestfile = htdigestfile
        self.ignoreparseerrors = ignoreparseerrors

    def __call__(self, user, algo="md5"):
        # The interface does not permit raising exceptions, so all we can do is
        # fail by returning None.
        try:
            statcache = os.stat(self.htdigestfile)
        except OSError:
            return None
        if self.statcache != statcache:
            try:
                self.readhtdigest(self.htdigestfile, self.ignoreparseerrors)
            except IOError:
                return None
            except ValueError:
                return None
        return HtdigestTokenGenerator.__call__(self, user, algo)

__all__.append("NonceStoreBase")
class NonceStoreBase(object):
    """Nonce storage interface."""
    def __init__(self):
        pass
    def newnonce(self, ident=None):
        """
        This method is to be overriden and should return new nonces.
        @type ident: str
        @param ident: is an identifier to be associated with this nonce
        @rtype: str
        """
        raise NotImplementedError
    def checknonce(self, nonce, count=1, ident=None):
        """
        This method is to be overridden and should do a check for whether the
        given nonce is valid as being used count times.
        @type nonce: str
        @type count: int
        @param count: indicates how often the nonce has been used (including
                this check)
        @type ident: str
        @param ident: it is also checked that the nonce was associated to this
            identifier when given
        @rtype: bool
        """
        raise NotImplementedError

def format_time(seconds):
    """
    internal method formatting a unix time to a fixed-length string
    @type seconds: float
    @rtype: str
    """
    # the overflow will happen about 2112
    return "%013X" % int(seconds * 1000000)

__all__.append("StatelessNonceStore")
class StatelessNonceStore(NonceStoreBase):
    """
    This is a stateless nonce storage that cannot check the usage count for
    a nonce and thus cannot protect against replay attacks. It however can make
    it difficult by posing a timeout on nonces and making it difficult to forge
    nonces.
    
    This nonce store is usable with L{scgi.forkpool}.

    >>> s = StatelessNonceStore()
    >>> n = s.newnonce()
    >>> s.checknonce("spam")
    False
    >>> s.checknonce(n)
    True
    >>> s.checknonce(n)
    True
    >>> s.checknonce(n.rsplit(':', 1)[0] + "bad hash")
    False
    """
    def __init__(self, maxage=300, secret=None):
        """
        @type maxage: int
        @param maxage: is the number of seconds a nonce may be valid. Choosing a
                large value may result in more memory usage whereas a smaller
                value results in more requests. Defaults to 5 minutes.
        @type secret: str
        @param secret: if not given, a secret is generated and is therefore
                shared after forks. Knowing this secret permits creating nonces.
        """
        NonceStoreBase.__init__(self)
        self.maxage = maxage
        if secret:
            self.server_secret = secret
        else:
            self.server_secret = gen_rand_str()

    def newnonce(self, ident=None):
        """
        Generates a new nonce string.
        @type ident: None or str
        @rtype: str
        """
        nonce_time = format_time(time.time())
        nonce_value = gen_rand_str()
        token = "%s:%s:%s" % (nonce_time, nonce_value, self.server_secret)
        if ident is not None:
            token = "%s:%s" % (token, ident)
        token = md5hex(token)
        return "%s:%s:%s" % (nonce_time, nonce_value, token)

    def checknonce(self, nonce, count=1, ident=None):
        """
        Check whether the provided string is a nonce.
        @type nonce: str
        @type count: int
        @type ident: None or str
        @rtype: bool
        """
        if count != 1:
            return False
        try:
            nonce_time, nonce_value, nonce_hash = nonce.split(':')
        except ValueError:
            return False
        token = "%s:%s:%s" % (nonce_time, nonce_value, self.server_secret)
        if ident is not None:
            token = "%s:%s" % (token, ident)
        token = md5hex(token)
        if token != nonce_hash:
            return False

        if nonce_time < format_time(time.time() - self.maxage):
            return False
        return True

__all__.append("MemoryNonceStore")
class MemoryNonceStore(NonceStoreBase):
    """
    Simple in-memory mechanism to store nonces.

    >>> s = MemoryNonceStore(maxuses=1)
    >>> n = s.newnonce()
    >>> s.checknonce("spam")
    False
    >>> s.checknonce(n)
    True
    >>> s.checknonce(n)
    False
    >>> n = s.newnonce()
    >>> s.checknonce(n.rsplit(':', 1)[0] + "bad hash")
    False
    """
    def __init__(self, maxage=300, maxuses=5):
        """
        @type maxage: int
        @param maxage: is the number of seconds a nonce may be valid. Choosing a
               large value may result in more memory usage whereas a smaller
               value results in more requests. Defaults to 5 minutes.
        @type maxuses: int
        @param maxuses: is the number of times a nonce may be used (with
                different nc values). A value of 1 makes nonces usable exactly
                once resulting in more requests. Defaults to 5.
        """
        NonceStoreBase.__init__(self)
        self.maxage = maxage
        self.maxuses = maxuses
        self.nonces = [] # [(creation_time, nonce_value, useage_count)]
                         # as [(str (hex encoded), str, int)]
        self.server_secret = gen_rand_str()

    def _cleanup(self):
        """internal methods cleaning list of valid nonces"""
        old = format_time(time.time() - self.maxage)
        while self.nonces and self.nonces[0][0] < old:
            self.nonces.pop(0)

    def newnonce(self, ident=None):
        """
        Generates a new nonce string.
        @type ident: None or str
        @rtype: str
        """
        self._cleanup() # avoid growing self.nonces
        nonce_time = format_time(time.time())
        nonce_value = gen_rand_str()
        self.nonces.append((nonce_time, nonce_value, 1))
        token = "%s:%s:%s" % (nonce_time, nonce_value, self.server_secret)
        if ident is not None:
            token = "%s:%s" % (token, ident)
        token = md5hex(token)
        return "%s:%s:%s" % (nonce_time, nonce_value, token)

    def checknonce(self, nonce, count=1, ident=None):
        """
        Do a check for whether the provided string is a nonce and increase usage
        count on returning True.
        @type nonce: str
        @type count: int
        @type ident: None or str
        @rtype: bool
        """
        try:
            nonce_time, nonce_value, nonce_hash = nonce.split(':')
        except ValueError:
            return False
        token = "%s:%s:%s" % (nonce_time, nonce_value, self.server_secret)
        if ident is not None:
            token = "%s:%s" % (token, ident)
        token = md5hex(token)
        if token != nonce_hash:
            return False

        self._cleanup() # avoid stale nonces

        # searching nonce_time
        lower, upper = 0, len(self.nonces) - 1
        while lower < upper:
            mid = (lower + upper) // 2
            if nonce_time <= self.nonces[mid][0]:
                upper = mid
            else:
                lower = mid + 1

        if len(self.nonces) <= lower:
            return False
        (nt, nv, uses) = self.nonces[lower]
        if nt != nonce_time or nv != nonce_value:
            return False
        if count != uses:
            del self.nonces[lower]
            return False
        if uses >= self.maxuses:
            del self.nonces[lower]
        else:
            self.nonces[lower] = (nt, nv, uses+1)
        return True

__all__.append("LazyDBAPI2Opener")
class LazyDBAPI2Opener(object):
    """
    Connects to database on first request. Otherwise it behaves like a dbapi2
    connection. This may be usefull in combination with L{scgi.forkpool},
    because this way each worker child opens a new database connection when
    the first request is to be answered.
    """
    def __init__(self, function, *args, **kwargs):
        """
        The database will be connected on the first method call. This is done
        by calling the given function with the remaining parameters.
        @param function: is the function that connects to the database
        """
        self._function = function
        self._args = args
        self._kwargs = kwargs
        self._dbhandle = None
    def _getdbhandle(self):
        """Returns an open database connection. Open if necessary."""
        if self._dbhandle is None:
            self._dbhandle = self._function(*self._args, **self._kwargs)
            self._function = self._args = self._kwargs = None
        return self._dbhandle
    def cursor(self):
        """dbapi2"""
        return self._getdbhandle().cursor()
    def commit(self):
        """dbapi2"""
        return self._getdbhandle().commit()
    def rollback(self):
        """dbapi2"""
        return self._getdbhandle().rollback()
    def close(self):
        """dbapi2"""
        return self._getdbhandle().close()

__all__.append("DBAPI2NonceStore")
class DBAPI2NonceStore(NonceStoreBase):
    """
    A dbapi2-backed nonce store implementation suitable for usage with forking
    wsgi servers such as L{scgi.forkpool}.

    >>> import sqlite3
    >>> db = sqlite3.connect(":memory:")
    >>> db.cursor().execute("CREATE TABLE nonces (key, value);") and None
    >>> db.commit() and None
    >>> s = DBAPI2NonceStore(db, maxuses=1)
    >>> n = s.newnonce()
    >>> s.checknonce("spam")
    False
    >>> s.checknonce(n)
    True
    >>> s.checknonce(n)
    False
    >>> n = s.newnonce()
    >>> s.checknonce(n.rsplit(':', 1)[0] + "bad hash")
    False
    """
    def __init__(self, dbhandle, maxage=300, maxuses=5, table="nonces"):
        """
        @param dbhandle: is a dbapi2 connection
        @type maxage: int
        @param maxage: is the number of seconds a nonce may be valid. Choosing a
               large value may result in more memory usage whereas a smaller
               value results in more requests. Defaults to 5 minutes.
        @type maxuses: int
        @param maxuses: is the number of times a nonce may be used (with
                different nc values). A value of 1 makes nonces usable exactly
                once resulting in more requests. Defaults to 5.
        """
        NonceStoreBase.__init__(self)
        self.dbhandle = dbhandle
        self.maxage = maxage
        self.maxuses = maxuses
        self.table = table
        self.server_secret = gen_rand_str()

    def _cleanup(self, cur):
        """internal methods cleaning list of valid nonces"""
        old = format_time(time.time() - self.maxage)
        cur.execute("DELETE FROM %s WHERE key < '%s:';" % (self.table, old))

    def newnonce(self, ident=None):
        """
        Generates a new nonce string.
        @rtype: str
        """
        nonce_time = format_time(time.time())
        nonce_value = gen_rand_str()
        dbkey = "%s:%s" % (nonce_time, nonce_value)
        cur = self.dbhandle.cursor()
        self._cleanup(cur) # avoid growing database
        cur.execute("INSERT INTO %s VALUES ('%s', '1');" % (self.table, dbkey))
        self.dbhandle.commit()
        token = "%s:%s" % (dbkey, self.server_secret)
        if ident is not None:
            token = "%s:%s" % (token, ident)
        token = md5hex(token)
        return "%s:%s:%s" % (nonce_time, nonce_value, token)

    def checknonce(self, nonce, count=1, ident=None):
        """
        Do a check for whether the provided string is a nonce and increase usage
        count on returning True.
        @type nonce: str
        @type count: int
        @type ident: str or None
        @rtype: bool
        """
        try:
            nonce_time, nonce_value, nonce_hash = nonce.split(':')
        except ValueError:
            return False
        # use bytes.isalnum to avoid locale specific interpretation
        if not str2bytes(nonce_time).isalnum() or \
                not str2bytes(nonce_value.replace("+", "").replace("/", "") \
                              .replace("=", "")).isalnum():
            return False
        token = "%s:%s:%s" % (nonce_time, nonce_value, self.server_secret)
        if ident is not None:
            token = "%s:%s" % (token, ident)
        token = md5hex(token)
        if token != nonce_hash:
            return False

        if nonce_time < format_time(time.time() - self.maxage):
            return False

        cur = self.dbhandle.cursor()
        #self._cleanup(cur) # avoid growing database

        dbkey = "%s:%s" % (nonce_time, nonce_value)
        cur.execute("SELECT value FROM %s WHERE key = '%s';" %
                    (self.table, dbkey))
        uses = cur.fetchone()
        if uses is None:
            self.dbhandle.commit()
            return False
        uses = int(uses[0])
        if count != uses:
            cur.execute("DELETE FROM %s WHERE key = '%s';" %
                        (self.table, dbkey))
            self.dbhandle.commit()
            return False
        if uses >= self.maxuses:
            cur.execute("DELETE FROM %s WHERE key = '%s';" %
                        (self.table, dbkey))
        else:
            cur.execute("UPDATE %s SET value = '%d' WHERE key = '%s';" %
                        (self.table, uses + 1, dbkey))
        self.dbhandle.commit()
        return True

def check_uri(credentials, environ):
    """internal method for verifying the uri credential
    @raises AuthenticationRequired:
    """
    # Doing this by stripping known parts from the passed uri field
    # until something trivial remains, as the uri cannot be
    # reconstructed from the environment exactly.
    try:
        uri = credentials["uri"]
    except KeyError:
        raise ProtocolViolation("uri missing in client credentials")
    if environ.get("QUERY_STRING"):
        if not uri.endswith(environ["QUERY_STRING"]):
            raise AuthenticationRequired("url mismatch")
        uri = uri[:-len(environ["QUERY_STRING"])]
    if environ.get("SCRIPT_NAME"):
        if not uri.startswith(environ["SCRIPT_NAME"]):
            raise AuthenticationRequired("url mismatch")
        uri = uri[len(environ["SCRIPT_NAME"]):]
    if environ.get("PATH_INFO"):
        if not uri.startswith(environ["PATH_INFO"]):
            raise AuthenticationRequired("url mismatch")
        uri = uri[len(environ["PATH_INFO"]):]
    if uri not in ('', '?'):
        raise AuthenticationRequired("url mismatch")

__all__.append("AuthDigestMiddleware")
class AuthDigestMiddleware(AuthenticationMiddleware):
    """Middleware partly implementing RFC2617. (md5-sess was omited)
    Upon successful authentication the environ dict will be extended
    by a REMOTE_USER key before being passed to the wrapped
    application."""
    authorization_method = "digest"
    algorithms = {"md5": md5hex}
    def __init__(self, app, gentoken, maxage=300, maxuses=5, store=None):
        """
        @param app: is the wsgi application to be served with authentication.
        @type gentoken: str -> (str or None)
        @param gentoken: has to have the same functionality and interface as the
                L{AuthTokenGenerator} class.
        @type maxage: int
        @param maxage: deprecated, see L{MemoryNonceStore} or
                L{StatelessNonceStore} and pass an instance to store
        @type maxuses: int
        @param maxuses: deprecated, see L{MemoryNonceStore} and pass an
                instance to store
        @type store: L{NonceStoreBase}
        @param store: a nonce storage implementation object. Usage of this
                parameter will override maxage and maxuses.
        """
        AuthenticationMiddleware.__init__(self, app)
        self.gentoken = gentoken
        if store is None:
            self.noncestore = MemoryNonceStore(maxage, maxuses)
        else:
            assert hasattr(store, "newnonce")
            assert hasattr(store, "checknonce")
            self.noncestore = store

    def authenticate(self, auth, environ):
        assert isinstance(auth, str)
        try:
            credentials = parse_digest_response(auth)
        except ValueError:
            raise ProtocolViolation("failed to parse digest response")

        ### Check algorithm field
        credentials["algorithm"] = credentials.get("algorithm",
                                                   "md5").lower()
        if not credentials["algorithm"] in self.algorithms:
            raise ProtocolViolation("algorithm not implemented: %r" %
                                    credentials["algorithm"])

        check_uri(credentials, environ)

        try:
            nonce = credentials["nonce"]
            credresponse = credentials["response"]
        except KeyError as err:
            raise ProtocolViolation("%s missing in credentials" %
                                    err.args[0])
        noncecount = 1
        if "qop" in credentials:
            if credentials["qop"] != "auth":
                raise ProtocolViolation("unimplemented qop: %r" %
                                        credentials["qop"])
            try:
                noncecount = int(credentials["nc"], 16)
            except KeyError:
                raise ProtocolViolation("nc missing in qop=auth")
            except ValueError:
                raise ProtocolViolation("non hexdigit found in nonce count")

        # raises AuthenticationRequired
        response = self.auth_response(credentials,
                                      environ["REQUEST_METHOD"])

        if not self.noncestore.checknonce(nonce, noncecount):
            raise StaleNonce()

        if response is None or response != credresponse:
            raise AuthenticationRequired("wrong response")

        digest = dict(nextnonce=(self.noncestore.newnonce(), True))
        if "qop" in credentials:
            digest["qop"] = ("auth", False)
            digest["cnonce"] = (credentials["cnonce"], True) # no KeyError
            digest["rspauth"] = (self.auth_response(credentials, ""), True)
        return dict(user=credentials["username"],
                    outheaders=[("Authentication-Info", format_digest(digest))])

    def auth_response(self, credentials, reqmethod):
        """internal method generating authentication tokens
        @raises AuthenticationRequired:
        """
        try:
            username = credentials["username"]
            algo = credentials["algorithm"]
            uri = credentials["uri"]
        except KeyError as err:
            raise ProtocolViolation("%s missing in credentials" % err.args[0])
        try:
            dig = [credentials["nonce"]]
        except KeyError:
            raise ProtocolViolation("missing nonce in credentials")
        qop = credentials.get("qop")
        if qop is not None:
            if qop != "auth":
                raise AuthenticationRequired("unimplemented qop: %r" % qop)
            try:
                dig.append(credentials["nc"])
                dig.append(credentials["cnonce"])
            except KeyError as err:
                raise ProtocolViolation(
                    "missing %s in credentials with qop=auth" % err.args[0])
            dig.append(qop)
        dig.append(self.algorithms[algo]("%s:%s" % (reqmethod, uri)))
        try:
            a1h = self.gentoken(username, algo)
        except TypeError:
            a1h = self.gentoken(username)
        if a1h is None:
            return None # delay the error for a nonexistent user
        dig.insert(0, a1h)
        return self.algorithms[algo](":".join(dig))

    def www_authenticate(self, exception):
        digest = dict(nonce=(self.noncestore.newnonce(), True),
                      realm=(self.gentoken.realm, True),
                      algorithm=("MD5", False),
                      qop=("auth", False))
        if isinstance(exception, StaleNonce):
            digest["stale"] = ("TRUE", False)
        challenge = format_digest(digest)
        return ("WWW-Authenticate", "Digest %s" % challenge)
