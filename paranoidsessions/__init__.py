"""

  paranoidsessions:  more comprehensive security checking for Django sessions

This module implements "paranoid sessions" for Django - sessions that work
considerably harder at security than the standard version.  Designed to make
session-stealing attacks as hard as possible, the extra measures that can be
employed are:

  * HTTP header fingerprinting (e.g. REMOTE_ADDR, HTTP_USER_AGENT)
  * per-request nonces (with configurable timeout and duplicate window)
  * periodic cycling of session keys
  * maintaining a second key for secure connections
  * marking session keys as "HttpOnly"

As always, there's a tradeoff here - these security measures involve increased
processing per request and more frequent writes to the session store.  You also
run the risk of terminating valid sessions that happen to look suspicious.
But by adjusting the various settings offered by this module, you should be
able to find a compromise that's suitable for your project.

To use this module, simply include it in MIDDLEWARE_CLASSES after the standard
session middleware:

MIDDLEWARE_CLASSES = (
    ...
    'django.contrib.sessions.middleware.SessionMiddleware',
    'paranoidsessions.ParanoidSessionMiddleware',
    ...
)

In keeping with the name, the default settings of this module are designed
to maximise security at the expense of performance and user convenience.
You'll probably want to adjust them to a compromise that's more suitable for
your application, but you should understand the tradeoffs before doing so.

In particular, the management of per-request nonces must account for the
asynchronous nature of the web.  Race conditions between multiple requests
from the same session mean that the use of nonces cannot be perfectly serial.
If a user sends two requests in quick succession, so that the second request is
sent before the first response is received, then these requests will validly
share a nonce.  This scenario is complicated further by the fact that requests
may be handled by different server processes.

To manage such overlapping requests, this module permits a small window within
which duplicate nonces are treated as valid.  To coordinate nonce generation
across multiple server processes, they are built from a pseudo-random stream
based on a shared random seed value.  This should be sufficiently unforgeable
for most applications - if your attacker is determined enough to compromise
nonces generated in this manner, you should consider serving the entire site
over a secure channel!

The following settings are available to tweak the behaviour of this module:

  PSESSION_CHECK_HEADERS:  List of headers to check on each request.  The
          session will be cleared if any of these headers vary from those
          sent when the session was initially created.

          Default:  ["REMOTE_ADDR","HTTP_X_FORWARDED_FOR","HTTP_USER_AGENT"]


  PSESSION_NONCE_TIMEOUT:  Time (in seconds) after which a new nonce will be
          generated.  The client must return a valid nonce with each request
          or the session will be cleared. Setting this to a larger value will
          decrease security but reduce the frequency of writes to the session
          store.  Setting it to zero means a new nonce is generated on every
          request.  Setting it to None will disable the use of nonces entirely.

          Default:  1


  PSESSION_NONCE_WINDOW:  Number of nonces prior to the current nonce that will
          still be accepted as valid.  This corresponds to the number of nonce
          updates that could be "in flight" between the server and client at
          any given time.  Setting it to zero will break overlapping requests.

          If you need to set it to any more than 1, your site has some serious
          performance issues.  Not that Django's built-in development server
          *does* have some serious performance issues; set it to at least 3
          for your development environment.

          Default:  1


  PSESSION_NONCE_WINDOW_TIMEOUT:  Time (in seconds) within which old nonces
          are accepted.  This window should be as small as possible, but is
          necessary if users will perform multiple overlapping requests.
          Setting it to None means the window never times out.

          Default:  1


  PSESSION_KEY_TIMEOUT:  Time (in seconds) after which the session key will
          be cycled.  This should only be needed if nonces are not in use;
          the difference is that key cycling doesn't require the client to
          send a separate nonce cookie.  Set it to None to disable key cycling.

          Default:  None


  PSESSION_SESSION_KEY:  Session key under which the request-tracking and
          verification data for this module should be stored.

          Default:  "PARANOID_SESSION_DATA"


  PSESSION_COOKIE_NAME:  Name of cookie used for the per-request nonce.

          Default:  "sessionnonce"


  PSESSION_SECURE_COOKIE_NAME:  Name of cookie used for the additional "secure
          connections only" session key.  This additional information is only
          passed between the server and client over a secure connection; if
          a sniffer or man-in-the-middle attack compromises all HTTP traffic,
          they still cannot forge session requests over HTTPS.

          Default:  "sessionid_https"


  PSESSION_CLEAR_SESSION_FUNCTION:  Function called to clear the session if a
          potential attack is detected.  An importable name or callable object
          may be given, taking a request object as its only argument.

          Default:  lambda req: req.session.flush()


  PSESSION_REQUEST_FILTER_FUNCTION:  Function to filter requests to be checked.
          Any requests for which this function returns False will not be
          subjected to paranoid validation.  This may be helpful for reducing
          processing overhead on low-risk targets such as media files, but
          will give an attacker more opportunities to compromise a given nonce.

          Default:  lambda req: True


If you expect a high density of overlapping requests, the default settings of
this module are probably too strict and will result in valid user sessions
being terminated.  Consider some of the following adjustments:

    * set NONCE_TIMEOUT to a small positive value e.g. 1 second
    * increase the NONCE_WINDOW and NONCE_WINDOW_TIMEOUT values
    * filter out requests to MEDIA_URL to reduce nonce cycling

"""

__version__ = "0.1.0"

import time

from django.utils.http import cookie_date
from django.utils.hashcompat import md5_constructor
from django.core.urlresolvers import get_callable
from django.contrib.sessions.backends.base import randrange
from django.conf import settings

MAX_NONCE_SEED = 18446744073709551616L     # 2 << 63

if not hasattr(settings,"PSESSION_CHECK_HEADERS"):
    check_headers = ("REMOTE_ADDR","HTTP_X_FORWARDED_FOR","HTTP_USER_AGENT",)
    settings.PSESSION_CHECK_HEADERS = check_headers
if not hasattr(settings,"PSESSION_NONCE_TIMEOUT"):
    settings.PSESSION_NONCE_TIMEOUT = 1
if not hasattr(settings,"PSESSION_NONCE_WINDOW"):
    settings.PSESSION_NONCE_WINDOW = 1
if not hasattr(settings,"PSESSION_NONCE_WINDOW_TIMEOUT"):
    settings.PSESSION_NONCE_WINDOW_TIMEOUT = 1
if not hasattr(settings,"PSESSION_KEY_TIMEOUT"):
    settings.PSESSION_KEY_TIMEOUT = None
if not hasattr(settings,"PSESSION_SESSION_KEY"):
    settings.PSESSION_SESSION_KEY = "PARANOID_SESSION_DATA"
if not hasattr(settings,"PSESSION_COOKIE_NAME"):
    settings.PSESSION_COOKIE_NAME = "sessionnonce"
if not hasattr(settings,"PSESSION_SECURE_COOKIE_NAME"):
    settings.PSESSION_SECURE_COOKIE_NAME = "sessionid_https"
if not hasattr(settings,"PSESSION_COOKIE_HTTPONLY"):
    settings.PSESSION_COOKIE_HTTPONLY = True
if hasattr(settings,"PSESSION_REQUEST_FILTER_FUNCTION"):
    request_filter = get_callable(settings.PSESSION_REQUEST_FILTER_FUNCTION)
    settings.PSESSION_REQUEST_FILTER_FUNCTION = request_filter
else:
    settings.PSESSION_REQUEST_FILTER_FUNCTION = lambda req: True
if hasattr(settings,"PSESSION_CLEAR_SESSION_FUNCTION"):
    clear_session = get_callable(settings.PSESSION_CLEAR_SESSION_FUNCTION)
    settings.PSESSION_CLEAR_SESSION_FUNCTION = clear_session
else:
    settings.PSESSION_CLEAR_SESSION_FUNCTION = lambda req: req.session.flush()


class NonceStream(object):
    """Generate an unpredictable stream of nonce values.

    This class simulates a cryptographic pseudo-random number generator
    using repeated hashing of an initial random seed.  There has been no
    formal cryptanalysis of such a scheme but:

        * I'm confident in its utility for this purpose
        * It's easy to implement using only python builtins

    If you're worried about the security of such a stream, you can replace
    this class with one based on a proper CSPRNG using e.g. PyCrypto. I'm
    also open to suggestions on how to improve this using python builtins.
    """

    def __init__(self):
        seed = (randrange(0,MAX_NONCE_SEED),settings.SECRET_KEY)
        self.state = md5_constructor("%s%s" % seed).hexdigest()

    def nonces(self):
        """Generator producing sequence of nonce values."""
        state = self.state
        while True:
            yield state
            state = md5_constructor(state + settings.SECRET_KEY).hexdigest()

    def increment(self):
        """Increment the nonce stream, discarding initial nonce."""
        state = self.state
        state = self.state
        self.state = md5_constructor(state + settings.SECRET_KEY).hexdigest()
        return self.state
        

class SessionFingerprint(object):
    """Object representing a unique request fingerprint for a session.

    This class is used to check that incoming requests are presenting valid
    session tokens, by checking them against certain "fingerprint" information
    that is contained in the session.  The fingerprint may include:

        * the values of certain HTTP headers
        * a per-request nonce

    It also maintains ancilliarly data for managing timeouts etc.
    """

    def __init__(self,request):
        self.hash = self.request_hash(request)
        self.nonce_stream = NonceStream()
        now = time.time()
        self.last_nonce_time = 0
        self.last_key_time = now
        self.last_request_time = now
        self.secure_key = None

    def check_request(self,request):
        """Check that the given request is valid for this session.

        It's valid if its fingerprint hash matches the current hash, or
        if the duplicate nonce window is enabled and it matches a sufficiently
        recent hash.
        """
        if request.is_secure():
            if self.secure_key is None:
                seed = (randrange(0,MAX_NONCE_SEED),settings.SECRET_KEY)
                self.secure_key = md5_constructor("%s%s" % seed).hexdigest()
                request.session.modified = True
            else:
                cookie_name = settings.PSESSION_SECURE_COOKIE_NAME
                key = request.COOKIES.get(cookie_name,"")
                if key != self.secure_key:
                    return False
        hash = self.request_hash(request)
        if hash != self.hash:
            return False
        if settings.PSESSION_NONCE_TIMEOUT is not None:
            nonce = request.COOKIES.get(settings.PSESSION_COOKIE_NAME,"")
            if nonce not in self.get_valid_nonces():
                return False
        self.last_request_time = time.time()
        return True

    def process_response(self,request,response):
        """Process a response and mark session as modified if necessary.

        This method sets the nonce cookie and cycles the session key if
        necessary.  If any changes are made, the request session is marked
        as modified so that it will be saved appropriately.
        """
        now = time.time()
        nonce_timeout = settings.PSESSION_NONCE_TIMEOUT
        #  Generate a new nonce if necessary
        if nonce_timeout is not None:
            #  If this request took an unusually long time, other requests
            #  might have incremented the nonce more than once.  We need to
            #  resync our data from the session store.
            if self.last_request_time < now + nonce_timeout:
                self.refresh_from_session(request)
            if self.last_nonce_time + nonce_timeout < now:
                self.nonce_stream.increment()
                self.set_nonce_cookie(request,response)
                self.last_nonce_time = now
                request.session.modified = True
        #  Generate a new session key if necessary
        if settings.PSESSION_KEY_TIMEOUT is not None:
            if self.last_key_time + settings.PSESSION_KEY_TIMEOUT < now:
                request.session.cycle_key()
                self.last_key_time = now
                request.session.modified = True
        #  Send the secure_key if the client doesn't have it yet, or has
        #  an incorrect value.  Remember, this will only be called for
        #  valid requests!
        if request.is_secure():
            cookie_name = settings.PSESSION_SECURE_COOKIE_NAME
            if self.secure_key != request.COOKIES.get(cookie_name,""):
                self.set_secure_key_cookie(request,response)
        #  Force the session cookie to be HttpOnly.
        #  This works even though we get called before the session cookie is
        #  sent; fortunately SimpleCookie remembers individual settings even
        #  if you re-assign the cookie.
        if request.session.modified or settings.SESSION_SAVE_EVERY_REQUEST:
            key = request.session.session_key
            self._set_cookie(request,response,settings.SESSION_COOKIE_NAME,key)
            
    def request_hash(self,request):
        """Create a hash of the given request's fingerprint data.

        This hash will contain data that should be the same for every request
        in this session.
        """
        hash = md5_constructor()
        if settings.PSESSION_CHECK_HEADERS:
            for header in settings.PSESSION_CHECK_HEADERS:
               hash.update(request.META.get(header,""))
        return hash.digest()

    def get_valid_nonces(self):
        """Get a sequence of all currently valid nonces."""
        now = time.time()
        nonces = self.nonce_stream.nonces()
        window = settings.PSESSION_NONCE_WINDOW
        timeout = settings.PSESSION_NONCE_WINDOW_TIMEOUT
        #  Yield or skip old nonces, depending on window timeout
        if timeout is None or now < self.last_nonce_time + timeout:
            for _ in xrange(window):
                yield nonces.next()
        else:
            for _ in xrange(window):
                nonces.next()
        #  Yield the current nonce
        yield nonces.next()
        #  I belive that races between Django processes could result in the
        #  client actually being one step ahead of the server.  Not likely,
        #  but it could happen.
        yield nonces.next()

    def set_nonce_cookie(self,request,response):
        """Set the nonce cookie on the given response."""
        nonce = list(self.get_valid_nonces())[-2]
        self._set_cookie(request,response,settings.PSESSION_COOKIE_NAME,nonce)

    def set_secure_key_cookie(self,request,response):
        """Set the secure-key cookie on the given response."""
        name = settings.PSESSION_SECURE_COOKIE_NAME
        self._set_cookie(request,response,name,self.secure_key,True)

    def _set_cookie(self,request,response,name,value,secure=False):
        """Set a session-related cookie.

        This duplicates the cookie-setting logic in the session middleware,
        so it will expire under the same rules as the session itself.
        """
        secure = secure or settings.SESSION_COOKIE_SECURE
        if request.session.get_expire_at_browser_close():
            max_age = None
            expires = None
        else:
            max_age = request.session.get_expiry_age()
            expires_time = time.time() + max_age
            expires = cookie_date(expires_time)
        response.set_cookie(name,value,secure=secure,
                            max_age=max_age,expires=expires,
                            domain=settings.SESSION_COOKIE_DOMAIN,
                            path=settings.SESSION_COOKIE_PATH)
        if settings.PSESSION_COOKIE_HTTPONLY:
            if "httponly" in response.cookies[name]:
                response.cookies[name]["httponly"] = True

    def refresh_from_session(self,request):
        """Refresh internal data from the session store."""
        session_data = request.session.load()
        try:
            fingerprint = session_data[settings.PSESSION_SESSION_KEY]
        except KeyError:
            pass
        else:
            if fingerprint.last_nonce_time > self.last_nonce_time:
                self.nonce_stream = fingerprint.nonce_stream
                self.last_nonce_time = fingerprint.last_nonce_time
            if fingerprint.last_key_time > self.last_key_time:
                self.last_key_time = fingerprint.last_key_time
            if fingerprint.last_request_time > self.last_request_time:
                self.last_request_time = fingerprint.last_request_time
        

class ParanoidSessionMiddleware(object):
    """Middleware implementing paranoid session checking.

    This middleware ensures that each session contains a SessionFingerprint
    object, and asks that object to validate each incoming request.
    """

    def process_request(self,request):
        if settings.PSESSION_REQUEST_FILTER_FUNCTION(request):
            try:
                fingerprint = request.session[settings.PSESSION_SESSION_KEY]
            except KeyError:
                fingerprint = SessionFingerprint(request)
                request.session[settings.PSESSION_SESSION_KEY] = fingerprint
                request.session.save()
            else:
                if not fingerprint.check_request(request):
                    settings.PSESSION_CLEAR_SESSION_FUNCTION(request)
            request.session.paranoid = True
        else:
            request.session.paranoid = False

    def process_response(self,request,response):
        if not hasattr(request,"session"):
            return response
        if getattr(request.session,"paranoid",True):
            try:
                fingerprint = request.session[settings.PSESSION_SESSION_KEY]
            except KeyError:
                fingerprint = SessionFingerprint(request)
                request.session[settings.PSESSION_SESSION_KEY] = fingerprint
            fingerprint.process_response(request,response)
        return response


