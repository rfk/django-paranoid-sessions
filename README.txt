

  paranoidsessions:  more comprehensive security checking for Django sessions

This module implements "paranoid sessions" for Django - sessions that work
considerably harder at security than the standard version.  Designed to make
session-stealing attacks as hard as possible, the extra measures that can be
employed are:

  * HTTP header fingerprinting (e.g. REMOTE_ADDR, HTTP_USER_AGENT)
  * per-request nonces (with configurable timeout and duplicate window)
  * periodic cycling of session keys

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

          Default:  0


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

          Default:  0.5


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

