
  paranoidsessions:  more compresensive security checking for Django sessions

This module implements "paranoid sessions" for Django - sessions that work
considerably harder at security than the standard version.  Desgined to make
session-stealing attacks as hard as possible, the extra measures that can be
employed are:

  * HTTP header fingerprinting (e.g. REMOTE_ADDR, HTTP_USER_AGENT)
  * per-request nonces (with configurable timeout and duplicate window)
  * periodic cycling of session keys

As always, there's a tradeoff here - these security measures involve increased
processing per request and more frequent writes to the session store.  But by
adjusting the various settings offered by this module, you should be able to
find a compromise that's suitable for your project.

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

The following settings are available:

  PSESSION_CHECK_HEADERS:  List of headers to check on each request.  The
          session will be cleared if any of these headers vary from those
          sent when the session was initially created.
          Default:  ["REMOTE_ADDR","HTTP_X_FORWARDED_FOR"]

  PSESSION_NONCE_TIMEOUT:  Time (in seconds) after which a new nonce will be
          generated.  The client must return a valid nonce with each request
          or the session will be cleared. Setting this to a larger value will
          decrease security but reduce the frequency of writes to the session
          store.  Setting it to zero means a new nonce is generated on every
          request.  Setting it to None will disable the use of nonces entirely.
          Default:  0

  PSESSION_NONCE_WINDOW:  Number of nonce indexes above or below the current
          nonce that will still be accepted as valid.  This should roughly
          correspond to the expected number of overlapping requests.
          Default:  1

  PSESSION_OLD_NONCE_TIMEOUT:  Time (in seconds) within which old nonces are
          accepted.  This window should be as small as possible, but may be
          necessary if users perform multiple overlapping requests.
          Default:  0.5

  PSESSION_KEY_TIMEOUT:  Time (in seconds) after which the session key will
          be cycled.  This should only be needed if nonces are not in use;
          the difference is that key cycling doesn't require the client to
          send a separate nonce cookie.  Setit to None to disable key cycling.
          Default:  None

  PSESSION_SESSION_KEY:  Session key under which the request-tracking and
          verification data for this module should be stored.
          Default:  "PARANOID_SESSION_DATA"

  PSESSION_COOKIE_NAME:  Name of cookie used for the per-request nonce.
          Default:  "sessionnonce"

  PSESSION_CLEAR_SESSION_FUNCTION:  Function called to clear the session if a
          potential attack is detected.  An importable name or callable object
          may be given, taking a request object as its only argument.
          Default:  paranoidsessions.clear_session

