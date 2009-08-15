#
#  django-paranoid-sessions setup script
#

from distutils.core import setup

#  Get the version info out of the module itself.
#  The import will fail if Django settings are not configured.
module = {}
try:
    execfile("paranoidsessions/__init__.py",module)
except ImportError:
    pass


NAME = "django-paranoid-sessions"
DESCRIPTION = "make Django work harder to prevent session-stealing attacks"
VERSION = module["__version__"]
AUTHOR = "Ryan Kelly"
AUTHOR_EMAIL = "ryan@rfk.id.au"
URL = "http://github.com/rfk/django-paranoid-sessions/tree/master"
LICENSE = "MIT"
LONG_DESC = module["__doc__"]
PACKAGES = ["paranoidsessions"]

setup(name=NAME,
      version=VERSION,
      author=AUTHOR,
      author_email=AUTHOR_EMAIL,
      url=URL,
      description=DESCRIPTION,
      long_description=LONG_DESC,
      packages=PACKAGES,
      license=LICENSE,
     )

