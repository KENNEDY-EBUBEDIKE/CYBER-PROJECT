from config.settings.base import *


DEBUG = False
ALLOWED_HOSTS = [
    'vodatrox.com',
    'www.vodatrox.com',
    'cyber-security.vodatrox.com',
    'www.cyber-security.vodatrox.com',
]

# *****  MEDIA FILES SETTINGS *****
MEDIA_ROOT = '/home/vodatro1/cyber-security.vodatrox.com/media/'

CORS_ALLOWED_ORIGINS = [
    'https://vodatrox.com',
]

CSRF_TRUSTED_ORIGINS = [
    'https://vodatrox.com',
]

# HTTP verbs that are allowed
CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "PATCH",
    "POST",
    "PUT",
]

# Whether to append trailing slashes to URLs.
APPEND_SLASH = True


'''  Deployment Security Configurations  '''

# *********************  CSRF PROTECTION  **********************************
# Redirects all Unsecure (HTTP) connections to HTTPS
SECURE_SSL_REDIRECT = True
# prevents accidentally sending session cookie over HTTP by accident.
SESSION_COOKIE_SECURE = True
# prevents accidentally sending CSRF cookie over HTTP by accident.
CSRF_COOKIE_SECURE = True


# *********************  HSTS PROTECTION  **********************************
# PreLoads the HSTS policy on the browser
SECURE_HSTS_PRELOAD = True

# The browser will refuse Unsecure connection to the site for n seconds
SECURE_HSTS_SECONDS = '86400'

# Forces HSTS on all sub domains of the site
SECURE_HSTS_INCLUDE_SUBDOMAINS = True


# *********************  XSS PROTECTION  **********************************
# Filters Cross Site Scripting Attacks
SECURE_BROWSER_XSS_FILTER = True

# Forces the browser to use the specified contentType and not guessing it
SECURE_CONTENT_TYPE_NOSNIFF = True


# *********************  CORS PROTECTION  **********************************
# send only the origin addr(domain addr without subdomain) as referrer header when the link is outside this domain
SECURE_REFERRER_POLICY = 'origin-when-cross-origin'


# *********************  OTHER PROTECTION  **********************************
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
