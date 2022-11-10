from config.settings.base import *


DEBUG = True
ALLOWED_HOSTS = ['*']
CORS_ALLOW_ALL_ORIGINS = True

# *****  MEDIA FILES SETTINGS *****
MEDIA_ROOT = BASE_DIR / '../media'
