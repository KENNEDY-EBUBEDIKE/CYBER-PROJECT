from django.contrib import admin
from .models import Vault, SharedSecret, RSAKeyPair
from django.utils.translation import gettext_lazy

admin.site.register(Vault)
admin.site.register(SharedSecret)
admin.site.register(RSAKeyPair)

# Text to put at the end of each page's <title>.
admin.site.site_title = gettext_lazy("Cyber Security admin")

# Text to put in each page's <h1>.
admin.site.site_header = gettext_lazy("Cyber Security App Admin")

# Text to put at the top of the admin index page.
admin.site.index_title = gettext_lazy("Amod Cyber Admin Panel")
