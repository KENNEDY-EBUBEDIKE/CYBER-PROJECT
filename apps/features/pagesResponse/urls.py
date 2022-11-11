from django.urls import path
from django.conf import settings
from .views import vault, upload_file, user_shared_secrets, public_keys

urlpatterns = [

    path('vault/', vault, name='vault'),
    path('upload/', upload_file, name='upload_file'),
    path('shared-secrets/', user_shared_secrets, name='shared_secrets'),
    path('public-keys/', public_keys, name='public_keys'),
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
