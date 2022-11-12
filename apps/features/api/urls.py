from django.urls import path
from django.conf import settings
from .views import *

urlpatterns = [

    path('download/', download, name='api-download'),
    path('delete/', delete_file, name='api-delete_file'),
    path('decrypt/', decrypt, name='api-decrypt'),
    path('done/', done, name='api-done'),
    path('generate-key-pair/', generate_key_pair, name='api-generate_key_pair'),
    path('delete-key-pair/', delete_key_pair, name='api-delete_key_pair'),
    path('download-prvkey/', download_private_key, name='api-download_private_key'),
    path('sign-document/', sign_document, name='api-sign_document'),
    path('verify-document-signature/', verify_document_signature, name='api-verify_document_signature'),
    path('unsign-document/', unsign_document, name='api-unsign_document'),
    path('download-signature/', download_signature, name='api-download_signature'),
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
