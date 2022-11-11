from django.urls import path
from django.conf import settings
from .views import download, delete_file, decrypt, done, generate_key_pair

urlpatterns = [

    path('download/', download, name='api-download'),
    path('delete/', delete_file, name='api-delete_file'),
    path('decrypt/', decrypt, name='api-decrypt'),
    path('done/', done, name='api-done'),
    path('generate-key-pair/', generate_key_pair, name='api-generate_key_pair'),
]


if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
