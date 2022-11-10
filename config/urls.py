from django.contrib import admin
from django.urls import path, include
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.users.pagesResponse.urls')),
    path('users/', include('apps.users.pagesResponse.urls')),
    path('api/users/', include('apps.users.api.urls')),


    path('features/', include('apps.features.pagesResponse.urls')),
    path('api/features/', include('apps.features.api.urls')),
]

if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
