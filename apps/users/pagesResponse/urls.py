from django.urls import path
from django.conf import settings
from django.contrib.auth import views as auth_view
from .views import login_view, admin_dashboard, register

urlpatterns = [
    path('', admin_dashboard, name='dashboard'),
    path('dashboard/', admin_dashboard, name='dashboard'),

    path('login/', login_view, name='login'),
    path('logout/', auth_view.LogoutView.as_view(), name='logout'),

    path('register/', register, name='register')
]

if settings.DEBUG:
    from django.conf.urls.static import static

    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
