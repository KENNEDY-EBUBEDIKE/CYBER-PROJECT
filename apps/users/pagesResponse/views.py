from django.shortcuts import render, resolve_url, redirect
from django.contrib.auth import authenticate, login, REDIRECT_FIELD_NAME
from django.apps import apps
from django.conf import settings
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.utils.http import url_has_allowed_host_and_scheme
from django.db import IntegrityError


user_model = apps.get_model("users", "User")
redirect_field_name = REDIRECT_FIELD_NAME


def get_redirect_url(request):
    """Return the user-originating redirect URL if it's safe."""
    redirect_to = request.POST.get(
        redirect_field_name,
        request.GET.get(redirect_field_name, '')
    )

    url_is_safe = url_has_allowed_host_and_scheme(
        url=redirect_to,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    )
    return redirect_to if url_is_safe else ''


def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        if user_model.objects.filter(email=email).exists():
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                next_url = get_redirect_url(request)
                return HttpResponseRedirect(next_url or resolve_url(settings.LOGIN_REDIRECT_URL))
            else:
                return render(request, 'login.html', {"error_message": "Incorrect Password"})  # incorrect password
        else:
            return render(request, 'login.html', {"error_message": "User does not Exist"})  # user does not exist
    return render(request, 'login.html')


@login_required()
def admin_dashboard(request):
    if request.user.is_authenticated:
        return render(request, "dashboard.html")
    else:
        return redirect(resolve_url(settings.LOGIN_REDIRECT_URL))


def register(request):
    if request.method == "POST":

        email = request.POST.get('email').lower()
        username = request.POST.get('username').upper()
        first_name = request.POST.get('first_name').upper()
        surname = request.POST.get('surname').upper()
        password = request.POST.get('password')
        appointment = request.POST.get('appointment')
        photo = request.FILES.get('photo')

        try:
            new_user = user_model.objects.create_user(
                username=username,
                email=email,
                password=password,

                first_name=first_name,
                surname=surname,
                appointment=appointment,
                photo=photo

            )
            new_user.save()
        except (IntegrityError, ValueError) as e:
            return render(request, "authentication-signup.html", {'error_message': e})
        return redirect("/users/dashboard")
    else:
        return render(request, "authentication-signup.html")


@login_required()
def user_profile(request):
    return render(request, "user-profile.html")
