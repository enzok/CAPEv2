from django.conf import settings
from django.shortcuts import redirect, render

try:
    from django_ratelimit.exceptions import Ratelimited
except ImportError:
    try:
        from ratelimit.exceptions import Ratelimited
    except ImportError:
        print("missed dependency: poetry run pip install django-ratelimit -U")


from django.urls import resolve, Resolver404


def handler403(request, exception=None):
    if isinstance(exception, Ratelimited):
        return render(request, "error.html", {"error": settings.RATELIMIT_ERROR_MSG}, status=429)
    return render(request, "error.html", {"error": "Forbidden"}, status=403)


def handler404(request, exception=None):
    if settings.APPEND_SLASH and not request.path_info.endswith("/"):
        urlconf = getattr(request, "urlconf", None)
        try:
            resolve(request.path_info + "/", urlconf)
            return redirect(request.get_full_path(force_append_slash=True), permanent=True)
        except Resolver404:
            pass
    return redirect("/")

