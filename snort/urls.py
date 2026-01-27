from django.urls import path
from . import views

app_name = "snort"

urlpatterns = [
    path("logs/", views.logs, name="logs"),
    path("rules/", views.rules, name="rules"),

    # Tambahan baru
    path("whitelist/", views.ip_whitelist, name="ip_whitelist"),
    path("blocklist/", views.ip_blocklist, name="ip_blocklist"),
]
