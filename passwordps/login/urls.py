from django.conf.urls import url
from login.views import login

urlpatterns = [
    url(r'^$', login),
]
