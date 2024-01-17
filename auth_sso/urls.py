from django.urls import path

from auth_sso.views import keycloak_login, keycloak_callback, home_page, login_page, logout_view

urlpatterns = [
    path('', home_page, name='home_page'),
    path('login/', login_page, name='login_page'),
    path('keycloak_login/', keycloak_login, name='keycloak_login'),
    path('keycloak_callback/', keycloak_callback, name='keycloak_callback'),
    path('logout/', logout_view, name='logout_page'),
]
