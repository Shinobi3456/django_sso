from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import logout


from auth_sso.backends import KeycloakConfidentialBackend


@login_required(redirect_field_name='next', login_url='/login/')
def home_page(request):
    return render(request, 'auth_sso/home.html')


def login_page(request):
    if request.user:
        if request.user.is_authenticated:
            return redirect('/')
    return render(request, 'auth_sso/index.html')


def keycloak_login(request):
   """
   Перенаправление пользователя на страницу аутентификации Keycloak.

   settings.KEYCLOAK_URL_BASE - путь до Keycloak c доменом
   settings.REALM_NAME - это название пространства Realm, задает при настройке Keycloak
   settings.CLIENT_ID - клиент относительно Keycloak это наше приложение
   """
   redirect_url = f"{settings.KEYCLOAK_URL_BASE}realms/{settings.REALM_NAME}/protocol/openid-connect/auth" \
                  f"?client_id={settings.CLIENT_ID}&response_type=code"

   return redirect(redirect_url)


def keycloak_callback(request):
    # Получите токен и информацию о пользователе из запроса
    try:
        code = request.GET['code']
    except Exception:
        return redirect('/login')  # Замените на свой шаблон ошибки

    backend = KeycloakConfidentialBackend()
    data_token = backend.exchange_code_for_token(code)
    if not data_token:
        return redirect('/login')

    # Аутентифицируйте пользователя в Django
    user = backend.authenticate(request, token=data_token)

    if user is not None:
        login(request, user)
        # Пользователь успешно аутентифицирован, теперь вы можете перенаправить его на другую страницу
        return redirect('/')  # Замените на путь, куда вы хотите перенаправить пользователя
    else:
        # Обработка случая, если аутентификация не удалась
        return render(request, 'auth_failed.html')  # Замените на свой шаблон ошибки


def logout_view(request):
    logout(request)
    return redirect('/login/')
