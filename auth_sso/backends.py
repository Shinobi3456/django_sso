from base64 import b64decode
from typing import Optional

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.contrib.auth.models import User


class KeycloakConfidentialBackend:

    @property
    def public_key(self):
        """Возвращает публичный ключ из Keycloak."""
        r = requests.get(f"{settings.KEYCLOAK_URL_BASE}realms/{settings.REALM_NAME}/")
        r.raise_for_status()
        key_der_base64 = r.json()["public_key"]
        key_der = b64decode(key_der_base64.encode())
        return serialization.load_der_public_key(key_der)

    @staticmethod
    def exchange_code_for_token(code: str) -> Optional[dict]:
        """Возвращает токен пользователя."""
        token_endpoint = f"{settings.KEYCLOAK_URL_BASE}realms/{settings.REALM_NAME}/protocol/openid-connect/token"
        payload = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': settings.CLIENT_ID,
            'client_secret': settings.CLIENT_SECRET,
            'redirect_uri': '/',
        }
        response = requests.post(token_endpoint, data=payload)
        if response.status_code == 200:
            return response.json()
        return None

    def decode_token(self, data: dict) -> dict:
        """Возвращает декодированные данные из токена."""
        access_token = data['access_token']
        decoded_token = jwt.decode(access_token, key=self.public_key, algorithms=['RS256'],
                                   audience=settings.KEYCLOAK_AUDIENCE)
        print(decoded_token)
        return decoded_token

    def authenticate(self, request, token: dict, **kwargs):
        # декодируем токен
        try:
            user_info = self.decode_token(token)
        except Exception:
            return None

        # Запрашиваем пользователя из базу данных Django
        user = self.get_user(user_info=user_info)

        # Если пользователь найден и токен действителен, вернем его
        return user

    def get_user(self, user_info) -> Optional[User]:
        user = User.objects.filter(username=user_info['preferred_username']).first()
        if settings.KEYCLOAK_IS_CREATE and not user:
            # Создание пользователя
            user = User.objects.create_user(
                username=user_info['preferred_username'],
                email=user_info['email'],
                last_name=user_info['given_name'],
                first_name=user_info['family_name']
            )

            # Установка пустого пароля
            user.set_unusable_password()

            # Сохранение пользователя
            user.save()
        return user
