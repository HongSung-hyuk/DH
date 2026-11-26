import base64
import hashlib
import hmac
import json
import re
from email.utils import parsedate_to_datetime
from functools import lru_cache
from pathlib import Path
from time import time

from django.db import transaction
from rest_framework.exceptions import AuthenticationFailed, NotFound, ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.backends.drf import SignatureAuthentication
from orgs.utils import get_current_org

from .models import Account


@lru_cache(maxsize=1)
def rotation_binding():
    path = Path('/opt/jumpserver/password-rotator-sync.json')
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


class RotatorSignatureAuthentication(SignatureAuthentication):
    required_headers = ['(request-target)', 'date', 'digest']

    def validate_authenticated_request(self, request, user, key_id):
        try:
            date = parsedate_to_datetime(request.headers['Date'])
            valid_date = date.tzinfo is not None and abs(time() - date.timestamp()) <= 120
        except (KeyError, ValueError, TypeError, OverflowError):
            valid_date = False
        if not valid_date:
            raise AuthenticationFailed('The signed request date is outside the allowed window.')
        digest = base64.b64encode(hashlib.sha256(request.body).digest()).decode('ascii')
        if not hmac.compare_digest(request.headers.get('Digest', '').encode(), f'SHA-256={digest}'.encode()):
            raise AuthenticationFailed('The signed request digest does not match.')


class RotatorPasswordAPI(APIView):
    authentication_classes = [RotatorSignatureAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    renderer_classes = [JSONRenderer]

    def account(self, request, pk, *, for_update=False):
        binding = rotation_binding()
        if (not request.user.is_authenticated or not request.user.is_service_account
                or request.auth != binding.get('key_id') or str(pk) != binding.get('account_id')
                or str(get_current_org().id) != binding.get('org_id')
                or not request.user.has_perm('accounts.view_account')):
            raise NotFound()
        accounts = Account.objects.select_for_update() if for_update else Account.objects
        account = accounts.filter(
            id=pk, org_id=binding.get('org_id'), asset_id=binding.get('asset_id'),
            username=binding.get('username'), secret_type='password', is_active=True,
        ).first()
        if account is None or account.follows_template:
            raise NotFound()
        return account

    def get(self, request, pk):
        account = self.account(request, pk)
        return Response({'asset_id': str(account.asset_id), 'username': account.username, 'version': account.version})

    @transaction.atomic
    def put(self, request, pk):
        account = self.account(request, pk, for_update=True)
        data = request.data
        if not isinstance(data, dict) or data.keys() != {'password', 'version'}:
            raise ValidationError('Expected a password and the previous account version.')
        password, version = data['password'], data['version']
        if (not isinstance(password, str) or not re.fullmatch(r'[A-Za-z0-9_@%+=.\-]{32}', password)
                or type(version) is not int or version < 0):
            raise ValidationError('Invalid password or account version.')
        previous = account.secret or ''
        if hmac.compare_digest(previous.encode('utf-8'), password.encode('ascii')):
            return Response({'synchronized': True})
        if version != account.version:
            return Response({'detail': 'The account changed since the rotation started.'}, status=409)
        account.secret = password
        account.save()
        return Response({'synchronized': True})
