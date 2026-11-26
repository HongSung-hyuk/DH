from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from rest_framework.exceptions import PermissionDenied, ValidationError

from acls.models import LoginAssetACL
from assets.const import Protocol
from authentication.api.connection_token import ConnectionTokenViewSet
from authentication.const import MFAType
from authentication.services.connection_acl import acl_state, validate_connection_policy
from authentication.services.connection_acl_batch import advance_acl_batch
from settings.api.settings import SettingsApi
from settings.models import Setting


@override_settings(ASSET_CONNECTION_OTP_REQUIRED=True)
class AssetConnectionOTPTests(SimpleTestCase):
    def setUp(self):
        self.view = ConnectionTokenViewSet()
        otp = SimpleNamespace(
            name=MFAType.OTP.value, display_name='OTP', has_code=True,
            challenge_required=lambda: False,
        )
        email = SimpleNamespace(name='email', has_code=True)
        self.user = SimpleNamespace(
            active_mfa_backends_mapper={otp.name: otp, email.name: email},
            active_mfa_backends=(otp, email),
        )
        self.view.request = SimpleNamespace(user=self.user)
        self.account = SimpleNamespace(username='asset-user')
        self.asset = object()
        setting_filter = patch.object(Setting.objects, 'filter')
        self.setting_query = setting_filter.start()
        self.setting_query.return_value.first.return_value = None
        self.addCleanup(setting_filter.stop)
        for patched in (
            patch.object(LoginAssetACL, 'get_match_rule_acls', return_value=None),
            patch.object(LoginAssetACL, 'filter_queryset', return_value=[]),
            patch('authentication.api.connection_token.get_request_ip_or_data', return_value='127.0.0.1'),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def create_context(self, protocol):
        return self.view._validate_acl(self.user, self.asset, self.account, 'web_cli', protocol)

    def token(self, protocol, context, *, reusable=False):
        return SimpleNamespace(
            protocol=protocol, acl_context=context, is_reusable=reusable,
            user=self.user, asset=self.asset, remote_addr='127.0.0.1',
        )

    def test_ssh_and_rdp_are_pending_until_otp_passes(self):
        for protocol in (Protocol.ssh, Protocol.rdp):
            with self.subTest(protocol=protocol):
                context = self.create_context(protocol)
                token = self.token(protocol, context)
                self.assertEqual(context['requirements'], {'mfa': 'pending'})
                self.assertEqual([method['value'] for method in acl_state(token)['mfa_methods']], [MFAType.OTP.value])
                validate_connection_policy(token, self.account, require_complete=False)
                with self.assertRaises(PermissionDenied):
                    validate_connection_policy(token, self.account)
                context['requirements']['mfa'] = 'passed'
                validate_connection_policy(token, self.account)
                token.is_reusable = True
                with self.assertRaises(PermissionDenied):
                    validate_connection_policy(token, self.account)

    def test_preexisting_token_and_unenrolled_user_are_denied(self):
        with self.assertRaises(PermissionDenied):
            validate_connection_policy(self.token(Protocol.ssh, {}), self.account)
        self.user.active_mfa_backends_mapper.pop(MFAType.OTP.value)
        with self.assertRaises(PermissionDenied):
            self.create_context(Protocol.ssh)

    def test_multiple_connections_cannot_share_one_otp_challenge(self):
        tokens = [self.token(protocol, self.create_context(protocol)) for protocol in (Protocol.ssh, Protocol.rdp)]
        with self.assertRaises(ValidationError):
            advance_acl_batch(tokens, self.view.request, {'step': 'mfa'})

    def test_other_protocols_and_disabled_policy_are_unchanged(self):
        self.assertEqual(self.create_context(Protocol.sftp), {})
        with self.settings(ASSET_CONNECTION_OTP_REQUIRED=False):
            self.assertEqual(self.create_context(Protocol.ssh), {})

    def test_saved_policy_takes_effect_even_with_an_older_worker_default(self):
        setting = SimpleNamespace(cleaned_value=False)
        self.setting_query.return_value.first.return_value = setting
        self.assertEqual(self.create_context(Protocol.ssh), {})
        setting.cleaned_value = True
        self.assertEqual(self.create_context(Protocol.ssh)['requirements'], {'mfa': 'pending'})

    def test_enabling_policy_does_not_invalidate_existing_sessions(self):
        token = self.token(Protocol.ssh, {})
        validate_connection_policy(token, self.account, check_asset_otp=False)
        with self.assertRaises(PermissionDenied):
            validate_connection_policy(token, self.account)

    def test_policy_endpoint_has_only_one_field_and_requires_security_permission(self):
        view = SettingsApi()
        view.request = SimpleNamespace(query_params={'category': 'asset_connection_otp'})
        self.assertEqual(set(view.get_serializer_class()().fields), {'ASSET_CONNECTION_OTP_REQUIRED'})
        self.assertEqual(view.rbac_category_permissions[view.get_category()], 'settings.change_security')
        self.assertEqual(view.get_object(), {'ASSET_CONNECTION_OTP_REQUIRED': True})
