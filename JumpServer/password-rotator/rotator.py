import argparse
import base64
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import string
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from email.utils import formatdate
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken


CONFIG = Path("/config")
SECRETS = Path("/secrets")
STATE = Path("/state")
USER = r"[a-z_][a-z0-9_-]{0,31}"
LABEL = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
SKIP_RESULTS = {"NOT_DUE", "NO_EXPIRY", "INELIGIBLE"}


class RotationError(Exception):
    pass


def match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise RotationError("invalid asset address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not match(r"(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", value):
            raise RotationError("invalid asset address") from None
        return value.lower()


@dataclass(frozen=True)
class Target:
    id: str
    asset_id: str
    account_id: str
    address: str
    port: int
    ssh_user: str
    target_user: str
    rsa_key_file: str
    discover_shell_accounts: bool = False
    password_account_id: str | None = None

    def __post_init__(self):
        if not match(LABEL, self.id) or not match(LABEL, self.rsa_key_file):
            raise RotationError("invalid target id or RSA key filename")
        if not match(USER, self.ssh_user) or not match(USER, self.target_user):
            raise RotationError("invalid Linux username")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise RotationError("invalid SSH port")
        if type(self.discover_shell_accounts) is not bool:
            raise RotationError("discover_shell_accounts must be boolean")
        if self.ssh_user == "root" or self.target_user == "root":
            raise RotationError("root accounts are ineligible")
        object.__setattr__(self, "asset_id", str(UUID(self.asset_id)))
        object.__setattr__(self, "account_id", str(UUID(self.account_id)))
        if self.password_account_id is not None:
            object.__setattr__(self, "password_account_id", str(UUID(self.password_account_id)))
        object.__setattr__(self, "address", address(self.address))

    @property
    def endpoint(self):
        return self.address, self.port, self.target_user


def load_settings():
    settings = json.loads((CONFIG / "settings.json").read_text())
    interval = settings["interval_seconds"]
    if type(interval) is not int or interval < 60 or type(settings["apply"]) is not bool:
        raise RotationError("interval_seconds must be at least 60 and apply must be boolean")
    targets = [Target(**item) for item in settings["targets"]]
    if not targets or len({item.id for item in targets}) != len(targets):
        raise RotationError("configure unique target IDs")
    if len({item.endpoint for item in targets}) != len(targets):
        raise RotationError("duplicate SSH endpoint and target user")
    return settings, targets


class JumpServer:
    def __init__(self, settings):
        url = urlsplit(settings["jumpserver_url"])
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.path not in {"", "/"} or url.query or url.fragment):
            raise RotationError("jumpserver_url must be a base HTTPS URL")
        self.server = url.hostname
        self.port = url.port
        self.organization = str(UUID(settings["organization_id"]))
        self.key_id = (SECRETS / "jms_access_key_id").read_text().strip()
        self.key_secret = (SECRETS / "jms_access_key_secret").read_bytes().strip()
        if not match(LABEL, self.key_id) or not self.key_secret:
            raise RotationError("invalid JumpServer access key files")
        self.tls = ssl.create_default_context()
        ca = CONFIG / "jumpserver-ca.pem"
        if ca.exists():
            self.tls.load_verify_locations(cafile=ca)

    def request(self, method, path, payload=None, *, sign_body=False):
        date = formatdate(usegmt=True)
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json", "Date": date, "X-JMS-ORG": self.organization}
        signed = f"(request-target): {method.lower()} {path}\naccept: application/json\ndate: {date}"
        signed_headers = "(request-target) accept date"
        if sign_body:
            digest_value = base64.b64encode(hashlib.sha256(body or b"").digest()).decode("ascii")
            headers["Digest"] = f"SHA-256={digest_value}"
            signed += f"\ndigest: {headers['Digest']}"
            signed_headers += " digest"
        digest = hmac.digest(self.key_secret, signed.encode(), "sha256")
        signature = base64.b64encode(digest).decode("ascii")
        authorization = (
            f'Signature keyId="{self.key_id}",algorithm="hmac-sha256",'
            f'headers="{signed_headers}",signature="{signature}"'
        )
        conn = http.client.HTTPSConnection(self.server, self.port, context=self.tls, timeout=15)
        try:
            headers["Authorization"] = authorization
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            if response.status != (201 if method == "POST" else 200):
                raise RotationError(f"JumpServer API {method} returned HTTP {response.status}")
            payload = response.read(2_000_001)
            if len(payload) > 2_000_000:
                raise RotationError("JumpServer API response exceeds size limit")
            result = json.loads(payload)
            if not isinstance(result, dict):
                raise RotationError("unexpected JumpServer API response")
            return result
        finally:
            conn.close()

    def validate(self, target):
        asset = self.request("GET", f"/api/v1/assets/assets/{target.asset_id}/")
        account = self.request("GET", f"/api/v1/accounts/accounts/{target.account_id}/")
        account_asset = account.get("asset")
        if isinstance(account_asset, dict):
            account_asset = account_asset.get("id")
        secret_type = account.get("secret_type")
        if isinstance(secret_type, dict):
            secret_type = secret_type.get("value")
        protocols = asset.get("protocols")
        ssh_ports = set()
        if isinstance(protocols, list):
            for item in protocols:
                if isinstance(item, dict) and item.get("name") == "ssh" and type(item.get("port")) is int:
                    ssh_ports.add(item["port"])
        if (asset.get("id") != target.asset_id or asset.get("is_active") is not True
                or address(asset.get("address")) != target.address or target.port not in ssh_ports):
            raise RotationError("registered asset is inactive or its address/SSH port differs from settings")
        if (account.get("id") != target.account_id or account.get("is_active") is not True
                or account_asset != target.asset_id or account.get("username") != target.ssh_user
                or secret_type != "ssh_key"):
            raise RotationError("registered account is inactive or is not the selected SSH key account")

    def registered_users(self, target):
        users = set()
        offset = 0
        while True:
            query = urlencode({"asset": target.asset_id, "limit": 100, "offset": offset, "order": "id"})
            page = self.request("GET", f"/api/v1/accounts/accounts/?{query}")
            rows = page.get("results")
            if not isinstance(rows, list) or len(rows) > 100:
                raise RotationError("unexpected JumpServer account page")
            for account in rows:
                asset = account.get("asset")
                asset_id = asset.get("id") if isinstance(asset, dict) else asset
                if asset_id != target.asset_id:
                    raise RotationError("JumpServer account filter returned a different asset")
                users.add(account["username"])
            if not page.get("next"):
                return users
            if not rows or offset >= 100_000:
                raise RotationError("JumpServer account pagination did not complete")
            offset += len(rows)

    def register_empty_account(self, target, username):
        account = self.request("POST", "/api/v1/accounts/accounts/", {
            "asset": target.asset_id, "name": username, "username": username,
            "secret_type": "password", "is_active": False, "privileged": False,
            "comment": "자동 발견 · 등록 시 비밀번호 미등록",
        })
        account_id = str(UUID(account["id"]))
        detail = self.request("GET", f"/api/v1/accounts/accounts/{account_id}/")
        if detail.get("has_secret") is not False or detail.get("is_active") is not False:
            raise RotationError("discovered account was not saved disabled with an empty secret")

    def password_version(self, target):
        reply = self.request(
            "GET", f"/api/v1/accounts/accounts/{target.password_account_id}/rotator-password/", sign_body=True,
        )
        version = reply.get("version")
        if (reply.get("asset_id") != target.asset_id or reply.get("username") != target.target_user
                or type(version) is not int or version < 0):
            raise RotationError("password synchronization account does not match the target")
        return version

    def sync_password(self, target, version, password):
        reply = self.request("PUT", f"/api/v1/accounts/accounts/{target.password_account_id}/rotator-password/", {
            "version": version, "password": password,
        }, sign_body=True)
        if reply.get("synchronized") is not True:
            raise RotationError("JumpServer did not confirm password synchronization")


def rsa_identity(target):
    key = SECRETS / target.rsa_key_file
    result = subprocess.run(
        ["ssh-keygen", "-y", "-P", "", "-f", str(key)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
    )
    if result.returncode or not result.stdout.startswith(b"ssh-rsa "):
        raise RotationError("unattended RSA private key is unreadable or invalid")
    return key


def remote(target, key, mode, password=None):
    command = [
        "ssh", "-F", "/dev/null", "-T", "-i", str(key), "-p", str(target.port),
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={CONFIG / 'known_hosts'}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
        "-o", "ConnectTimeout=10", "-l", target.ssh_user, "--", target.address,
        "sudo", "-n", "/usr/local/sbin/jms-password-rotate", mode, target.target_user,
    ]
    data = b"" if password is None else (password + "\n").encode("ascii")
    result = subprocess.run(command, input=data, capture_output=True, timeout=40)
    if mode == "discover":
        if result.returncode or len(result.stdout) > 256_000:
            raise RotationError(f"SSH helper discover failed (exit {result.returncode})")
        users = result.stdout.decode("ascii").splitlines()
        if not all(match(USER, user) and user != "root" for user in users):
            raise RotationError("SSH helper returned an invalid shell account")
        return set(users)
    valid = SKIP_RESULTS | ({"DUE"} if mode == "status" else {"CHANGED"})
    reply = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode or reply not in valid:
        raise RotationError(f"SSH helper {mode} failed (exit {result.returncode})")
    return reply


def generate_password():
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "_@%+=.-"]
    alphabet = "".join(groups)
    chars = [secrets.choice(group) for group in groups]
    chars.extend(secrets.choice(alphabet) for _ in range(28))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


@contextmanager
def vault():
    cipher = Fernet((SECRETS / "vault.key").read_bytes().strip())
    with (STATE / "rotator.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db = sqlite3.connect(STATE / "rotations.sqlite3")
        try:
            db.execute("PRAGMA synchronous = FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS rotations (
                id TEXT PRIMARY KEY, target TEXT NOT NULL,
                current BLOB, pending BLOB, updated_at TEXT,
                sync_account_id TEXT, sync_version INTEGER
            )""")
            with db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(rotations)")}
                if "sync_account_id" not in columns:
                    db.execute("ALTER TABLE rotations ADD COLUMN sync_account_id TEXT")
                if "sync_version" not in columns:
                    db.execute("ALTER TABLE rotations ADD COLUMN sync_version INTEGER")
            db.commit()
            yield db, cipher
        finally:
            db.close()


def finish(db, target_id, changed):
    with db:
        if changed:
            db.execute("UPDATE rotations SET current=pending, pending=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?", (target_id,))
        else:
            db.execute("UPDATE rotations SET pending=NULL, sync_account_id=NULL, sync_version=NULL WHERE id=?", (target_id,))


def synchronize(api, db, cipher, target, version, encrypted):
    api.sync_password(target, version, cipher.decrypt(encrypted).decode("ascii"))
    with db:
        db.execute("UPDATE rotations SET sync_account_id=NULL, sync_version=NULL WHERE id=?", (target.id,))
    logging.info("%s API_SYNCED", target.id)


def check_target(api, db, cipher, target, key, apply, force):
    identity = json.dumps([api.server, api.port or 443, api.organization, target.asset_id, *target.endpoint])
    row = db.execute("SELECT target, pending, current, sync_account_id, sync_version FROM rotations WHERE id=?", (target.id,)).fetchone()
    if row and row[0] != identity:
        raise RotationError("target ID belongs to a different asset or endpoint")
    if row and row[1] is not None:
        raise RotationError("pending change requires reconciliation before retry")
    if row and row[2] is not None:
        cipher.decrypt(row[2])
    if row and row[3] is not None:
        if row[3] != target.password_account_id or type(row[4]) is not int:
            raise RotationError("pending synchronization belongs to a different password account")
        logging.info("%s API_SYNC_PENDING", target.id)
        if apply:
            synchronize(api, db, cipher, target, row[4], row[2])
        return
    version = api.password_version(target) if target.password_account_id is not None else None
    result = remote(target, key, "status")
    if not apply or (result != "DUE" and not (force and result == "NOT_DUE")):
        logging.info("%s %s", target.id, result)
        if force:
            raise RotationError("requested password change did not run")
        return

    password = generate_password()
    encrypted = cipher.encrypt(password.encode("ascii"))
    with db:
        db.execute("""INSERT INTO rotations (id, target, pending, sync_account_id, sync_version) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET pending=excluded.pending,
                sync_account_id=excluded.sync_account_id, sync_version=excluded.sync_version""",
            (target.id, identity, encrypted, target.password_account_id, version),
        )
    # A missing acknowledgement leaves the committed pending password available for reconciliation.
    result = remote(target, key, "force" if force else "apply", password)
    finish(db, target.id, changed=result == "CHANGED")
    logging.info("%s %s", target.id, result)
    if result == "CHANGED" and version is not None:
        synchronize(api, db, cipher, target, version, encrypted)
    if force and result != "CHANGED":
        raise RotationError("requested password change was rejected")


def run_cycle(settings, targets, apply, force=False):
    failed = False
    api = JumpServer(settings)
    discovered_assets = set()
    with vault() as (db, cipher):
        for target in targets:
            try:
                api.validate(target)
                key = rsa_identity(target)
                if target.discover_shell_accounts and not force and target.asset_id not in discovered_assets:
                    try:
                        users = remote(target, key, "discover") - api.registered_users(target)
                        for user in sorted(users):
                            if apply:
                                api.register_empty_account(target, user)
                            logging.info("%s %s %s", target.id, user,
                                         "REGISTERED_NO_PASSWORD" if apply else "UNREGISTERED_SHELL_ACCOUNT")
                        if not users:
                            logging.info("%s NO_UNREGISTERED_SHELL_ACCOUNTS", target.id)
                        discovered_assets.add(target.asset_id)
                    except (RotationError, OSError, ValueError, http.client.HTTPException, subprocess.TimeoutExpired) as error:
                        logging.error("%s discovery failed: %s", target.id, error)
                        failed = True
                check_target(api, db, cipher, target, key, apply, force)
            except RotationError as error:
                logging.error("%s %s", target.id, error)
                failed = True
            except (OSError, ValueError, http.client.HTTPException, subprocess.TimeoutExpired, sqlite3.Error, InvalidToken) as error:
                logging.error("%s %s", target.id, type(error).__name__)
                failed = True
    return int(failed)


def manage(args):
    with vault() as (db, cipher):
        if args.action == "status":
            for target_id, current, pending, sync_pending, updated in db.execute(
                "SELECT id, current IS NOT NULL, pending IS NOT NULL, sync_account_id IS NOT NULL, updated_at FROM rotations ORDER BY id"
            ):
                status = "PENDING" if pending else "API_SYNC_PENDING" if sync_pending else "CHANGED" if current else "NO_CHANGE"
                print(target_id, status, updated or "-")
            return
        row = db.execute("SELECT current, pending FROM rotations WHERE id=?", (args.target,)).fetchone()
        if row is None:
            raise RotationError("target has no saved change")
        current, pending = row
        if args.action == "resolve":
            if pending is None:
                raise RotationError("target has no pending change")
            cipher.decrypt(pending)
            finish(db, args.target, changed=args.result == "changed")
            return
        if not sys.stdout.isatty():
            raise RotationError("password retrieval requires an interactive terminal")
        if pending is not None and not args.pending:
            raise RotationError("current password may be stale while a change is pending")
        selected = pending if args.pending else current
        if selected is None:
            raise RotationError("requested password is unavailable")
        print(cipher.decrypt(selected).decode("ascii"))


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    run = commands.add_parser("run")
    run.add_argument("--once", action="store_true", help="check once without changing passwords")
    rotate = commands.add_parser("rotate-now", help="change one configured account before expiry")
    rotate.add_argument("target")
    commands.add_parser("status")
    show = commands.add_parser("show")
    show.add_argument("target")
    show.add_argument("--pending", action="store_true")
    resolve = commands.add_parser("resolve")
    resolve.add_argument("target")
    resolve.add_argument("result", choices=["changed", "unchanged"])
    args = parser.parse_args()
    try:
        if args.action not in {"run", "rotate-now"}:
            manage(args)
            return 0
        settings, targets = load_settings()
        if args.action == "rotate-now":
            selected = [target for target in targets if target.id == args.target]
            if not selected:
                raise RotationError("requested target is not configured")
            return run_cycle(settings, selected, apply=True, force=True)
        if args.once:
            return run_cycle(settings, targets, apply=False)
        while True:
            run_cycle(settings, targets, apply=settings["apply"])
            time.sleep(settings["interval_seconds"])
    except RotationError as error:
        logging.error("%s", error)
    except Exception as error:
        logging.error("%s", type(error).__name__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
