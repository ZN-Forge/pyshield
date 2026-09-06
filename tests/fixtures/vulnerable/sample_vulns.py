"""Fixture file containing intentional security vulnerabilities for scanner testing."""

import hashlib
import os
import random
import subprocess
from Crypto.Cipher import DES

# PS201: Hardcoded credential
PASSWORD = "fake_hardcoded_password_12345!"

# PS202: Private key material
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0fakekeydatafakekeydatafakekeydata
-----END RSA PRIVATE KEY-----"""

# PS203: High-confidence API token (obviously synthetic/fake)
AWS_KEY = "AKIA9988776655443322"


def trigger_eval(user_data: str):
    # PS101
    return eval(user_data)


def trigger_exec(code_str: str):
    # PS102
    exec(code_str)


def trigger_os_system(cmd: str):
    # PS103
    os.system(cmd)


def trigger_subprocess(cmd: str):
    # PS104
    subprocess.run(cmd, shell=True)


def trigger_weak_hash(data: bytes):
    # PS301
    return hashlib.md5(data).hexdigest()


def trigger_insecure_crypto(key: bytes):
    # PS302
    return DES.new(key)


def trigger_insecure_random():
    # PS303
    auth_token = str(random.random())
    return auth_token
