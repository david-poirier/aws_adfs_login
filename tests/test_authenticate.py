import os

import aws_adfs_login

ENTRY_URL = os.environ['ADFS_ENTRY_URL']
USERNAME = os.environ.get('ADFS_USERNAME')
PASSWORD = os.environ.get('ADFS_PASSWORD')
VERIFICATION_CODE = os.environ.get('ADFS_VERIFICATION_CODE')

def test_interactive_auth():
    roles = aws_adfs_login.authenticate(ENTRY_URL)
    assert(len(roles) > 0)

def test_non_interactive_auth():
    roles = aws_adfs_login.authenticate(
            ENTRY_URL,
            username=USERNAME,
            password=PASSWORD,
            verification_code=VERIFICATION_CODE)
    assert(len(roles) > 0)

def test_get_credentials():
    roles = aws_adfs_login.authenticate(
            ENTRY_URL,
            username=USERNAME,
            password=PASSWORD,
            verification_code=VERIFICATION_CODE)
    assert(len(roles) > 0)
    for role in roles:
        creds = role.get_credentials()
        print('.', end='', flush=True)

