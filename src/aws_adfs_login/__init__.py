import base64
import getpass
import urllib
import xml.etree.ElementTree

import boto3
import bs4
import requests


class AwsRole:
    def __init__(self, saml_assertion, role_arn, principal_arn):
        self.saml_assertion = saml_assertion
        self.role_arn = role_arn
        self.principal_arn = principal_arn

        # arn:aws:iam::12345:role/Example_Role_Name
        role_parts = role_arn.split(':')
        self.account = role_parts[4]
        self.role_name = role_parts[5].split('/')[-1]

    def get_credentials(self, duration_seconds=60*60):
        client = boto3.client('sts')
        result = client.assume_role_with_saml(
                RoleArn=self.role_arn,
                PrincipalArn=self.principal_arn,
                SAMLAssertion=self.saml_assertion,
                DurationSeconds=duration_seconds)

        key_id = result['Credentials']['AccessKeyId']
        secret = result['Credentials']['SecretAccessKey']
        session_token = result['Credentials']['SessionToken']
        expiry = result['Credentials']['Expiration']

        credentials = AwsCredentials(
                key_id, secret, session_token, expiry)
        return credentials


class AwsCredentials:
    def __init__(self, key_id, secret, session_token, expiry):
        self.key_id = key_id
        self.secret = secret
        self.session_token = session_token
        self.expiry = expiry

    def get_client(self, service, region_name='us-east-1'):
        client = boto3.client(
                service,
                region_name=region_name,
                aws_access_key_id=self.key_id,
                aws_secret_access_key=self.secret,
                aws_session_token=self.session_token)
        return client


def _input(name, obfuscate=False):
    while True:
        if obfuscate:
            value = getpass.getpass(f'{name}: ')
        else:
            value = input(f'{name}: ')
        if len(value) > 0:
            return value


def _login(session, login_url, username, password):
    while True:
        if username is None:
            username = _input('Username')
        if password is None:
            password = _input('Password', obfuscate=True)

        headers = {
                'PreAuthenticate': 'True'
                }
        data = {
                'UserName': username,
                'Password': password,
                'AuthMethod': 'FormsAuthentication'
                }

        r = session.post(login_url, headers=headers, data=data, allow_redirects=False)
        # redirect == success
        if r.status_code == 302:
            next_url = r.headers['Location']
            r = session.get(next_url)
            return r
        print('Login failed, try harder')
        username = None
        password = None


def _verify_code(session, r, verification_code):
    while True:
        if verification_code is None:
            verification_code = _input('Verification code', obfuscate=True)

        # 'auto-submit' the initial form
        soup = bs4.BeautifulSoup(r.text, 'html.parser')
        verification_url = soup.find('form', {'id': 'options'}).get('action')
        auth_method = soup.find(id='authMethod').get('value')
        context = soup.find(id='context').get('value')

        headers = {
                'Referer': r.url
                }
        data = {
                'AuthMethod': auth_method,
                'Context': context,
                }
        r = session.post(verification_url, headers=headers, data=data, allow_redirects=False)

        # 'fill in' the 'OathCode' on the subsequent form
        soup = bs4.BeautifulSoup(r.text, 'html.parser')
        verification_url = soup.find('form', {'id': 'options'}).get('action')
        auth_method = soup.find(id='authMethod').get('value')
        context = soup.find(id='context').get('value')

        headers = {
                'Referer': r.url
                }
        data = {
                'AuthMethod': auth_method,
                'Context': context,
                'OathCode': verification_code
                }

        r = session.post(verification_url, headers=headers, data=data, allow_redirects=False)
        # redirect == success
        if r.status_code == 302:
            next_url = r.headers['Location']
            r = session.get(next_url)
            return r

        print('Verification failed, try harder...')

        # click on 'try again' button
        soup = bs4.BeautifulSoup(r.text, 'html.parser')
        verification_url = soup.find('form', {'id': 'options'}).get('action')
        auth_method = soup.find(id='authMethod').get('value')
        context = soup.find(id='context').get('value')
        headers = {
                'Referer': r.url
                }
        data = {
                'AuthMethod': auth_method,
                'Context': context,
                '__EVENTTARGET': 'differentVerificationOption'
                }
        r = session.post(verification_url, headers=headers, data=data, allow_redirects=False)

        # reset code
        verification_code = None


def _process_saml_assertion(_r):
    roles = []
    soup = bs4.BeautifulSoup(_r.text, 'html.parser')
    assertion = soup.find('input', {'name': 'SAMLResponse'}).get('value')
    assertion_xml = xml.etree.ElementTree.fromstring(base64.b64decode(assertion))
    for saml2attribute in assertion_xml.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                role = saml2attributevalue.text
                role_parts = role.split(',')
                if 'saml-provider' in role_parts[0]:
                    principal_arn = role_parts[0]
                    role_arn = role_parts[1]
                else:
                    role_arn = role_parts[0]
                    principal_arn = role_parts[1]
                roles.append(AwsRole(assertion, role_arn, principal_arn))
    return roles


def authenticate(entry_url, username=None, password=None, verification_code=None):
    s = requests.Session()
    r = _login(s, entry_url, username, password)

    if 'verification code' in r.text.lower():
        r = _verify_code(s, r, verification_code)

    roles = _process_saml_assertion(r)
    return roles

