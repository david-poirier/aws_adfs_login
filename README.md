# aws_adfs_login

Python 3.6+ library to enable ADFS auth against AWS

## Usage

```python
import aws_adfs_login

roles = aws_adfs_login.authenticate(
    'https://adfs-server/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices')
for role in roles:
    credentials = role.get_credentials()
    key_id, secret, session_token, expiry = credentials
```

