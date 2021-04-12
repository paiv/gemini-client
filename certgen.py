#!/usr/bin/env python
import datetime
import readline
import sys
try:
    from cryptography import x509
except ModuleNotFoundError:
    setup_guide = '''This script requires cryptography module.
Alternatively, self-signed certificate could be generated with:
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem
'''
    print(setup_guide, end='', file=sys.stderr)
    exit(1)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main(key_size=2048, password=False, cn=None, country=None, state=None, lifetime=365, outfile=None):
    now = datetime.datetime.utcnow()
    lifetime = datetime.timedelta(days=(lifetime or 365))
    if cn is None:
        cn = input('Common Name (your name): ')

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    attribs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if country:
        attribs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        attribs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    iname = x509.Name(attribs)
    builder = builder.subject_name(iname)
    builder = builder.issuer_name(iname)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + lifetime)
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    encryption = serialization.NoEncryption()

    if password:
        import getpass
        password = getpass.getpass('Enter password: ')
        encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption)

    if outfile:
        so = open(outfile, 'wb')
    else:
        so = sys.stdout.buffer

    so.write(key_pem)
    so.write(cert_pem)

    if outfile:
        so.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--key_size', metavar='N', type=int, default=2048, help='Private key bit size')
    parser.add_argument('-p', '--password', action='store_true', help='Set container password (interactive)')
    parser.add_argument('-cn', '--common-name', metavar='CN', help='Certificate Common Name (your name)')
    parser.add_argument('--country', metavar='S', help='Issuer country code')
    parser.add_argument('--state', metavar='S', help='Issuer state')
    parser.add_argument('-t', '--lifetime', metavar='DAYS', type=int, help='Certificate lifetime (days)')
    parser.add_argument('-o', '--output', metavar='FILE', help='Output file name (.pem)')
    args = parser.parse_args()

    main(key_size=args.key_size, password=args.password,
        cn=args.common_name, country=args.country, state=args.state,
        lifetime=args.lifetime, outfile=args.output)
