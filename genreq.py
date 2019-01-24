#! /usr/bin/env python3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from ipaddress import IPv4Address
from ipaddress import IPv6Address
from ipaddress import AddressValueError

import configparser

def gen_alt_name(list):
  alt_name_objs = []
  for name in list:
    try:
      addr = IPv4Address(name)
      alt_name_objs.append(x509.IPAddress(addr))
      continue
    except AddressValueError:
      pass

    try:
      addr = IPv6Address(name)
      alt_name_objs.append(x509.IPAddress(addr))
      continue
    except AddressValueError:
      pass

    alt_name_objs.append(x509.DNSName(name))
  return x509.SubjectAlternativeName(alt_name_objs)

config = configparser.RawConfigParser()
config.read('config.ini')

country=config.get('DEFAULT','country');
state=config.get('DEFAULT','state');
city=config.get('DEFAULT','city');
organization=config.get('DEFAULT','organization');
common_name=config.get('DEFAULT','common_name');

subject = []
alt_names = set()

print("Now create certificate signing request. Please enter the following details")
print("Leaving it empty confirms the default values")
print("Submitting a dot clears the value")
print("\n")
tmp_country=input("Country: [" + country +"]: ")
if not tmp_country:
    subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
elif tmp_country != ".":
    subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, tmp_country))

tmp_state=input("State: [" + state +"]: ")
if not tmp_state:
    subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
elif tmp_state != ".":
    subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, tmp_state))

tmp_city=input("City: [" + city +"]: ")
if not tmp_city:
  subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
elif tmp_city != ".":
  subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, tmp_city))

tmp_organization=input("Organization: [" + organization +"]: ")
if not tmp_organization:
  subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
elif tmp_organization != ".":
  subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, tmp_organization))

cn = ""
tmp_common_name=input("Common Name: [" + common_name +"]: ")
if not tmp_common_name:
  subject.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
  cn = common_name
elif tmp_common_name != ".":
  subject.append(x509.NameAttribute(NameOID.COMMON_NAME, tmp_common_name))
  cn = tmp_common_name

alt_names.add(cn)
print("\nEnter Alternative names")
print("Leaving it empty continues")
while True:
  name = input("Alternatvie name: ")
  if not name:
    break;
  else:
    alt_names.add(name)

key = rsa.generate_private_key(public_exponent=65537,key_size=4096,backend=default_backend());

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).add_extension(gen_alt_name(alt_names),
    critical=False,
).add_extension(
    x509.KeyUsage(content_commitment=True,digital_signature=True,key_encipherment=True,data_encipherment=False,key_agreement=True,key_cert_sign=False,crl_sign=False,decipher_only=False, encipher_only=False),critical=False
# Sign the CSR with our private key.
).sign(key, hashes.SHA256(), default_backend())

with open(cn + ".key", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))

with open(cn + ".csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

