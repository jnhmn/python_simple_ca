#! /usr/bin/env python3

import sys
import datetime

import getpass

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def load_csr(path):
  f = open(path,"rb")
  plaincsr = f.read()
  f.close()
  csr = x509.load_pem_x509_csr(plaincsr,default_backend())
  if not csr.is_signature_valid:
    sys.exit(1)
  subject = csr.subject
  ext_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
  ext_keyuse = csr.extensions.get_extension_for_class(x509.KeyUsage).value
  ext_extdkeyuse = csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
  pubkey = csr.public_key()

  builder = x509.CertificateBuilder()
  builder = builder.subject_name(subject)
  builder = builder.add_extension(ext_san, critical=False)
  builder = builder.add_extension(ext_keyuse, critical=False)
  builder = builder.add_extension(ext_extdkeyuse, critical=False)
  builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey),critical=False)
  builder = builder.public_key(pubkey)
  return builder

def gen_serial():
  try:
    serial_list = set(line.strip() for line in open('serials.txt'))
  except FileNotFoundError:
    serial_list = set()
  serial = x509.random_serial_number()
  while serial in serial_list:
    serial = x509.random_serial_number()
  return serial

serial = gen_serial()
one_day = datetime.timedelta(1, 0, 0)
valid_before = datetime.datetime.utcnow() - datetime.timedelta(0, 100, 0)
valid_after = datetime.datetime.utcnow() + 365*one_day

builder = load_csr("jnhmn.de.csr")
print(builder)
builder = builder.not_valid_before(valid_before).not_valid_after(valid_after)
builder = builder.serial_number(serial)

fhdl_ca_pub = open("ca.crt","rb")
ca_pub = x509.load_pem_x509_certificate(fhdl_ca_pub.read(),default_backend())
fhdl_ca_pub.close()
builder = builder.issuer_name(ca_pub.subject)
builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pub.public_key()), critical=False)

fhdl_ca_priv = open("ca.key","rb")
passwd = getpass.getpass("Please enter password: ")
ca_priv = serialization.load_pem_private_key(fhdl_ca_priv.read(),bytes(passwd, 'utf-8'),default_backend())
fhdl_ca_priv.close()

certificate = builder.sign(ca_priv,hashes.SHA256(),default_backend())
print("\n")
print(certificate)
with open("serials.txt", "a") as f:
  f.write(str(serial)+"\n")

with open("jnhmn.crt", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))
