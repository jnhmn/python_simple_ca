#! /usr/bin/env python3

import sys
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

one_day = datetime.timedelta(1, 0, 0)
valid_before = datetime.datetime.today() - datetime.timedelta(0, 100, 0)
valid_after = datetime.datetime.today() + 365*one_day

with open("jnhmn.de.csr", "rb") as f:
  plaincsr = f.read()
  f.close()
  csr = x509.load_pem_x509_csr(plaincsr,default_backend())
  if not csr.is_signature_valid:
    sys.exit(1)
  subject = csr.subject
  ext_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
  ext_keyuse = csr.extensions.get_extension_for_class(x509.KeyUsage).value
  pubkey = csr.public_key()
  print(subject)
  print(ext_san)
  print(ext_keyuse)


  builder = x509.CertificateBuilder().subject_name(subject).add_extension(ext_san,\
  critical=False).add_extension(ext_keyuse, critical=False).not_valid_before(\
  valid_before).not_valid_after(valid_after).public_key(pubkey)
  print(builder)
