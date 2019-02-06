#! /usr/bin/env python3

import argparse
import sys
from req_ext_helpers import *
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import configparser

def gen_csr(key, subject, extensions):
  builder = x509.CertificateSigningRequestBuilder()
  builder = builder.subject_name(x509.Name(subject))
  for ext in extensions:
    builder = builder.add_extension(ext[0], critical=ext[1])
  # Sign the CSR with our private key.
  csr = builder.sign(key, hashes.SHA512(), default_backend())
  return csr

def main(argdata):
  config = configparser.RawConfigParser()
  config.read('config.ini')

  country=config.get('DEFAULT','country');
  state=config.get('DEFAULT','state');
  city=config.get('DEFAULT','city');
  organization=config.get('DEFAULT','organization');
  common_name=config.get('DEFAULT','common_name');
  if argdata.cn: common_name = argdata.cn

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

  key = rsa.generate_private_key(public_exponent=65537,key_size=4096,backend=default_backend())
  ext_list = []
  ext_list.append((gen_alt_name(alt_names), False))
  ext_list.append((gen_basic_key_usage(), False))
  ext_list.append((gen_extended_key_usage(), False))

  csr = gen_csr(key,subject,ext_list)

  with open(cn + ".key", "wb") as f:
      f.write(key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
      ))

  with open(cn + ".csr", "wb") as f:
      f.write(csr.public_bytes(serialization.Encoding.PEM))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='issuecert')
    parser.add_argument('cn', metavar='common name', type=str, nargs='?', help='common name',)
    arg_data = parser.parse_args()
    try:
        main(arg_data)
    except KeyboardInterrupt:
        print("\nAborted by user!")
        sys.exit()