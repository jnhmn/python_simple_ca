#! /usr/bin/env python3

import argparse
import sys
from python_simple_ca.req_ext_helpers import *
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
  config = configparser.ConfigParser(interpolation=None)
  config.read('config.ini')

  if argdata.cn:
    if config.has_section(argdata.cn):
      cnf_section=argdata.cn
      common_name=config.get(cnf_section,'common_name', fallback=argdata.cn)
    else:
      cnf_section='DEFAULT'
      common_name=argdata.cn
  else:
    cnf_section='DEFAULT'
    common_name=""

  country=config.get(cnf_section,'country')
  state=config.get(cnf_section,'state')
  city=config.get(cnf_section,'city')
  organization=config.get(cnf_section,'organization')
  ou=config.get(cnf_section,'ou',fallback='')
  san=config.get(cnf_section,'san',fallback='')
  privpass=config.get(cnf_section,'passphrase',fallback='')

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

  tmp_ou=input("Organizational Unit: [" + ou +"]: ")
  ou_list = [];
  if not tmp_ou:
    ou_list = split_multivalues(ou)
  elif tmp_ou != ".":
    ou_list = split_multivalues(tmp_ou)
  for element in  ou_list:
    subject.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, element))

  cn = ""
  tmp_common_name=input("Common Name: [" + common_name +"]: ")
  if not tmp_common_name:
    subject.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    cn = common_name
  elif tmp_common_name != ".":
    subject.append(x509.NameAttribute(NameOID.COMMON_NAME, tmp_common_name))
    cn = tmp_common_name

  print("\nEnter Alternative names")
  alt_names = set(split_multivalues(san))
  if alt_names:
    print("Following Subject Alternative Names are preconfigured")
    for element in alt_names:
      print("- " +element)
    print()
    print("Submitting a dot clears the list")
  alt_names.add(cn)
  print("Leaving it empty continues")
  while True:
    name = input("Alternatvie name: ")
    if not name:
      break;
    if name == '.':
      alt_names = set()
      alt_names.add(cn)
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
      enc_alg = serialization.NoEncryption()
      if privpass:
        enc_alg = serialization.BestAvailableEncryption(privpass.encode('UTF-8'))
      f.write(key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=enc_alg,
      ))

  with open(cn + ".csr", "wb") as f:
      f.write(csr.public_bytes(serialization.Encoding.PEM))


def console_entry():
    parser = argparse.ArgumentParser(prog='issuecert')
    parser.add_argument('cn', metavar='common name', type=str, nargs='?', help='common name',)
    arg_data = parser.parse_args()
    try:
        main(arg_data)
    except KeyboardInterrupt:
        print("\nAborted by user!")
        sys.exit()

if __name__ == '__main__':
    console_entry()
