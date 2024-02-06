#! /usr/bin/env python3

import sys
import getpass
import csv
import datetime

from os.path import exists

from cryptography import x509

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

#from python_simple_ca.genreq import gen_csr
from python_simple_ca.issuecert import gen_serial
from python_simple_ca.req_ext_helpers import *



import configparser


def main():
  if exists("ca.crt"):
    print("There already exists a ca in this directory!")
    cont = input("Do you REALLY want to continue? [y/N]: ")
    if cont != "y" and cont != "Y":
       print("Aborting!...")
       sys.exit()

  try:
    config = configparser.ConfigParser(interpolation=None)
    f = open('config.ini','r')
    config.read_file(f)
  except (configparser.ParsingError, FileNotFoundError):
    print("Invalid config file: 'config.ini'" , file=sys.stderr)
    sys.exit(1)

  cnf_section='DEFAULT'
  common_name=""

  country=config.get(cnf_section,'country')
  state=config.get(cnf_section,'state')
  city=config.get(cnf_section,'city')
  organization=config.get(cnf_section,'organization')
  ou=config.get(cnf_section,'ou',fallback='')
  san=config.get(cnf_section,'san',fallback='')
  privpass=config.get(cnf_section,'passphrase',fallback='')
  keysize=config.getint(cnf_section,'keysize',fallback=4096)

  subject = []

  print("Now create a new Certificate Authority. Please enter the following details")
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

  lifetime = 5
  while True:
    tmp_lifetime=input("Certificate Lifetime: [5]: ")
    if not tmp_lifetime:
      break
    try:
      i_lifetime = int(tmp_lifetime)
      if i_lifetime > 0 and i_lifetime < 11:
        lifetime = i_lifetime
        break
    except ValueError: 
      pass
    print("Please enter a valid number between 1 and 10")

  key = rsa.generate_private_key(public_exponent=65537,key_size=keysize,backend=default_backend())
  pubkey = key.public_key()
  serial = gen_serial()
  d_now = datetime.datetime.utcnow()
  valid_before = d_now - datetime.timedelta(0, 100, 0)
  valid_after = datetime.datetime(d_now.year + lifetime, d_now.month, d_now.day, d_now.hour, d_now.minute, d_now.second)
  subject = x509.Name(subject)

  builder = x509.CertificateBuilder()
  builder = builder.subject_name(subject)
  builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
  builder = builder.add_extension(gen_ca_basic_key_usage(), critical=True)
  builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey),critical=False)
  builder = builder.public_key(pubkey)
  builder = builder.not_valid_before(valid_before).not_valid_after(valid_after)
  builder = builder.serial_number(serial)
  builder = builder.issuer_name(subject)

  certificate = builder.sign(key,hashes.SHA512(),default_backend())

  with open("ca.key", "wb") as f:
      enc_alg = serialization.NoEncryption()
      privpass = getpass.getpass("Please enter key password: ")
      if privpass:
        enc_alg = serialization.BestAvailableEncryption(privpass.encode('UTF-8'))
      f.write(key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=enc_alg,
      ))

 # Update serial list
  with open("serials.txt", "a") as f:
    f.write(str(serial)+"\n")

  hex_serial =  '{:x}'.format(serial)
  with open("certs.csv","a") as csvfile:
    out = ':'.join(hex_serial[i:i+2] for i in range(0, len(hex_serial), 2))
    writer = csv.writer(csvfile,dialect='unix')
    writer.writerow([out,valid_before.isoformat(),valid_after.isoformat(),subject.rfc4514_string()])
    csvfile.close()

  # Write signed certificate to file
  filename = "ca.crt"
  with open(filename, "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))




def console_entry():
  try:
    main()
  except KeyboardInterrupt:
    print("\nAborted by user!")
    sys.exit()
