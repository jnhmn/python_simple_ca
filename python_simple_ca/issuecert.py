#! /usr/bin/env python3

import sys
import datetime
import csv
import argparse

import getpass

from python_simple_ca.ext_print import *

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
  pubkey = csr.public_key()

  builder = x509.CertificateBuilder()
  builder = builder.subject_name(subject)

  try:
    ext_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    builder = builder.add_extension(ext_san, critical=False)
  except: pass

  try:
    ext_keyuse = csr.extensions.get_extension_for_class(x509.KeyUsage).value
    builder = builder.add_extension(ext_keyuse, critical=False)
  except: pass

  try:
    ext_extdkeyuse = csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    builder = builder.add_extension(ext_extdkeyuse, critical=False)
  except: pass

  builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey),critical=False)
  builder = builder.public_key(pubkey)
  return [subject, builder]

printspecial = {
  x509.OID_SUBJECT_ALTERNATIVE_NAME: print_san,
  x509.OID_KEY_USAGE: print_kuse,
  x509.OID_EXTENDED_KEY_USAGE: print_extkuse,
  x509.OID_SUBJECT_KEY_IDENTIFIER: print_skeyid
}

def print_csr(builder):
  sn = builder._subject_name
  print("Subject: "+sn.rfc4514_string())
  print()
  extensions = builder._extensions
  for ext in extensions:
    print(ext.oid._name + "\tCritical: "+str(ext._critical))
    printspecial.get(ext.oid,print)(ext)
    print()

def gen_serial():
  try:
    serial_list = set(line.strip() for line in open('serials.txt'))
  except FileNotFoundError:
    serial_list = set()
  serial = x509.random_serial_number()
  while serial in serial_list:
    serial = x509.random_serial_number()
  return serial

def main(arg_data):
  serial = gen_serial()
  one_day = datetime.timedelta(1, 0, 0)
  valid_before = datetime.datetime.utcnow() - datetime.timedelta(0, 100, 0)
  valid_after = datetime.datetime.utcnow() + 365*one_day

  [subject, builder] = load_csr(arg_data.csr[0])
  print_csr(builder)

  print("\n")
  contd = input("Continue (N/y)")
  if (contd != 'y'):
    sys.exit(1)


  # Load CA public key
  fhdl_ca_pub = open("ca.crt","rb")
  ca_pub = x509.load_pem_x509_certificate(fhdl_ca_pub.read(),default_backend())
  fhdl_ca_pub.close()
  # Load CA private key
  fhdl_ca_priv = open("ca.key","rb")
  passwd = getpass.getpass("Please enter password: ")
  ca_priv = serialization.load_pem_private_key(fhdl_ca_priv.read(),bytes(passwd, 'utf-8'),default_backend())
  fhdl_ca_priv.close()

  builder = builder.not_valid_before(valid_before).not_valid_after(valid_after)
  builder = builder.serial_number(serial)
  builder = builder.issuer_name(ca_pub.subject)
  builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
  builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pub.public_key()), critical=False)

  certificate = builder.sign(ca_priv,hashes.SHA512(),default_backend())

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
  filename = "certs/" + hex_serial + ".crt"
  with open(filename, "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))
  print(filename)


def console_entry():
    parser = argparse.ArgumentParser(prog='issuecert')
    parser.add_argument('csr', metavar='signing request', type=str, nargs=1, help='signing request')
    arg_data = parser.parse_args()
    print(arg_data)
    try:
        main(arg_data)
    except KeyboardInterrupt:
        print("\nAborted by user!")
        sys.exit()

if __name__ == '__main__':
    console_entry()
