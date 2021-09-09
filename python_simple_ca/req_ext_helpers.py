from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from ipaddress import IPv4Address
from ipaddress import IPv6Address
from ipaddress import AddressValueError

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

def gen_basic_key_usage():
  return x509.KeyUsage(
    content_commitment=False,
    digital_signature=True,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    decipher_only=False,
    encipher_only=False
  )

def gen_extended_key_usage():
  usages = []
  usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
  return x509.ExtendedKeyUsage(usages)

def split_multivalues(instr):
  if len(instr) == 0:
    return [];
  return instr.split(',');
