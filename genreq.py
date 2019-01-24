#! /usr/bin/env python3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from ipaddress import IPv4Address


country="US"
state="CA"
city="San Diego"
organization="Example Limited"
common_name="example.com"

subject = []

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
if not tmp_country:
    subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
elif tmp_country != ".":
    subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, tmp_state))

subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
subject.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

key = rsa.generate_private_key(public_exponent=65537,key_size=4096,backend=default_backend());


csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).add_extension(
    x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.IPAddress(IPv4Address("136.243.232.117")),
        x509.DNSName(u"vgr.morloc.de"),
        x509.DNSName(u"mail.jnhmn.de"),
        x509.DNSName(u"jnhmn.de"),
    ]),
    critical=False,
).add_extension(
    x509.KeyUsage(content_commitment=True,digital_signature=True,key_encipherment=True,data_encipherment=False,key_agreement=True,key_cert_sign=False,crl_sign=False,decipher_only=False, encipher_only=False),critical=False
# Sign the CSR with our private key.
).sign(key, hashes.SHA256(), default_backend())

with open("request.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

