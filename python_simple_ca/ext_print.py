from cryptography import x509
from ipaddress import IPv4Address
from ipaddress import IPv6Address

def print_san(ext):
    sdns = ext._value.get_values_for_type(x509.DNSName)
    names = []
    for el in sdns:
        names.append(el)
    sip = ext._value.get_values_for_type(x509.IPAddress)
    for el in sip:
        names.append(el.exploded)
    print("\"" + "\", \"".join(names) + "\"")

def print_kuse(ext):
    usages = filter(lambda a: not a.startswith('_'), dir(ext._value))
    fltd = []
    for a in usages:
        try:
            if(getattr(ext._value,a) == True):
                fltd.append(a)
        except: pass
    print(",".join(fltd))

def print_extkuse(ext):
    usages = map(lambda a: a._name, ext._value)
    print (",".join(usages))

def print_skeyid(ext):
    print(":".join(format(x, '02x') for x in ext._value.digest))