#!/usr/bin/python3
import lief
import OpenSSL
import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

def usage():
    print("Usage:\n"
           "python3 verify.py <elf_file>\n")

if len(sys.argv)!=2:
    usage()
    quit()

elf_f=sys.argv[1]

def verify_signature(key,data,signature):
    print("verifing Signature")
    h=SHA256.new(data)
    rsa=RSA.importKey(key)
    signer=PKCS1_v1_5.new(rsa)
    rsp="Success" if (signer.verify(h,signature)) else "Verfication Failure"
    print(rsp)

def get_section(binary,name):
    sec=binary.get_section(name)
    return bytes(sec.content)

with open(elf_f,'rb') as f:
    elf=f.read()

binary=lief.parse(elf)
text=get_section(binary,".text")
sign=get_section(binary,".sign")
crt=get_section(binary,".crt")
#从crt中解析出pubkey
cert=OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,crt.decode("UTF-8"))
pubkey=OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM,cert.get_pubkey())

verify_signature(pubkey,text,sign)
print(pubkey.decode())
#print(text.decode())
#print(sign)
