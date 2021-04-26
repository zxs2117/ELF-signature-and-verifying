#/usr/bin/python3
# -*- coding: iso-8859-15 -*-

#导入头文件
import sys
import lief
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

def usage():
    print("Usage:\n"
           "python3 generate.py <elf_file> <private_key> <crt_file>\n")
if len(sys.argv)!=4:
    usage()
    quit()

#读取文件名
elf_f=sys.argv[1]
key_f=sys.argv[2]
crt_f=sys.argv[3]
#sig_f=sys.argv[4]
#pub_f=sys.argv[5]

def generate_signature(key,data):
    print("Generating Signature")
    h=SHA256.new(data)
    rsa=RSA.importKey(key)
    signer=PKCS1_v1_5.new(rsa)
    signature=signer.sign(h)
    print("type sign: ",type(signature))
    print(signature)
    return signature

def get_text(binary):
    sec_text=binary.get_section(".text")
    return bytes(sec_text.content)

def add_section(binary,name,content):
    new_sec=lief.ELF.Section(name)
    new_sec.content=content
    binary.add(new_sec,False)



with open(elf_f,'rb') as f:
    elf=f.read()
with open(key_f,'rb') as f:
    key=f.read()
with open(crt_f,'rb') as f:
    crt=f.read()   

binary=lief.parse(elf)
data=get_text(binary)
sign=generate_signature(key,data)



if binary.has_section(".sign"):
    binary.remove(binary.get_section(".sign"))
add_section(binary,".sign",bytearray(sign))
#binary.remove(binary.get_section(".sign"))
sig=binary.get_section(".sign")
#with open(sig_f,'wb') as f:
#    f.write(bytes(sig.content))
t=bytes(sig.content)
print(t)
if binary.has_section(".crt"):
    binary.remove(binary.get_section(".crt"))
add_section(binary,".crt",bytearray(crt))
binary.write(elf_f)