import binascii
import sys
with open('data.raw','r') as r:
    data = r.read()
print(str(bytes.fromhex(data)))