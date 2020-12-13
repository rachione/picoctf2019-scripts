import sys
aList = 'SOLVECRYPTO'
bList = 'UFJKXQZQUNB'


for a, b in zip(aList, bList):
    c = ( (ord(b)-ord('A'))-(ord(a)-ord('A')))%26
    sys.stdout.write(chr(ord('A')+c))
    
