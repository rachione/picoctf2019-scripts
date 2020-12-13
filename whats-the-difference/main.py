import sys


with open('cattos.jpg','rb') as f:
    a=f.read()
with open('kitters.jpg','rb') as f:
    b=f.read()

for i in range(0,len(a)):
    if a[i]!=b[i]:
        sys.stdout.write(chr(a[i]))