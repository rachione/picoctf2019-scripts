import sys


a = [106, 85, 53, 116, 95, 52, 95, 98]
b = [0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f]
c = [142, 131, 164, 63, 163, 137, 63, 141]
d = ['7', '2', '4', 'c', '8', 'f', '9', '2']

for i in a:
    sys.stdout.write(chr(i))
for i in b:
    sys.stdout.write(chr(i))
for i in c:
    sys.stdout.write(chr(int(str(i),8)))
for i in d:
    sys.stdout.write(i)
