import sys
with open('ports.txt', 'r') as r:
    data = r.read()

data = data.split('\n')


for a in data[1:-2]:
    sys.stdout.write(chr(int(a[1:4])))
