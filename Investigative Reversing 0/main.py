import sys
data = '70 69 63 6F 43 54 4B 80 6B 35 7A 73 69 64 36 71 5F 35 32 36 36 61 38 35 37 7D'
data = data.split(' ')
data = map(lambda x: int(x, 16), data)
data = list(data)

for i in data[0:5+1]:
    sys.stdout.write(chr(i))


for i in data[6:0xe+1]:
    sys.stdout.write(chr(i-5))

sys.stdout.write(chr(data[0xf]+3))


for i in data[0x10:0x1a+1]:
    sys.stdout.write(chr(i))
