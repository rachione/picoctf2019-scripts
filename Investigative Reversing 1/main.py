import sys


def ToList(v):
    return list(map(lambda x: int(x, 16), v.split(' ')))


def myprint(v):
    sys.stdout.write(chr(v))


m1 = '43 46 7B 41 6E 31 5F 37 66 63 30 32 37 38 36 7D'
m2 = '85 73'
m3 = '69 63 54 30 74 68 61 5F'

m1 = ToList(m1)
m2 = ToList(m2)
m3 = ToList(m3)


# 0
myprint(m2[0]-15)
myprint(m3[0])
myprint(m3[1])

quest = 0



local_68 = 6
m1index = 1
while local_68 < 10:
    quest -= 1
    myprint(m1[m1index])
    m1index += 1
    local_68 += 1

#myprint(m2[1]+quest)

local_64 = 10
m3index = 3
while local_64 < 0xf:
    myprint(m3[m3index])
    m3index += 1
    local_64 += 1




local_60 = 0xf
while local_60 < 0x1a:
    myprint(m1[m1index])
    m1index += 1
    local_60 += 1

print('\n')
