import sys
import string
from PIL import Image
im = Image.open('buildings.png', 'r')
pixel_values = list(im.getdata())

binary = ''
for pixel in pixel_values:
    for i, p in enumerate(pixel):
        if i == 3:
            break
        if p % 2 != 0:
            binary += '1'
        else:
            binary += '0'

msgs = []
for i in range(0, len(binary)//8*8, 8):
    sum = 0
    for j in range(i, i+8):
        sum <<= 1
        sum |= int(binary[j])
    msgs.append(sum)


for m in msgs:
    w = chr(m)
    if w in string.printable:
        sys.stdout.write(w)
