import sys

with open("encoded.bmp", "rb") as f:
    f.seek(0x2d3)

    for i in range(100):
        if (i&1)==0:
            b=''
            for j in range(8):
                data = f.read(1)
                b += str(int.from_bytes(data, 'big') & 1)
            sys.stdout.write(chr(int(b[::-1],2)))
        else:
            f.read(1)
        

