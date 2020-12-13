import sys

for k in range(5, 0, -1):
    with open("Item0" + str(k) + "_cp.bmp", "rb") as f:
        f.seek(0x7e3)

        for i in range(0x32):
            if (i % 5) == 0:
                b = ''
                for j in range(8):
                    data = f.read(1)
                    b += str(int.from_bytes(data, 'big') & 1)
                sys.stdout.write(chr(int(b[::-1], 2)))
            else:
                f.read(1)
