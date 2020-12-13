
import sys

hexBytes = [1096770097,
            1952395366,
            1600270708,
            1601398833,
            1716808014,
            1734293602,
            1701067056,
            892756537]


for h in hexBytes:
    b = "{0:032b}".format(h)
    b = list(b)

    for i in range(0, len(b), 8):
        n = int(''.join(b[i:i+8]), 2)
        sys.stdout.write(chr(n))


