import sys

indexs = [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, -5), (9, 2), (10, -5), (11, 2), (12, -5), (13, 2), (14, -5), (15, 2), (16, -5), (17, 2), (18, -5), (19, 2), (20, -5), (21, 2), (22, -5)]


rev = 'picoCTF{w1{1wq8b5.:/f.<}'


for t in indexs:
    sys.stdout.write(chr(ord(rev[t[0]])+t[1]))
