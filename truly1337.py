import sys
import string
# 01100011 01101111 01101110 01110100 01100001 01101001 01101110 01100101 01110010

msg = sys.argv[1]

for i in range(2, 16+1):
    try:
        ans = ''.join(map(lambda x: chr(int(x, i)), msg.split(' ')))
        if ans[0] in string.printable:
            print(ans)
    except:
        pass


