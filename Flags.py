import string
import sys


def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3


s = 'PICOCTF{F!@^%@&*%T#FF}'
alS = 'PICOCTF{F!@^S@&*STUFF}'

alterS = 'PICOCTF{FLAGSA&*STUFF}'

ignore = 'PICOCTF{FLAGSA&*STUFF}'

mlist = []
for u in string.ascii_uppercase:
    if u in ignore:
        continue
    mlist.append(u)


testWord = []

for i in mlist:
    for j in mlist:
        if i == j:
            continue
        w = 'A%s%s' % (i, j)
        testWord.append(w)


with open('words_alpha.txt', 'r') as f:
    wordData = f.read()

wordData = wordData.split('\n')
wordData = list(map(lambda x: x.upper(), wordData))


ans = intersection(wordData, testWord)
print(ans)


# 'PICOCTF{FLAGSARESTUFF}'
# 'PICOCTF{FLAGSANDSTUFF}'
# 'PICOCTF{FLAGSANYSTUFF}'
# 'PICOCTF{FLAGSAVESTUFF}'
