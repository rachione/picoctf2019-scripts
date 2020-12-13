import sys
a = 14311663942709674867122208214901970650496788151239520971623411712977119645236321549653782653
hNum = hex(a)
hNum = hNum.replace('0x', '')


hNumArry = [hNum[i:i+2] for i in range(0, len(hNum), 2)]

for c in hNumArry:
    sys.stdout.write(chr(int(c, 16)))
