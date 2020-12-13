


ans = []

sum1 = 0
while sum1 < 8:
    ans.append((sum1, 0))
    sum1 += 1


sum2 = 8
while sum2 < 0x17:
    if sum2 & 1 == 0:
        ans.append((sum2, -0x5))
    else:
        ans.append((sum2, +2))
    sum2 += 1


print(ans)
