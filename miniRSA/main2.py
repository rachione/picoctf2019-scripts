import sys
a = 13016382529449106065894479374027604750406953699090365388202767087888130179936381
hNum = hex(a)
result = bytearray.fromhex(hNum[2:]).decode()
print(result)