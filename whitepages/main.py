
target = 0x7069636f4354467
targetBit = "{0:b}".format(target)

with open('whitepages.txt', 'rb') as f:
    data = f.read()

data = data.hex()

data = data.replace('e28083', '0')
data = data.replace('20', '1')

if targetBit in data:
    index = data.index(targetBit)
    print(index)
    ans = hex(int(data[index:], 2))
    
    print(bytes.fromhex(ans[2:]))
  
