import math


with open('data.txt', 'r') as f:
    data = f.read()

result = ''
for i in range(0, len(data), 8):
    result += '0x'
    result += data[i:i+8]
    result += '\n'


with open('result.txt', 'w') as f:
    data = f.write(result)
