with open('mystery', 'rb') as f:
    mystery = f.read()
with open('flag.png', 'rb') as f:
    sample = f.read()

mystery = bytearray(mystery) 

for i in range(0, 0x3e):
    if i in range(0x55, 0x57):
        continue
    mystery[i] = sample[i]






with open('output.png', 'wb') as f:
    f.write(mystery)
