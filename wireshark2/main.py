
import re
with open('data.txt', 'r') as f:
    data = f.read()


splitLine = "==================================================================="

data = re.findall('Follow:[.\s\S]*?%s\n' % (splitLine), data)

result = []

for block in data:
    lines = re.findall('[0-9]*[\n](.*?)[\n]', block)
    content = ''
    for l in lines[2:]:
        content += l
    result.append(content)

output = '\n\n'.join(result)


with open('output.txt', 'w') as f:
    f.write(output)
