
import jwt
import base64

payload = {'user': '123456'}
ans = b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiMTIzNDU2In0.SkSVvsMzWJ-E4PMQs23y4_7cjFr-H_aqFIUAHnidxQU'
test = b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiMTIzNDU2In0.mY3E2ZFtGvgXM-NgHWb-vkioucmNds4xo1v8nfGECrs'


with open('password.lst', 'r') as f:
    data = f.read()

data = data.split('\n')
data = list(map(lambda x: x.strip(), data))

for key in data:
    encoded = jwt.encode(payload, key, algorithm='HS256')
    if encoded == ans:
        print('key:', key)
