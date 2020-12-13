
import base64
import sys
from urllib.parse import unquote

a = 'JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY0JTYyJTM2JTM5JTM0JTM2JTYyJTYx'
base64_a = base64.b64decode(a)

# UTF-8 decoded
ans = unquote(str(base64_a))
print(ans)
