from functools import reduce
import itertools
import socket
import re


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1:
        q = a / b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1


def find_invpow(x, n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


class Netcat:
    """ Python 'netcat like' module """

    def __init__(self, ip, port):
        self.buff = b""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))

    def read(self, length=1024):
        """ Read 1024 bytes off the socket """
        return self.socket.recv(length)

    def read_until(self, data):
        """ Read data into the buffer until we have data """
        while not data in self.buff:
            self.buff += self.socket.recv(1024)
        pos = self.buff.find(data)
        rval = self.buff[:pos + len(data)]
        self.buff = self.buff[pos + len(data):]
        return rval

    def write(self, data):
        self.socket.send(data)

    def close(self):
        self.socket.close()


N = []
C = []
for i in range(0, 65537):
    nc = Netcat('2019shell1.picoctf.com', 49851)
    data = nc.read()
    data = str(data)
    m = re.findall(r"\d+", data)
    c = m[0]
    n = m[1]
    C.append(int(c))
    N.append(int(n))
    print(i)

e = len(N)
flag_cubed = chinese_remainder(N, C)
print("flag_cubed: ", flag_cubed)
flag = find_invpow(flag_cubed, e)

print("flag: ", flag)

try:
    print("flag: ", bytearray.fromhex(hex(ans)[2:]).decode())
except:
    pass

