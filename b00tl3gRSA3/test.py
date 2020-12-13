
import codecs
import gmpy2


def multiply(x, y):
    _CUTOFF = 1536
    if x.bit_length() <= _CUTOFF or y.bit_length() <= _CUTOFF:  # Base case
        return x * y
    else:
        n = max(x.bit_length(), y.bit_length())
        half = (n + 32) // 64 * 32
        mask = (1 << half) - 1
        xlow = x & mask
        ylow = y & mask
        xhigh = x >> half
        yhigh = y >> half

        a = multiply(xhigh, yhigh)
        b = multiply(xlow + xhigh, ylow + yhigh)
        c = multiply(xlow, ylow)
        d = b - a - c
        return (((a << half) + d) << half) + c


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


n = 105
c = 25
e = 5


F = [3,
     5,
     7]


test = 1
for f in F:
    test = multiply(test, f)
assert test == n

phi = 1
for f in F:
    phi = multiply(phi, (f-1))


g = gcd(e, phi)
assert g == 1

d = gmpy2.invert(e, phi)
print(d)

ans = pow(c, d, n)
print(ans)

