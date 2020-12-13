
import codecs
import gmpy2
import sympy


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


#m < n
n = 66228565655147654983512330351269496613299765618973213272281271869696986095493536579207364731620706779146637661175917597430524397387074900686724151445806966949656620154626229189201801589967140892031847668371628336319972754632888714089074997473039080048142085004365926056787541829285349699984572649088344110382601708739501829787729488706023977923
c = 53661832153197173143993463804490159919084493874126010369987047051653198383328609155852648041908463460523209451759062554931881962072357844176675853089656679799613949578564698373351529146012358948947862322065990751074960788563776702772342945555478682085311395603145036739918837603118844025686513656500716523300557135736996206778953196311254892297
e = 65537

#get primes
factors = sympy.factorint(n)

print(factors)


test = 1
for f in factors :
    test = multiply(test, f)
assert test == n

phi = 1
for f in factors:
    phi = multiply(phi, (f-1))


g = gcd(e, phi)
assert g == 1

d = gmpy2.invert(e, phi)

ans = pow(c, d, n)
print(ans)

try:
    print("flag: ", bytearray.fromhex(hex(ans)[2:]).decode())
except:
    pass

