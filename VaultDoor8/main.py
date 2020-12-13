import sys

expected = [0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, 0xF0, 0x77, 0xA4, 0xD0,
            0xC5, 0x77, 0xF4, 0x86, 0xD0, 0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xF1, 0xC1, 0xF0,
            0x94, 0xC1, 0xA5, 0xC1, 0xC2, 0xA4]


def switchBits_rev(c, p1, p2):
    mask1 = (1 << p1)
    mask2 = (1 << p2)
    bit1 = (c & mask1)
    bit2 = (c & mask2)
    rest = (c & ~(mask1 | mask2))
    shift = (p2 - p1)
    result = ((bit1 << shift) | (bit2 >> shift) | rest)
    return result


def switchBits(c, p1, p2):
    mask1 = (1 << p1)
    mask2 = (1 << p2)
    bit1 = (c & mask1)
    bit2 = (c & mask2)
    rest = (c & ~(mask1 | mask2))
    shift = (p2 - p1)
    result = ((bit1 << shift) | (bit2 >> shift) | rest)
    return result


def test_rev(c, p1, p2):
    mask1 = (1 << p1)
    mask2 = (1 << p2)
    bit1 = (c & mask1)
    bit2 = (c & mask2)
    rest = (c & ~(mask1 | mask2))
    shift = (p2 - p1)
    result = ((bit1 << shift) | (bit2 >> shift) | rest)
    return result


def test(c, p1, p2):
    mask1 = (1 << p1)
    mask2 = (1 << p2)
    bit1 = (c & mask1)
    bit2 = (c & mask2)
    rest = (c & ~(mask1 | mask2))
    shift = (p2 - p1)
    result = ((bit1 << shift) | (bit2 >> shift) | rest)
    return result


for c in expected:
    c = switchBits(c, 6, 7)
    c = switchBits(c, 2, 5)
    c = switchBits(c, 3, 4)
    c = switchBits(c, 0, 1)
    c = switchBits(c, 4, 7)
    c = switchBits(c, 5, 6)
    c = switchBits(c, 0, 3)
    c = switchBits(c, 1, 2)
    sys.stdout.write(chr(c))




'''
a = test(200, 1, 7)
print(hex(a))
a_rev = test_rev(a, 1, 7)
print(a_rev)
'''
