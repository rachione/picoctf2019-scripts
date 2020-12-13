import binascii
from pwn import *
import sys
import ctypes

LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
BINARY = './seed_spring'
context.terminal = ['tmux', 'splitw', '-h']


def attach_gdb(sh):
    gdb.attach(sh)


def P32(v):
    return struct.pack('I', v)


def P64(v):
    return struct.pack('Q', v)


def deHex(v):
    return binascii.unhexlify(v)[::-1]


def start():
    if args["REMOTE"]:
        sh = remote('2019shell1.picoctf.com', 12269)
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
    def send(x): return sh.sendlineafter(': ', x)

    for i in range(100):
        sh = start()
        try:
            LIBC.srand(LIBC.time(0)-i)
            for i in range(30):
                ans = LIBC.rand() & 0xf
                send(str(ans))

            data = sh.recvall(timeout=1)
            if 'pico' in data:
                print(data)
                break
        except:
            print('fk')


if __name__ == '__main__':
    main()
