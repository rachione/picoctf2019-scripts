from pwn import *


# socat TCP-LISTEN:8000,reuseaddr,fork EXEC:./times-up
def main():
    

    if args["REMOTE"]:
        p = remote("3.15.247.173", 8000)
    else:
        p = process("./times-up")
    

    chellenge = p.readuntil("\n")
    ans = chellenge.split(":")[1]
    ans = str(eval(ans))
    p.sendline(ans)
    p.interactive()
    

    



if __name__ == "__main__":
    main()
