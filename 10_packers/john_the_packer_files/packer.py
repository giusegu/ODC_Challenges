
# We put an hardware breakpoint on the entry point of the binary (0x804970e) and we run the binary with gdb
# We write dump memory first 0x804970e (0x804970e+(0x53*4)): We use it in gdb to get the deobfuscated function in a file called first (we will use it to patch the binary) (0x53 is the number of instructions of the deobfuscated function and 4 is the size of the instructions because we are in a 32 bits binary so 4 bytes per instruction)

BINARY_BASE = 0x8048000  # Base address of the binary
BINARY_BREAKPOINT = 0x804970e  # Entry point of the binary that we will patch
# Defining the function that will patch the binary (binary is the original file, path_file is the file that contains the deobfuscated function, address is the address in which we want to patch the binary)


def patch_binary(binary, path_file, address):
    with open(path_file, 'rb') as f:
        patch = f.read()  # We read the deobfuscated function
    # We get the offset of the address in which we want to patch the binary
    offset = address - BINARY_BASE
    patch_len = len(patch)  # We get the length of the deobfuscated function
    # We patch the binary which is componsed by the begging binary + the deobfuscated function + the end of the original binary
    binary = binary[:offset] + patch + binary[offset + patch_len:]
    return binary


# We open the binary of the original file and read it into a variable
with open("./john", 'rb') as f:
    binary = f.read()

# We call the function to patch the binary with the address of the entry point (the same where we put rhe hardware breakpoint on gdb)
binary = patch_binary(binary, "./first", BINARY_BREAKPOINT)

with open("./john_patched", 'wb') as f:
    f.write(binary)
