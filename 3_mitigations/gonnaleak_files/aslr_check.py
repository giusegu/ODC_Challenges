from pwn import *


def check_aslr(binary_path):
    # Get the absolute path of the binary
    binary_path = os.path.abspath(binary_path)

    # Run the binary for the first time
    p = process(binary_path)

    # Get the base address of the binary
    binary_base_address = p.libs()[binary_path]

    # Close the process
    p.close()

    # Run the binary again
    p = process(binary_path)

    # Get the base address of the binary in the second run
    second_binary_base_address = p.libs()[binary_path]

    # Close the process
    p.close()

    # Check if the base address of the binary has changed (ASLR is active if it changes)
    aslr_active = (binary_base_address != second_binary_base_address)

    return aslr_active


# Example usage
binary_path = 'gonnaleak'
aslr_status = check_aslr(binary_path)

if aslr_status:
    print("ASLR is active.")
else:
    print("ASLR is not active.")
