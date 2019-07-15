	.cpu cortex-m4	
    .eabi_attribute 14, 0 // Use R9 as just another callee-saved register (V6)
    .eabi_attribute 34, 0 // Don't allow for unaligned data accesses
	.eabi_attribute 18, 0 // We prohibit use of wchar_t in our implemenation of the salt library.
    .eabi_attribute 26, 0 // We don't use enums in the API of the assembler functions.
    .eabi_attribute 24, 2 // This assembly code assumes that 64 bit values are aligned at at least 32 bit boundaries.
	.eabi_attribute 25, 0 // We don't require to preserve alignment of 8 byte objects to 8 byte boundaries.
	.eabi_attribute 23, 0 // Code in this assembler file should not use floating point numbers.
