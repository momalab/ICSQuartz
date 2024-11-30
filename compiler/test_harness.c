/*
 * Test harness to execute inputs to the PLC program.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

extern "C"
{
    int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size);
    extern size_t PLC_PRG_input_size;
}

int main(int argc, char **argv) {

    // Ensure 1 input
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // Zero the input
    uint8_t input[PLC_PRG_input_size];
    memset(input, 0, PLC_PRG_input_size);

    // Even number of characters for hex input
    if (strlen(argv[1]) % 2 != 0) {
        printf("Invalid input: Hex string must have an even number of characters\n");
        return 1;
    }

    // Read input as hexadecimal
    for (int i = 0; i < MIN(PLC_PRG_input_size, strlen(argv[1]) / 2); i++) {
        sscanf(argv[1] + 2*i, "%2hhx", &input[i]);
    }

    // Print input as hexadecimal
    printf("Input: ");
    for (int i = 0; i < PLC_PRG_input_size; i++) {
        printf("%02x", input[i]);
    }
    printf("\n");

    // Execute the input
    printf("Executing program...\n");
    for (int i = 0; i < 1000000; i++) {
        LLVMFuzzerTestOneInput((uint8_t*)&input, PLC_PRG_input_size);
    }
    printf("Program executed!\n");

    return 0;
}