
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ROUND_UP(num, divisor) (((num) + (divisor)-1) / (divisor))

struct PLC_PRG_struct {
  uint8_t data[81];
};

extern "C"
{
    void PLC_PRG(struct PLC_PRG_struct *);
    extern struct PLC_PRG_struct PLC_PRG_instance;
    size_t PLC_PRG_instance_size = sizeof(struct PLC_PRG_struct);
    size_t PLC_PRG_input_size = PLC_PRG_instance_size;
    size_t PLC_PRG_struct_size = PLC_PRG_instance_size;
}

int check_ascii(const unsigned char *buffer, size_t Size) {
    for (size_t i = 0; i < Size; i++) {
        if (buffer[i] > 0x7F) {
            return 0; // Non-ASCII character found
        }
    }
    return 1; // All characters are ASCII
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size)
{
    struct PLC_PRG_struct PLC_PRG_fuzzer_instance;

    /* Fresh copy of default values every run */
    memset(&PLC_PRG_fuzzer_instance, 0, PLC_PRG_struct_size);

    // Disallow empty inputs
    if (Size == 0)
        return 0;

    if (Size <= PLC_PRG_struct_size && check_ascii(Data, Size)) {
        // Return 0 for all empty input
        for (size_t i = 0; i < Size; i++) {
            if (Data[i] != 0)
                break;
            if (i == Size - 1)
                return 0; // Return 0 if all elements are zero
        }
        /* Copy in default values to local struct */
        memcpy(&PLC_PRG_fuzzer_instance, Data, MIN(Size, PLC_PRG_struct_size));
        /* Invoke the ST program */
        PLC_PRG(&PLC_PRG_fuzzer_instance);
    }
    
    return 0;
}
