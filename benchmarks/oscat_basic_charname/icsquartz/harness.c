
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct PLC_PRG_struct {
    int8_t field;
};

extern "C"
{
    void PLC_PRG(struct PLC_PRG_struct *);
    extern struct PLC_PRG_struct PLC_PRG_instance;
    size_t PLC_PRG_instance_size = sizeof(struct PLC_PRG_struct);
    size_t PLC_PRG_input_size = PLC_PRG_instance_size;
    size_t PLC_PRG_struct_size = PLC_PRG_instance_size;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size)
{
    struct PLC_PRG_struct PLC_PRG_fuzzer_instance;

    /* Fresh copy of default values every run */
    memset(&PLC_PRG_fuzzer_instance, 0, PLC_PRG_input_size);

    // Disallow empty inputs
    if (Size == 0)
        return 0;

    if (Size <= PLC_PRG_input_size) {
        /* Copy in default values to local struct */
        memcpy(&PLC_PRG_fuzzer_instance, Data, MIN(Size, PLC_PRG_input_size));
        /* Invoke the ST program */
        PLC_PRG(&PLC_PRG_fuzzer_instance);
    }
    
    return 0;
}
