#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))


struct Code_struct
{
    double (*array8_ptr)[8];
    uint8_t *i8_ptr;
    int32_t i32;
    int16_t i16;
    double double1;
    double double2;
    int16_t i16_2;
    double array65[65];
    double array2[2];
};

struct PLC_PRG_struct
{
    double in[8];
    uint8_t ssMethodType;
    double array2[2];
    struct Code_struct Code_struct;
};

// Fuzzer input struct
struct PLC_PRG_struct PLC_PRG_fuzzer_instance;
unsigned scan_cycle = 0;
unsigned scan_cycle_max = 1000000;

extern "C"
{
    void PLC_PRG(struct PLC_PRG_struct *);
    extern struct PLC_PRG_struct PLC_PRG_instance;
    size_t PLC_PRG_instance_size = sizeof(struct PLC_PRG_struct);
    size_t PLC_PRG_input_size = sizeof(double[8]);
}

// Fuzzer link variables
extern "C"
{
    // Program State Sizing
    uint8_t *program_state_fresh = (uint8_t *)&PLC_PRG_instance.ssMethodType;
    uint8_t *program_state_start = (uint8_t *)&PLC_PRG_fuzzer_instance.ssMethodType;
    uint8_t *program_state_end = (uint8_t *)&PLC_PRG_fuzzer_instance + sizeof(struct PLC_PRG_struct);
    unsigned program_state_size = program_state_end - program_state_start;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size)
{
    /* Scan cycle management */
    // if (scan_cycle == 0 || scan_cycle > scan_cycle_max)
    // {
    //     /* Start with new default values */
    //     memcpy(&PLC_PRG_fuzzer_instance, &PLC_PRG_instance, PLC_PRG_instance_size);
    //     /* Reset scan cycles */
    //     scan_cycle = 0;
    // }
    scan_cycle++;
    // printf("Scan cycle: %d\n", scan_cycle);

    /* Clear input size between runs */
    memset(&PLC_PRG_fuzzer_instance, 0, PLC_PRG_input_size);

    /* Copy in fuzzer values */
    // if (Size <= PLC_PRG_input_size) {
        memcpy(&PLC_PRG_fuzzer_instance, Data, MIN(Size, PLC_PRG_input_size));

        PLC_PRG(&PLC_PRG_fuzzer_instance);
    // }

    return 0;
}
