
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct Code_struct
{
    char *byte;               // i8 maps to char in C (assuming we use it to store a byte)
    int32_t (*double_array1)[8]; // [2 x double] is an array of 2 doubles
    int16_t *short_int;       // i16 maps to int16_t in C
    double value1;           // double remains double in C
    double double_array2[8]; // [2 x double] again, an array of 2 doubles
    double value2;           // another double
    double value3;           // and another double
    int32_t i32;
};

struct PLC_PRG_struct {
    int32_t array[8];
    int16_t i16;
    int8_t i8;
    int16_t another_i16;
    struct Code_struct code;
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
    size_t PLC_PRG_input_size = sizeof(int32_t[8]);
}

// Fuzzer link variables
extern "C"
{
    // Program State Sizing
    uint8_t *program_state_fresh = (uint8_t *)&PLC_PRG_instance.i16;
    uint8_t *program_state_start = (uint8_t *)&PLC_PRG_fuzzer_instance.i16;
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

    /* Fresh copy of default values every run */
    memset(&PLC_PRG_fuzzer_instance, 0, PLC_PRG_input_size);

    /* Copy in fuzzer values */
    memcpy(&PLC_PRG_fuzzer_instance, Data, MIN(Size, PLC_PRG_input_size));

    PLC_PRG(&PLC_PRG_fuzzer_instance);

    return 0;
}
