
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))


struct Code
{
    char *char_ptr;          // i8* maps to char* in C
    double *double_ptr;      // double* remains double* in C
    double (*array_ptr)[21]; // [21 x double]* maps to a pointer to an array of 21 doubles
    int32_t *int_ptr;        // i32* maps to int32_t* in C
    double fixed_array[10];   // [4 x double] is a fixed size array of 4 doubles
    double value1;           // double remains double in C
    double value2;           // double remains double in C
    double value3;           // double remains double in C
    int16_t iter;
};

struct PLC_PRG_struct {
    double array[21];
    double field1;
    int32_t field3;
    int8_t ssMethodType;
    struct Code field6;
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
    size_t PLC_PRG_input_size = sizeof(double[21]);
}

// Fuzzer link variables
extern "C"
{
    // Program State Sizing
    uint8_t *program_state_fresh = (uint8_t *)&PLC_PRG_instance.field1;
    uint8_t *program_state_start = (uint8_t *)&PLC_PRG_fuzzer_instance.field1;
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
    if (Size <= PLC_PRG_input_size) {
        memcpy(&PLC_PRG_fuzzer_instance, Data, MIN(Size, PLC_PRG_input_size));

        PLC_PRG(&PLC_PRG_fuzzer_instance);
    }

    return 0;
}
