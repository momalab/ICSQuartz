
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))


// Define the Code struct first, as it is used in PLC_PRG
struct Code {
    int8_t* ptr1;                 // Corresponds to i8*
    int16_t* ptr2;                // Corresponds to i16*
    double** ptr3;                // Corresponds to double** (pointer to pointer to double)
    int32_t* ptr4;                // Corresponds to i32*
    int8_t array1[3];             // Corresponds to [3 x i8]
    double value1;                // Corresponds to double
    int8_t field1;                // Corresponds to i8
    double array2[7];             // Corresponds to [7 x double]
};

// Define the PLC_PRG struct, which includes the Code struct
struct PLC_PRG_struct {
    double array1[7];             // Corresponds to [7 x double]
    double* ptr1;                 // Corresponds to double*
    int32_t field1;               // Corresponds to i32
    int8_t field2;                // Corresponds to i8
    int16_t field3;               // Corresponds to i16
    struct Code code;             // Corresponds to %Code
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
    size_t PLC_PRG_input_size = sizeof(double[7]);
}

// Fuzzer link variables
extern "C"
{
    // Program State Sizing
    uint8_t *program_state_fresh = (uint8_t *)&PLC_PRG_instance + PLC_PRG_input_size;
    uint8_t *program_state_start = (uint8_t *)&PLC_PRG_fuzzer_instance + PLC_PRG_input_size;
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
