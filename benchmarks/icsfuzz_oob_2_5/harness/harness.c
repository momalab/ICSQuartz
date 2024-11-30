#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ROUND_UP(num, divisor) (((num) + (divisor)-1) / (divisor))

struct PLC_PRG_struct {
    int16_t input1;
    int16_t output1;
    int32_t in_addr;
};

// Fuzzer input struct
struct PLC_PRG_struct PLC_PRG_fuzzer_instance;
unsigned scan_cycle = 0;
unsigned scan_cycle_max = 1000;

extern "C"
{
    void PLC_PRG(struct PLC_PRG_struct *);
    extern struct PLC_PRG_struct PLC_PRG_instance;
    size_t PLC_PRG_instance_size = sizeof(struct PLC_PRG_struct);
    size_t PLC_PRG_input_size = 4;
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
    struct PLC_PRG_struct PLC_PRG_fuzzer_instance;

    /* Fresh copy of default values every run */
    memcpy(&PLC_PRG_fuzzer_instance, &PLC_PRG_instance, sizeof(struct PLC_PRG_struct));

    // Disallow empty inputs
    if (Size == 0)
        return 0;

    if (Size <= 2) {
        /* Copy in default values to local struct */
        memcpy(&PLC_PRG_fuzzer_instance.input1, Data, MIN(Size, 2));
        /* Invoke the ST program */
        PLC_PRG(&PLC_PRG_fuzzer_instance);
    }
    
    return 0;
}

/* Manually invoke Base64 */
/* This part only compiles when calling `build-bootstrap.sh` */
#ifdef RUN_LOCAL
int main() {
    /* Fresh copy of default values every run */
    // memcpy(&BASE64_DEMO_fuzzer_instance, &BASE64_DEMO_instance, sizeof(struct BASE64_DEMO_struct));

    /* Input variables (for testing) */
    // char *input_str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    uint8_t input[] = {255, 0};

    for (int i = 0; i < 65535; i++)
    {
        printf("Testing %d\n", i);
        LLVMFuzzerTestOneInput((uint8_t*)&i, 2);
    }
    // LLVMFuzzerTestOneInput(input, 2);

    printf("Done executing Base64\n");

    return 0;
}
#endif
