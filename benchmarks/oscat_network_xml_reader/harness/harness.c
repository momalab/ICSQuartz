#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ROUND_UP(num, divisor) (((num) + (divisor)-1) / (divisor))

/* These structs need to have idential sizes and layouts with */
/* the corresponding ST ones. See `artifacts/build/main.ll`   */
/* for references to each of these. */

// Mapping for %TP = type { i8, i64, i8, i64, i8, [24 x i8] }
struct TP
{
    uint8_t field1;
    uint64_t field2;
    uint8_t field3;
    uint64_t field4;
    uint8_t field5;
    uint8_t field6[24];
};

// Mapping for %XML_CONTROL = type { i16, i64, i16, i16, i16, i16, i16, [251 x i8], [251 x i8], [251 x i8], [251 x i8], i16, i16, i16, i16 }
struct XML_CONTROL
{
    uint16_t COMMAND;
    uint64_t WATCHDOG;
    uint16_t START_POS;
    uint16_t STOP_POS;
    uint16_t COUNT;
    uint16_t TYP;
    uint16_t LEVEL;
    uint8_t PATH[251];
    uint8_t ELEMENT[251];
    uint8_t ATTRIBUTE[251];
    uint8_t VALUE[251];
    uint16_t BLOCK1_START;
    uint16_t BLOCK1_STOP;
    uint16_t BLOCK2_START;
    uint16_t BLOCK2_STOP;
};

// Mapping for %XML_READER = type { %XML_CONTROL*, [4096 x i8]*, i16, i16, i16, i16, i16, i8, i16, i16, i8, i8, [11 x i8], [11 x i8], %TP }
struct XML_READER
{
    struct XML_CONTROL *CTRL;
    uint8_t *BUF; // Assuming NW_BUF_LONG is a buffer of [4096 x i8]
    uint16_t index;
    uint16_t index2;
    uint16_t stop;
    uint16_t mode;
    uint16_t command;
    uint8_t c;
    uint16_t s1;
    uint16_t e1;
    uint8_t path_overflow;
    uint8_t empty_tag;
    uint8_t s_code[11];
    uint8_t e_code[11];
    struct TP watchdog;
};

struct XMLParser_DEMO_struct
{
    uint8_t buf[4096];
    struct XML_READER reader;
    struct XML_CONTROL ctrl;
};

extern "C"
{
    void PLC_PRG(struct XMLParser_DEMO_struct *);
    extern struct XMLParser_DEMO_struct PLC_PRG_instance;
    size_t PLC_PRG_instance_size = sizeof(struct XMLParser_DEMO_struct);
    size_t PLC_PRG_input_size = PLC_PRG_instance_size;
    size_t PLC_PRG_struct_size = PLC_PRG_instance_size;
}


/* This instance stores all default values from ST. Do not overwrite values! */
// extern struct XMLParser_DEMO_struct XMLParser_DEMO_instance;
/* This instance is for running. Clone the struct above before each run! */
struct XMLParser_DEMO_struct XMLParser_DEMO_fuzzer_instance;

extern "C" int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size)
{
    /* Fresh copy of default values every run */
    memcpy(&XMLParser_DEMO_fuzzer_instance, &PLC_PRG_instance, sizeof(struct XMLParser_DEMO_struct));

    /* Temporary, until ST has a while loop */
    if (Size < 4095)
    {
        /* Copy in default values to local struct */
        memcpy(XMLParser_DEMO_fuzzer_instance.buf, Data, Size);
        /* Null-terminate fuzzer input (we might not actually need this)*/
        XMLParser_DEMO_fuzzer_instance.buf[Size] = '\0';
        /* Set the start/end config */
        XMLParser_DEMO_fuzzer_instance.ctrl.COMMAND = 0xFFFF;
        XMLParser_DEMO_fuzzer_instance.ctrl.START_POS = 0;
        XMLParser_DEMO_fuzzer_instance.ctrl.STOP_POS = Size - 1;

        // XMLParser_DEMO_fuzzer_instance.ctrl.WATCHDOG = 5;
        /* Invoke the ST program */
        while (1)
        {
            PLC_PRG(&XMLParser_DEMO_fuzzer_instance);
            if (XMLParser_DEMO_fuzzer_instance.ctrl.TYP == 99)
                break;
            // printf("Type: %d\n", XMLParser_DEMO_fuzzer_instance.ctrl.TYP);
            // printf("Path: %s\n", XMLParser_DEMO_fuzzer_instance.ctrl.PATH);
            // printf("Element: %s\n", XMLParser_DEMO_fuzzer_instance.ctrl.ELEMENT);
            // printf("Value: %s\n", XMLParser_DEMO_fuzzer_instance.ctrl.VALUE);
        }
    }

    return 0;
}
