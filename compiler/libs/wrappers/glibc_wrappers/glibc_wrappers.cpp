/****************************************
Author: Corban Villa
Date: June 20, 2023
Description: These functions wrap the standard library functions,
in order to provide additional information for debugging.
*****************************************/
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <cstring>
#include <stdbool.h>

#include <sys/types.h> // For pid_t
#include <unistd.h>    // For getpid(), getppid(), and kill()
#include <signal.h>    // For kill() and SIGUSR1
#include <stdio.h>     // For perror()

extern "C" {
    FILE* __fopen(const char *filename, const char *mode) {
        // printf("fopen: %s\n", filename);
        FILE* ret = fopen(filename, mode);
        // printf("fopen resp: %u\n (0x%x)\n", ret, ret);
        return ret;
    }

    uint32_t __fread(void *ptr, size_t size, size_t nitems, FILE *stream) {
        // printf("fread: %u\n", stream);
        uint32_t ret = fread(ptr, size, nitems, stream);
        // printf("fread resp: %u\n", ret);
        return ret;
    }

    int __fclose(FILE *stream) {
        // printf("fclose: %x\n", stream);
        int ret = fclose(stream);
        // printf("fclose resp: %u\n", ret);
        return ret;
    }

    void * __memcpy(void *dest, const void *src, size_t n) {
        // printf("memcpy: src=%p => dst=%p (size=%d)\n", src, dest, n);
        void* ret = memcpy(dest, src, n);
        // printf("memcpy resp: %p\n", ret);
        return ret;
    }

    void * __memset(void *s, int c, size_t n) {
        // printf("memset: s=%p (size=%d)\n", s, n);
        void* ret = memset(s, c, n);
        // printf("memset resp: %p\n", ret);
        return ret;
    }

    void read_array(char *dest, size_t n) {
        printf("read_array: %p (size=%d)\n", dest, n);
        for (int i = 0; i < n; i++) {
            printf(" --> %d\n", dest[i]);
            dest[i] = 0xDEAD;
        }
    }

    void unimplemented(char *func_name) {
        printf("Unimplemented function: %s\n", func_name);
        assert(0);
    }

    void SHL__BOOL(void *arg1, void *arg2) {
        unimplemented("SHL__BOOL");
    }

    void SHR__BOOL(void *arg1, void *arg2) {
        unimplemented("SHR__BOOL");
    }

    bool __bitcpy(
        uint8_t *pDest, uint16_t wDstStartBit,
        uint8_t *pSource, uint16_t wSrcStartBit,
        uint16_t wSize)
    {
        if (!pDest || !pSource)
        {
            return false; // Invalid pointers
        }

        while (wSize > 0)
        {
            uint16_t srcBytePos = wSrcStartBit / 8;
            uint16_t srcBitPos = wSrcStartBit % 8;
            uint16_t destBytePos = wDstStartBit / 8;
            uint16_t destBitPos = wDstStartBit % 8;

            // Calculate how many bits we can copy in this iteration.
            uint16_t bitsToCopy = 8 - (srcBitPos > destBitPos ? srcBitPos : destBitPos);
            if (bitsToCopy > wSize)
            {
                bitsToCopy = wSize;
            }

            // Mask for the bits to be copied from the source byte
            uint8_t srcMask = ((1 << bitsToCopy) - 1) << srcBitPos;
            // Shift the bits from source to the correct position and mask out the rest
            uint8_t bitsFromSource = (pSource[srcBytePos] & srcMask) >> srcBitPos;

            // Prepare the destination byte by clearing the space where bits will be copied
            uint8_t destMask = ((1 << bitsToCopy) - 1) << destBitPos;
            pDest[destBytePos] &= ~destMask;                    // Clear the destination bits
            pDest[destBytePos] |= bitsFromSource << destBitPos; // Set the new bits

            wDstStartBit += bitsToCopy;
            wSrcStartBit += bitsToCopy;
            wSize -= bitsToCopy;
        }

        return true;
    }
}

// extern "C" {
//     extern void *Code();

//     void *(*GetCodePointer())()
//     {
//         return Code;
//     }
// }

// extern "C" {
//     void StartPerfTimer()
//     {
//         pid_t parent_pid = getppid(); // Get the parent process ID
//         if (kill(parent_pid, SIGUSR1) == -1)
//         {
//             // If kill fails, print the error
//             perror("Error sending signal to parent");
//         }
//     }
// }
