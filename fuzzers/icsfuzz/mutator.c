#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mutator.h"

#ifndef SCAN_CYCLE_MS
#define SCAN_CYCLE_MS 4
#endif

// Macro to write input, log, and sleep until next cycle is ready
#define WRITE_AND_LOG(fd, addr, out_buf, len, log_fd)                   \
    do {                                                                \
        lseek(fd, addr, SEEK_SET);                                      \
        if (write(fd, out_buf, len) == -1) {                            \
            printf("Error while writing\n");                            \
            exit(1);                                                    \
        }                                                               \
        struct timespec ts;                                             \
        clock_gettime(CLOCK_REALTIME, &ts);                             \
        dprintf(log_fd, "%ld.%09ld; In: 0x", ts.tv_sec, ts.tv_nsec);    \
        for (size_t i = 0; i < len; i++) {                              \
            dprintf(log_fd, "%02x", (unsigned char)out_buf[i]);         \
        }                                                               \
        dprintf(log_fd, "\n");                                          \
        usleep(SCAN_CYCLE_MS * 1000);                                   \
    } while(0)

uint32_t fuzzing_engine(int fd, unsigned long addr, char *in_buf, int len, int log_fd) {

  signed int stage_cur, stage_max, stage_cur_byte, stage_cur_val;
  uint8_t i, j;
  uint8_t *stage_name = "init";
  uint8_t *stage_short = "init";
  uint8_t *out_buf;
  
  uint32_t  ret_val = 1;

  out_buf = malloc(len*sizeof(len));

  memcpy(out_buf, in_buf, len);

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 4;
  stage_name  = "bitflip 1/1";

  
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 1;

    FLIP_BIT(out_buf, stage_cur);

    WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);
    
    FLIP_BIT(out_buf, stage_cur);
  }

   
  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;


  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 1;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);

    out_buf[stage_cur] ^= 0xFF;

  }

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

  for (i = 0; i < len - 1; i++) {

    stage_cur_byte = i;

    *(uint16_t*)(out_buf + i) ^= 0xFFFF;
    
    WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);
    
    stage_cur++;

    *(uint16_t*)(out_buf + i) ^= 0xFFFF;


  }

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;


  for (i = 0; i < len - 3; i++) {

    stage_cur_byte = i;

    *(uint32_t*)(out_buf + i) ^= 0xFFFFFFFF;

    WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);

    stage_cur++;

    *(uint32_t*)(out_buf + i) ^= 0xFFFFFFFF;

  }
  
  
  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  for (i = 0; i < len; i++) {

    uint8_t orig = out_buf[i];

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      uint8_t r = orig ^ (orig + j);

      WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);
      
      stage_max--;

      r =  orig ^ (orig - j);

      stage_max--;

      out_buf[i] = orig;

    }

  }


  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

 
  for (i = 0; i < len - 1; i++) {

    uint16_t orig = *(uint16_t*)(out_buf + i);


    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      uint16_t r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);

      stage_max--;
      
      stage_max--;

      
      *(uint16_t*)(out_buf + i) = orig;

    }

  }


  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;


  for (i = 0; i < len - 3; i++) {

    uint32_t orig = *(uint32_t*)(out_buf + i);


    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      uint32_t r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);
      
      WRITE_AND_LOG(fd, addr, out_buf, len, log_fd);
      
      stage_max--;
      
      stage_max--;

      
      *(uint32_t*)(out_buf + i) = orig;
      	
    }

     
    if (i == len - 4)

	return orig;

    else

	continue;
  }

  return ret_val;

}
