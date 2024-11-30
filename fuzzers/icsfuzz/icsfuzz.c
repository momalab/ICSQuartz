#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "mutator.h"
#include <signal.h> // For signal handling


#define LEN 128
#define MAX_LINE_LENGTH 80

int log_fd = -1;

// Fuzzer cleanup
void cleanup_and_exit(int signum) {
    if (log_fd != -1) {
        close(log_fd);
    }
    printf("\nICSFuzz exiting gracefully after receiving signal %d\n", signum);
    exit(0);
}


// ICSFuzz entry point
int main(int argc, char* argv[]) {

	// Check if input arguments are valid
 	if (argc != 5) {
		printf("./fuzzer pid addr length tid\n");
 		exit(1);
	}

	// Parse input arguments: 
	int pid = strtoul(argv[1], NULL, 10);
	unsigned long addr = strtoul(argv[2], NULL, 16);
	int len  = strtol (argv[3], NULL, 10);
	int taskid  = strtoul(argv[4], NULL, 10);

	// Log inputs (for coverage tracking)
	log_fd = open("/icsfuzz.log", O_WRONLY | O_CREAT | O_APPEND, 0644);

    // Set up signal handlers for SIGINT and SIGTERM
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

	// Form /proc/pid/mem and /proc/pid/maps strings.
	// /proc/pid/maps shows the memory structure and the areas of the memory area of the process.
	// /proc/pid/mem is the actual virtual memory of the process.
	// Source: https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
	char* proc_mem = malloc(50);
	sprintf(proc_mem, "/proc/%d/mem", pid);
	
	char* proc_maps = malloc(50);
	sprintf(proc_maps, "/proc/%d/maps", pid);

	// Open the codesys runtime memory
	printf("opening %s, address is 0x%lx\n", proc_mem, addr);
	int fd_proc_mem = open(proc_mem, O_RDWR);
	if (fd_proc_mem == -1) {
		printf("Could not open %s\n", proc_mem);
		exit(1);
	}

	// Create a buffer for the input to the fuzzer
	char *buf = malloc(len);
	int seed_input = 0xdeadbeef;
	sprintf(buf, "%d", seed_input);
                    
	// Move the fd_proc_mem memory pointer to the address used for fuzzing
	lseek(fd_proc_mem, addr, SEEK_SET);
	
	// Main fuzzing loop
	while(1){
		// The fuzzing engine mutates the input in the buffer, uses it for fuzzing, and then returns it as retval
		uint32_t retval = fuzzing_engine(fd_proc_mem, addr, buf, len, log_fd);
		// Place the mutated fuzzer output back into the input buffer, for use in the next loop
		// If we want to keep track of inputs that crash the application, we need to output this to a log file
		sprintf(buf, "%d", retval);
	}
	
	// Free memory before exiting
	free(buf);
	free(proc_mem);
	free(proc_maps);
	close(log_fd);

	return 0;
}