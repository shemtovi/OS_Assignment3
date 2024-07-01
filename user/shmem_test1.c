#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define SHARED_MEMORY_SIZE 4096


int main() {
    char *shared_mem = "not initialaized";
    int perent_id = getpid();
    int pid = fork();
    if (pid < 0) {
        printf("Fork failed\n");
        exit(1);
    } else if (pid == 0) { // Child process
        // Wait a bit for the parent to map the shared memory
        sleep(1);
        int child_pid = getpid();
        int addr = map_shared_pages(perent_id,child_pid,*shared_mem, SHARED_MEMORY_SIZE);
        // Print the shared memory content
        printf("Child read: %s\n", &addr);

        // Exit child
        exit(0);
    } else { // Parent process
        // Map shared memory to the child process
        // if (map_shared_pages(shared_mem, SHARED_MEMORY_SIZE, pid) == 0) {
        //     printf("Shared memory mapping failed\n");
        //     exit(1);
        // }

        // Wait for the child to finish
        shared_mem = "Hello Child";
        wait(0);

        // Clean up (optional, since we're exiting)
        free(shared_mem);
    }

    exit(0);
}

