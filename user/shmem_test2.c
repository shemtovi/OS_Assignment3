#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define SHARED_MEMORY_SIZE 4096
int main() {
    int parent_id = getpid();
    char *str = (char*)malloc(SHARED_MEMORY_SIZE); // Allocate shared memory

    int pid = fork();
    if (pid < 0) {
        printf("Fork failed\n");
        exit(1);
    } else if (pid == 0) { // Child process
        printf("Child process initial size: %d\n", sbrk(0));
        
        // Write the string in shared memory
        

        int child_pid = getpid();
         uint64 addr = map_shared_pages(parent_id, child_pid, (uint64)str, SHARED_MEMORY_SIZE);
        printf("Child process size after mapping: %d\n", sbrk(0));
        strcpy((char *)addr, "Hello daddy");
        // Unmap shared memory
        unmap_shared_pages(child_pid, addr, SHARED_MEMORY_SIZE);
        printf("Child process size after unmapping: %d\n", sbrk(0));
        sleep(10);
        // Allocate memory using malloc
        str = (char*)malloc(SHARED_MEMORY_SIZE*100);
        printf("Child process size after malloc: %d\n", sbrk(0));

        // Exit child
        exit(0);
    } else { // Parent process
        sleep(10); // Wait a bit for the child to write to shared memory

        // Print the string written by the child
        printf("Parent read: %s\n", str);

        // Wait for the child to finish
        wait(0);
    }

    free(str); // Free the allocated memory
    exit(0);
}
