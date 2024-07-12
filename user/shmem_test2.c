#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    int size = 20;
    int parent_id = getpid();
    char *str = (char*)malloc(size); 

    uint64 address;
    int pid = fork();
    if (pid < 0) {
        printf("Fork failed\n");
        exit(1);
    }
    else if (pid > 0)
    { // daddt process
        sleep(30); 
        printf("daddy reads: %s\n", str);
        wait(0);
    }
    else 
    { // Child process
        printf("Child intit size: %d\n", sbrk(0));
        
        int child_pid = getpid();
        address = map_shared_pages(parent_id, child_pid, (uint64)str, size);
        printf("Child size post map: %d\n", sbrk(0));
        //copy
        strcpy((char *)address, "Hello daddy");
        //unmap
        unmap_shared_pages(child_pid, address, size);
        printf("Child  size post unmap: %d\n", sbrk(0));
        sleep(10);
        
        str = (char*)malloc(size);
        printf("Child size post malloc: %d\n", sbrk(0));

        exit(0);
    }

    free(str); // Free the allocated memory
    exit(0);
}
