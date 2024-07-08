#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define SHARED_MEMORY_SIZE 4096


int main() {
    int perent_id = getpid();
     char *test = (char*)malloc(20);
    int pid = fork();
    if (pid < 0) {
        printf("Fork failed\n");
        exit(1);
    } else if (pid == 0) { // Child process
        sleep(10);

        printf("test:%s, test_addr:%d\n", test,test);
        int child_pid = getpid();
        uint64 addr = map_shared_pages(perent_id,child_pid,(uint64)test, 20);
         printf("addr: %d\n", addr);
        printf("Child read:%s\n", (char*)addr);

        exit(0);
    } else { // Parent process
        strcpy(test, "Hello Childddddd");
        wait(0);

    }

    exit(0);
}
