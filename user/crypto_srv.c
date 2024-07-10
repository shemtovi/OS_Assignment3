#include "kernel/types.h"
#include "user/user.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/fs.h"
#include "kernel/file.h"
#include "kernel/fcntl.h"

#include "kernel/crypto.h"

int main(void) {
  if(open("console", O_RDWR) < 0){
    mknod("console", CONSOLE, 0);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr

  printf("crypto_srv: starting\n");

  if(getpid() != 2){
    printf("runnig not by kernel(getpid() != 2)\n");
    exit(0);
  }

  while(1){
    void* pointer;
    uint64 size;
    if(take_shared_memory_request(&pointer,&size) == -1){
      //error mapping
      printf("ERROR IN MAPPING\n");
      exit(1);
    }
    printf("finnish mapping\n");
    struct crypto_op *op = (struct crypto_op*)pointer;
    if(op->state != CRYPTO_OP_STATE_INIT){
      asm volatile ("fence rw,rw" : : : "memory");
      op->state = CRYPTO_OP_STATE_ERROR;
    }
    if(!((op->type == CRYPTO_OP_TYPE_ENCRYPT)||(op->type == CRYPTO_OP_TYPE_DECRYPT))){
      asm volatile ("fence rw,rw" : : : "memory");
      op->state = CRYPTO_OP_STATE_ERROR;
    }   
   
    uint64 key_size = op->key_size;
    uint64 data_size = op->data_size;
    uchar * key = op->payload;
    uchar * data = op->payload + key_size;
    for(int index = 0; index<data_size;index++){
      int offset = index%key_size;
      data[index] ^= key[offset];
    }   
    asm volatile ("fence rw,rw" : : : "memory");
    op->state = CRYPTO_OP_STATE_DONE;
    printf("finnish encryption\n");
    if(remove_shared_memory_request(op,size) == -1){
      //error unmapping
      printf("ERROR IN UNMAPPING\n");
      exit(1);
    }
  }

  exit(0);
}