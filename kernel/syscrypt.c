#include "types.h"
#include "param.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"

#include "shmem_queue.h"

volatile struct proc* crypto_srv_proc = 0;

// a user program that calls exec("/crypto_srv")
// assembled from ../user/init_crypto_srv.S
// od -t xC ../user/init_crypto_srv
static uchar crypto_srv_init_code[] = {
  0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45,
  0x02, 0x97, 0x05, 0x00, 0x00, 0x93, 0x85,
  0x95, 0x02, 0x93, 0x08, 0x70, 0x00, 0x73,
  0x00, 0x00, 0x00, 0x93, 0x08, 0x20, 0x00,
  0x73, 0x00, 0x00, 0x00, 0xef, 0xf0, 0x9f,
  0xff, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74,
  0x6f, 0x5f, 0x73, 0x72, 0x76, 0x00, 0x00,
  0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

uint64 sys_crypto_op(void) {
    // Crypto server process not initialized yet
    if (crypto_srv_proc == 0) {
        return -1;
    }

    uint64 crypto_op;
    uint64 size;

    argaddr(0, &crypto_op);
    argaddr(1, &size);

    const struct proc *p = myproc();

    // Record crypto operation request in the shmem queue
    shmem_queue_insert(p->pid, crypto_srv_proc->pid, crypto_op, size);

    return 0;
}

uint64 sys_take_shared_memory_request(void) {
  struct proc *p = myproc();
  if (crypto_srv_proc == 0 || p != crypto_srv_proc) {
      return -1;
  }

  const struct shmem_request req = shmem_queue_remove();
  
  struct proc* src_proc = find_proc(req.src_pid);
  if (src_proc == 0) {
    return -1;
  }
  acquire(&src_proc->lock);
  const uint64 dst_va = map_shared_pages(src_proc, p, req.src_va, req.size);
  if (dst_va == 0) {
    release(&src_proc->lock);
    return -1;
  }

  uint64 arg_dst_va;
  uint64 arg_dst_size;
  argaddr(0, &arg_dst_va);
  argaddr(1, &arg_dst_size);
  copyout(p->pagetable, arg_dst_va, (char*)&dst_va, sizeof(dst_va));
  copyout(p->pagetable, arg_dst_size, (char*)&req.size, sizeof(req.size));

  release(&src_proc->lock);
  return 0;
}

uint64 sys_remove_shared_memory_request(void) {
  struct proc *p = myproc();
  if (crypto_srv_proc == 0 || p != crypto_srv_proc) {
      return -1;
  }

  uint64 src_va;
  uint64 size;

  argaddr(0, &src_va);
  argaddr(1, &size);

  return unmap_shared_pages(p, src_va, size);
}

// Set up crypto server process AFTER userspace has been initialized
void
crypto_srv_init(void)
{
  struct proc* p = allocproc();
  crypto_srv_proc = p;
  
  // allocate one user page and copy the crypto_srv_init_code
  uvmfirst(p->pagetable, crypto_srv_init_code, sizeof(crypto_srv_init_code));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "crypto_srv_init", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;
  release(&p->lock);
}


uint64 sys_unmap_shared_pages(void){
  uint64 proc_pid;
  uint64 addr;
  uint64 size;

  argint(0, (int*)&proc_pid);
  argaddr(1, &addr);
  argint(2, (int*)&size);

  struct proc* proc = find_proc(proc_pid);
  return unmap_shared_pages(proc,addr,size);
}

uint64 sys_map_shared_pages(void){
  uint64 src_proc_pid;
  uint64 dst_proc_pid;
  uint64 src_va;
  uint64 size;

  argint(0, (int*)&src_proc_pid);
  argint(1, (int*)&dst_proc_pid);
  argaddr(2, &src_va);
  argint(3, (int*)&size);
 

  struct proc* src_proc = find_proc(src_proc_pid);
  struct proc* dst_proc = find_proc(dst_proc_pid);
  if (src_proc == 0 || dst_proc == 0) {
    return -1;
  }

  uint64 dst_va = map_shared_pages(src_proc, dst_proc, src_va, size);
  if (dst_va == 0) {
    return -1;
  }

  return dst_va;

}

uint64 map_shared_pages(struct proc* src_proc, struct proc* dst_proc, uint64 src_va, uint64 size) {
    uint64 src_start = PGROUNDDOWN(src_va);
    uint64 src_end = PGROUNDUP(src_va + (uint32)size);
    uint64 dst_start_va = PGROUNDUP(dst_proc->sz);
    printf("src_start :%x%x, src_end :%x%x,dst_start_va:%x%x\n,src_va:%x%x\n",(uint32)(src_start >> 32), (uint32)src_start,
                                                                              (uint32)(src_end >> 32), (uint32)src_end,
                                                                              (uint32)(dst_start_va >> 32), (uint32)dst_start_va,
                                                                              (uint32)(src_va >> 32), (uint32)src_va);
    
    uint64 dst_addr = dst_start_va;

    for (uint64 addr = src_start; addr < src_end; addr += PGSIZE) {       
        pte_t* pte = walk(src_proc->pagetable, addr, 0);
        printf("addr:%d PTE:%p\n",addr,pte);
        if (pte == 0 || (*pte & PTE_V) == 0 || (*pte & PTE_U) == 0){
             printf("pte FLAGS faild\n");
            return 0;
        }
          

        uint64 pa = PTE2PA(*pte);
        uint64 flags = PTE_FLAGS(*pte) | PTE_S; 
        if (mappages(dst_proc->pagetable, dst_addr, PGSIZE, pa, flags) != 0){
          printf("MAPPAGES FAILS\n");
          return 0;
        }
        dst_addr += PGSIZE;
            
    }
    printf("finished mappage\n");
    dst_proc->sz = dst_addr;
    return dst_start_va + (src_va - src_start);
}

uint64 unmap_shared_pages(struct proc* p, uint64 addr, uint64 size){
  uint64 unmap_start = PGROUNDDOWN(addr);
  uint64 unmap_end = PGROUNDUP(addr + size);
  printf("unmap_start :%x%x, unmap_end :%x%x,addr:%x%x, size:%x%x\n",(uint32)(unmap_start >> 32), (uint32)unmap_start,
                                                          (uint32)(unmap_end >> 32), (uint32)unmap_end,
                                                          (uint32)(addr >> 32), (uint32)addr,
                                                          (uint32)(size >> 32), (uint32)size);
  
  if (p->sz < unmap_end || size < 0 || addr < 0) {
    printf("unmap fall in 200");
    return -1;
  }
  for (uint64 va = unmap_start; va < unmap_end; va += PGSIZE) {
        pte_t* pte = walk(p->pagetable, va, 0);
        if((*pte & PTE_S) == 0){
          printf("unmap fall in PTE_S ==0");
          return -1;
        }

  }
  uvmunmap(p->pagetable,unmap_start,((unmap_end-unmap_start)/PGSIZE),0);
  p->sz = unmap_start;
  return 0;
}

