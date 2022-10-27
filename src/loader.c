#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <elf.h>
#include <signal.h>

#include "debug.h"

#define PGSIZE (1UL << 12)
#define PGMASK (PGSIZE - 1)
#define ALIGN_LOW(x)  (((uint64_t) (x))  & ~PGMASK)
#define ALIGN_HIGH(x) ((((uint64_t) (x)) + PGMASK) & ~PGMASK)

#define MAX_AUXV 48
typedef struct {
    uint64_t atnum;
    uint64_t atval;
} Elf_Aux;

typedef struct {
    int aux_cnt;
    Elf_Aux aux[MAX_AUXV];
} Elf_Auxv;

#define AUX_NEW(auxv, num, val) \
    do { \
        (auxv)->aux[(auxv)->aux_cnt].atnum = (num); \
        (auxv)->aux[(auxv)->aux_cnt].atval = (val); \
        (auxv)->aux_cnt++; \
    } while(0)

#define STACK_PUSH(sp, x) \
    do { \
        (sp) = ((void *)(sp)) - 8; \
        *((uint64_t *)(sp)) = (uint64_t) (x); \
    } while(0)

#define STACK_PUSH_AUX(sp, atnum, atval) \
    do { \
        STACK_PUSH(sp, atval); \
        STACK_PUSH(sp, atnum); \
    } while(0)

int load_elf(const char *elf, void **entry, Elf_Auxv *auxv);


// // TODO: Demand Paging
// static void handler(int sig, siginfo_t *si, void *unused)
// {
//     printf("Got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
//     printf("Implements the handler only\n");

//     exit(EXIT_FAILURE);
// }

void start_exec(void *entry, void *sp) {
    __asm__ __volatile__(
        "mov $0, %%rax\n"
        "mov $0, %%rbx\n"
        "mov $0, %%rcx\n"
        "mov $0, %%rdx\n"
        "mov $0, %%rsi\n"
        "mov $0, %%rdi\n"
        // "mov $0, %%rbp\n"
        "mov $0, %%r8\n"
        "mov $0, %%r9\n"
        "mov $0, %%r10\n"
        "mov $0, %%r11\n"
        "mov $0, %%r12\n"
        "mov $0, %%r13\n"
        "mov $0, %%r14\n"
        "mov $0, %%r15\n"
    :::);

    __asm__ __volatile__(
        "mov %0, %%rsp\n"
    ::"a"(sp):);

    __asm__ __volatile__(
        "jmp *%0\n"
    ::"a"(entry):);
}

int setup_stack(int argc, char **argv, char **envp, Elf_Auxv *auxv, void **sp) {
    char **argv_p, **envp_p;
    char *rsp;
    void *stack_end;

    uint64_t size = PGSIZE*5; // TODO: proper size (cannot grow)
    int prot = PROT_READ|PROT_WRITE;
    int flags = MAP_PRIVATE|MAP_GROWSDOWN|MAP_POPULATE|MAP_STACK|MAP_ANON;

    if ((stack_end = mmap(0, size, prot, flags, -1, 0)) == MAP_FAILED) {
        perror("Error while mmap");
        return -1;
    }
    stack_end += size; 
    rsp = stack_end;

    int envc = 0;
    for (char **tmp = envp; *tmp != NULL; tmp++) envc++;

    envp_p = malloc(sizeof (char *) * envc);

    for (int i = 0; i < envc; i++) {
        rsp -= strlen(envp[i]) + 1;
        strcpy(rsp, envp[i]);
        envp_p[i] = rsp;
    }

    argv_p = malloc(sizeof (char *) * (argc-1));

    for (int i = 1; i < argc; i++) {
        rsp -= strlen(argv[i]) + 1;
        strcpy(rsp, argv[i]);
        argv_p[i-1] = rsp;
    }

    for (int i = 0; i < 16; i++) {
        *--rsp = rand();
    }
    char *rand = rsp;

    // Align stack by 16 bytes.
    rsp = (char *) ((uint64_t) rsp &  ~0xfUL);

    // Fill auxv.
    STACK_PUSH_AUX(rsp, AT_NULL, 0);
    STACK_PUSH_AUX(rsp, AT_RANDOM, rand);

    STACK_PUSH_AUX(rsp, AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
    STACK_PUSH_AUX(rsp, AT_HWCAP, getauxval(AT_HWCAP));
    STACK_PUSH_AUX(rsp, AT_HWCAP2, getauxval(AT_HWCAP2));
    STACK_PUSH_AUX(rsp, AT_PAGESZ, getauxval(AT_PAGESZ));
    STACK_PUSH_AUX(rsp, AT_CLKTCK, getauxval(AT_CLKTCK));
    STACK_PUSH_AUX(rsp, AT_FLAGS, getauxval(AT_FLAGS));
    STACK_PUSH_AUX(rsp, AT_UID, getauxval(AT_UID));
    STACK_PUSH_AUX(rsp, AT_EUID, getauxval(AT_EUID));
    STACK_PUSH_AUX(rsp, AT_GID, getauxval(AT_GID));
    STACK_PUSH_AUX(rsp, AT_EGID, getauxval(AT_EGID));
    STACK_PUSH_AUX(rsp, AT_PLATFORM, getauxval(AT_PLATFORM));

    for (int i = 0; i < auxv->aux_cnt; i++) {
        STACK_PUSH_AUX(rsp, auxv->aux[i].atnum, auxv->aux[i].atval);
    }
    
    rsp -= sizeof (char *);
    *((uint64_t *) rsp) = 0;
    rsp -= sizeof (char *) * (envc);
    memcpy(rsp, envp_p, sizeof (char *) * (envc));

    rsp -= sizeof (char *);
    *((uint64_t *) rsp) = 0;
    rsp -= sizeof (char *) * (argc - 1);
    memcpy(rsp, argv_p, sizeof (char *) * (argc-1));

    rsp -= sizeof (char *);
    *((uint64_t *) rsp) = argc - 1;

    // dump_stack(rsp);

    *sp = rsp;

    free(envp_p);
    free(argv_p);

    return 0;
}

int load_exec(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr_p) {
    // Read and load segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = &phdr_p[i];

        if (phdr->p_type == PT_LOAD) {
            int prot = PROT_NONE;
            if (phdr->p_flags & PF_R) prot |= PROT_READ;
            if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
            if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

            int flags = MAP_PRIVATE|MAP_FIXED_NOREPLACE|MAP_POPULATE;

            uint64_t addr_align = ALIGN_LOW(phdr->p_vaddr);
            size_t size_align = ALIGN_HIGH(phdr->p_vaddr + phdr->p_filesz) - addr_align;
            if ((uint64_t) mmap((void *)addr_align, size_align, prot, flags, fd, ALIGN_LOW(phdr->p_offset)) != addr_align) {
                perror("Error while mmap");
                return -1;
            }

            flags |= MAP_ANON;

            uint64_t anon_addr = addr_align + size_align;
            size_t anon_size = (ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) > anon_addr)? ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) - anon_addr : 0;
            if (anon_size > 0) {
                if ((uint64_t) mmap((void *)anon_addr, anon_size, prot, flags, -1, 0) != anon_addr) {
                    perror("Error while mmap");
                    return -1;
                }
                if (prot & PROT_WRITE)
                    memset((void *) (phdr->p_vaddr + phdr->p_filesz), 
                        0UL, 
                        (size_t) (anon_addr - (phdr->p_vaddr + phdr->p_filesz)));
            }
        }

        // TODO: relro
    }

    return 0;
}

int load_dyn(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr_p, void **entry, Elf_Auxv *auxv) {
    uint64_t base, vaddr_start, vaddr_end;
    size_t load_addr_min = -1;
    size_t load_addr_max = 0;
    size_t load_size;
    char *interp = NULL;
    void *interp_entry;

    // Check if it contains PT_INTERP
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = &phdr_p[i];

        if (phdr->p_type == PT_INTERP) {
            interp = malloc(phdr->p_filesz);
            lseek(fd, phdr->p_offset, SEEK_SET);
            read(fd, interp, phdr->p_filesz);
        }

        else if (phdr->p_type == PT_LOAD) {
            vaddr_start = ALIGN_LOW(phdr->p_vaddr);
            vaddr_end = ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz);
            load_addr_min = (vaddr_start < load_addr_min)? vaddr_start : load_addr_min;
            load_addr_max = (vaddr_end > load_addr_max)? vaddr_end : load_addr_max;
        }
    }

    load_size = load_addr_max - load_addr_min;

    if ((base = (uint64_t) mmap(0, load_size, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0)) == (uint64_t)MAP_FAILED) {
        perror("Error while mmap");
        return -1;
    } 

    if (interp) {
        load_elf(interp, &interp_entry, auxv);
        AUX_NEW(auxv, AT_ENTRY, ehdr->e_entry + base);
    } else {
        AUX_NEW(auxv, AT_BASE, base);
    }

    if (base != (uint64_t)MAP_FAILED) {
        munmap((void *)base, load_size);
    }

    // Read and load segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = &phdr_p[i];

        // print_phdr(phdr);

        if (phdr->p_type == PT_LOAD) {
            int prot = PROT_NONE;
            if (phdr->p_flags & PF_R) prot |= PROT_READ;
            if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
            if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

            int flags = MAP_PRIVATE|MAP_FIXED_NOREPLACE|MAP_POPULATE;

            uint64_t addr_align = ALIGN_LOW(phdr->p_vaddr);
            size_t size_align = ALIGN_HIGH(phdr->p_vaddr + phdr->p_filesz) - addr_align;
            if ((uint64_t) mmap((void *)addr_align + base, size_align, prot, flags, fd, ALIGN_LOW(phdr->p_offset)) != addr_align + base) {
                perror("Error while mmap");
                return -1;
            }

            flags |= MAP_ANON;

            uint64_t anon_addr = addr_align + size_align;
            size_t anon_size = (ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) > anon_addr)? ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) - anon_addr : 0;
            if (anon_size > 0) {
                if ((uint64_t) mmap((void *)anon_addr + base, anon_size, prot, flags, -1, 0) != anon_addr + base) {
                    perror("Error while mmap");
                    return -1;
                }
                if (prot & PROT_WRITE)
                    memset((void *) (phdr->p_vaddr + base + phdr->p_filesz), 0UL, anon_addr - (phdr->p_vaddr + phdr->p_filesz));
            }
        }

        else if (phdr->p_type == PT_PHDR) {
            AUX_NEW(auxv, AT_PHDR, ehdr->e_phoff + base);
            AUX_NEW(auxv, AT_PHENT, ehdr->e_phentsize);
            AUX_NEW(auxv, AT_PHNUM, ehdr->e_phnum);
        }

        // TODO: relro
    }

    if (interp)
        *entry = interp_entry;
    else 
        *entry = (void *) (ehdr->e_entry + base);

    free(interp);

    return 0;
}

int load_elf(const char *elf, void **entry, Elf_Auxv *auxv) {
    int fd, ret = -1;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;

    if ((fd = open(elf, O_RDONLY)) < 0) {
        perror("Error while opening binary file:");
        exit(EXIT_FAILURE);
    };

    // Read and validate elf file header
    lseek(fd, 0, SEEK_SET);
    if (read(fd, &ehdr, sizeof ehdr) < 0) {
        perror("Error while reading file header");
        return -1;
    };

    // TODO: validate file header

    // print_ehdr(&ehdr);

    // Read and load segments
    phdr = malloc(ehdr.e_phentsize * ehdr.e_phnum);

    lseek(fd, ehdr.e_phoff, SEEK_SET);
    if (read(fd, phdr, ehdr.e_phentsize * ehdr.e_phnum) < 0) {
        perror("Error while reading program header");
        return -1;
    }

    if (ehdr.e_type == ET_EXEC) {
        AUX_NEW(auxv, AT_ENTRY, ehdr.e_entry);
        *entry = (void *) ehdr.e_entry;
        ret = load_exec(fd, &ehdr, phdr);
    }
    else if (ehdr.e_type == ET_DYN) {
        ret = load_dyn(fd, &ehdr, phdr, entry, auxv);
    }
    else {
        printf("Elf type not supported\n");
        ret = -1;
    }

    free(phdr);

    return ret;
}

int main(int argc, char **argv, char **envp) {
    int fd;
    Elf_Auxv auxv;
    void *entry, *sp;

    // signal(SIGSEGV, handler);

    if (argc < 2) {
        printf("Usage: %s [binary] [args...]\n", argv[0]);
        exit(0);
    }

    auxv.aux_cnt = 0;
    memset(auxv.aux, 0UL, sizeof (Elf_Aux) * MAX_AUXV);
    AUX_NEW(&auxv, AT_EXECFN, (uint64_t)argv[1]);

    if (load_elf(argv[1], &entry, &auxv) < 0) {
        exit(EXIT_FAILURE);
    }

    if (setup_stack(argc, argv, envp, &auxv, &sp) < 0) {
        exit(EXIT_FAILURE);
    }

    start_exec(entry, sp);
}