#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <elf.h>

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

#define STACK_PUSH_U64(sp, x) \
    do { \
        (sp) = ((void *)(sp)) - sizeof (uint64_t); \
        *((uint64_t *)(sp)) = (uint64_t) (x); \
    } while(0)

#define STACK_PUSH_AUX(sp, atnum, atval) \
    do { \
        STACK_PUSH_U64(sp, atval); \
        STACK_PUSH_U64(sp, atnum); \
    } while(0)

#define DEBUG_MMAP(addr, size, prot, flags, fd, ofs, check_addr) \
    do { \
        if (fd < 0) fprintf(stderr, "Elf map (addr: 0x%lx) (size: 0x%lx) (type: ANON)\n", addr, size); \
        else fprintf(stderr, "Elf map (addr: 0x%lx) (size: 0x%lx) (type: FILE) (offset: 0x%lx)\n", addr, size, ofs); \
        if ((uint64_t) mmap(addr, size, prot, flags, fd, ofs) != check_addr) { \
            perror("Error while mmap"); \
            return -1; \
        } \
    } while(0)

int load_elf(const char *elf, void **entry, Elf_Auxv *auxv);


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

    uint64_t size = PGSIZE*8; // TODO: proper size (cannot grow)
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

    rsp = (char *) ((uint64_t) rsp &  ~0xfUL);

    // Setup auxv.
    AUX_NEW(auxv,  AT_RANDOM, rand);
    AUX_NEW(auxv,  AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
    AUX_NEW(auxv,  AT_HWCAP, getauxval(AT_HWCAP));
    AUX_NEW(auxv,  AT_HWCAP2, getauxval(AT_HWCAP2));
    AUX_NEW(auxv,  AT_PAGESZ, getauxval(AT_PAGESZ));
    AUX_NEW(auxv,  AT_CLKTCK, getauxval(AT_CLKTCK));
    AUX_NEW(auxv,  AT_FLAGS, getauxval(AT_FLAGS));
    AUX_NEW(auxv,  AT_UID, getauxval(AT_UID));
    AUX_NEW(auxv,  AT_EUID, getauxval(AT_EUID));
    AUX_NEW(auxv,  AT_GID, getauxval(AT_GID));
    AUX_NEW(auxv,  AT_EGID, getauxval(AT_EGID));
    AUX_NEW(auxv,  AT_PLATFORM, getauxval(AT_PLATFORM));

    // Align stack so that rsp be aligned by 16 at last.
    // 1 (argc) + argc (argv) + envc + 1 (envp) + aux_cnt*2 + 2 (auxv) 
    int args_cnt = (auxv->aux_cnt * 2) + envc + argc + 4;
    if (args_cnt % 2) STACK_PUSH_U64(rsp, 0);

    // Fill auxv.
    STACK_PUSH_AUX(rsp, AT_NULL, 0);
    for (int i = 0; i < auxv->aux_cnt; i++) {
        STACK_PUSH_AUX(rsp, auxv->aux[i].atnum, auxv->aux[i].atval);
    }

    // Fill envp.
    STACK_PUSH_U64(rsp, 0);
    rsp -= sizeof (char *) * (envc);
    memcpy(rsp, envp_p, sizeof (char *) * (envc));

    // Fill argv
    STACK_PUSH_U64(rsp, 0);
    rsp -= sizeof (char *) * (argc - 1);
    memcpy(rsp, argv_p, sizeof (char *) * (argc-1));

    // Set argc
    STACK_PUSH_U64(rsp, 0);
    *((int *) rsp) = argc - 1;

    // dump_stack(rsp);

    *sp = rsp;

    free(envp_p);
    free(argv_p);

    return 0;
}

int load_exec(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr_p, Elf_Auxv *auxv) {
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
            DEBUG_MMAP((void *)addr_align, size_align, prot, flags, fd, ALIGN_LOW(phdr->p_offset), addr_align);
            flags |= MAP_ANON;

            uint64_t anon_addr = addr_align + size_align;
            size_t anon_size = (ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) > anon_addr)? ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) - anon_addr : 0;
            if (anon_size > 0) {
                DEBUG_MMAP((void *)anon_addr, anon_size, prot, flags, -1, 0, anon_addr);
                if (prot & PROT_WRITE)
                    memset((void *) (phdr->p_vaddr + phdr->p_filesz), 
                        0UL, 
                        (size_t) (anon_addr - (phdr->p_vaddr + phdr->p_filesz)));
            }

            if (phdr->p_offset == 0) {
                AUX_NEW(auxv, AT_PHDR, ehdr->e_phoff + addr_align);
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
            DEBUG_MMAP((void *)addr_align + base, size_align, prot, flags, fd, ALIGN_LOW(phdr->p_offset), addr_align + base);

            flags |= MAP_ANON;

            uint64_t anon_addr = addr_align + size_align;
            size_t anon_size = (ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) > anon_addr)? ALIGN_HIGH(phdr->p_vaddr + phdr->p_memsz) - anon_addr : 0;
            if (anon_size > 0) {
                DEBUG_MMAP((void *)anon_addr + base, anon_size, prot, flags, -1, 0, anon_addr + base);
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
    if (read(fd, &ehdr, sizeof (Elf64_Ehdr)) < 0) {
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
        AUX_NEW(auxv, AT_PHENT, ehdr.e_phentsize);
        AUX_NEW(auxv, AT_PHNUM, ehdr.e_phnum);
        *entry = (void *) ehdr.e_entry;
        ret = load_exec(fd, &ehdr, phdr, auxv);
    }
    else if (ehdr.e_type == ET_DYN) {
        ret = load_dyn(fd, &ehdr, phdr, entry, auxv);
    }
    else {
        printf("Elf type not supported\n");
        ret = -1;
    }

    free(phdr);

    close(fd);

    return ret;
}

int main(int argc, char **argv, char **envp) {
    int fd;
    Elf_Auxv auxv;
    void *entry, *sp;

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