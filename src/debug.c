#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <elf.h>

#include "debug.h"

void print_ehdr(Elf64_Ehdr *ehdr) {
    printf("e_ident:");
    for (int i = 0; i < EI_NIDENT; i++)
        printf(" %02x", ehdr->e_ident[i]);
    printf("\n");

    printf("type: %x\n", ehdr->e_type);
    
    printf("entry : 0x%lx\n", ehdr->e_entry);

    printf("program header table start: %ld\n", ehdr->e_phoff);
    printf("program header entry size: %d\n", ehdr->e_phentsize);
    printf("program header entry count: %d\n", ehdr->e_phnum);

    printf("\n");
}

void print_phdr(Elf64_Phdr *phdr) {
    printf("%d %x %lx\n %016lx\n %016lx %016lx\n %016lx %016lx \n", 
        phdr->p_type, 
        phdr->p_flags,
        phdr->p_align,
        phdr->p_offset,
        phdr->p_vaddr,
        phdr->p_paddr,
        phdr->p_filesz,
        phdr->p_memsz);
}

void dump_stack(char *rsp) {
    printf("argc @ 0x%p: %d\n", rsp, *((uint32_t *)rsp) );
    rsp += 8;

    printf("argv @ 0x%p:\n", rsp);
    while (*rsp) {
        printf(" %s\n", *((char **)rsp));
        rsp += 8;
    }
    rsp += 8;

    printf("envp @ 0x%p:\n", rsp);
    while (*((char **)rsp)) {
        printf(" %s\n", *((char **)rsp));
        rsp += 8;
    }
    rsp += 8;

    printf("auxv @ 0x%p:\n", rsp);
    while (*((char **)rsp)) {
        printf("% ld : %lx (%ld)\n", *((uint64_t *)(rsp)), *((uint64_t *)(rsp+8)), *((uint64_t *)(rsp+8)));
        rsp += 16;
    }
}