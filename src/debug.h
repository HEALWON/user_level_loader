#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <elf.h>

void print_ehdr(Elf64_Ehdr *ehdr);
void print_phdr(Elf64_Phdr *phdr);
void dump_stack(char *rsp);

#endif // __DEBUG_H__