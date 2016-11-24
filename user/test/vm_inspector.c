#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

#define ENTRY_SIZE	8
#define PGDIR_SHIFT	30
#define PMD_SHIFT	21
#define PAGE_SHIFT	12
#define PTRS_PER_PGD	512
#define PTRS_PER_PMD	512
#define PTRS_PER_PTE	512
#define PAGE_SIZE	4096


unsigned long get_phys()
{
	unsigned long tmp = 1;
	return (tmp << 40) - 1;
}
int pgd_index(unsigned long addr) 
{
	return (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1));
}

int pmd_index(unsigned long addr) 
{
	return (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1));
}
int pte_index(unsigned long addr)
{
	return (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1));
}
int pa_offset(unsigned long addr)
{
	return addr & (PAGE_SIZE - 1);
}
int main(int argc, char ** argv)
{

	size_t pgd_len = sysconf(_SC_PAGE_SIZE) * 4096;
	unsigned long fake_pgd_base;
	unsigned long fake_pmd_base;
	unsigned long page_table_addr;

	void *result = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		perror("1 mmap fail\n");
		exit(1);
	}
	fake_pgd_base = (unsigned long)result;

	result = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		perror("2 mmap fail\n");
		exit(1);
	}
	fake_pmd_base = (unsigned long)result;
	
	result = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		perror("3 mmap fail\n");
		exit(1);
	}
	page_table_addr = (unsigned long)result;


	pid_t pid;
	char *ptr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
	int verbose;
	if (argc == 5) {
		pid = strtol(argv[2], NULL, 10);
		if (strncmp("-v", argv[1], 2) != 0) {
			printf("Usage: ./vm_inspector -v pid va_begin va_end");
			exit(1);
		}
		verbose = 1;
		begin_vaddr = strtol(argv[3], &ptr, 16);
		end_vaddr = strtol(argv[4], &ptr, 16);
	} else if (argc == 4) {
		verbose = 0;
		pid = strtol(argv[1], NULL, 10);
		begin_vaddr = strtol(argv[2], &ptr, 16);
		end_vaddr = strtol(argv[3], &ptr, 16);
	} else {
		printf("usage: ./vm_inspector -v pid va_begin va_end\n");
		exit(1);
	}

	if (begin_vaddr >= end_vaddr) {
		printf("invalid begin_vaddr and end_vaddr\n");
		exit(1);
	}
	if (syscall(245, pid, fake_pgd_base, fake_pmd_base, page_table_addr, begin_vaddr, end_vaddr)) {
		perror("syscall 245 failed!\n");
		exit(1);
	}
	int cur_pgd_index;
	int cur_pmd_index;
	int cur_pte_index;
	unsigned long cur_fake_pmd;
	unsigned long cur_fake_pte;
	unsigned long cur_pa_base;
	unsigned long cur_pa;
	unsigned long current_va;
	unsigned long table_entry;
	current_va = begin_vaddr;
	unsigned long phys_mask;
	phys_mask = get_phys();
	while(current_va <= end_vaddr) {
		cur_pgd_index = pgd_index(current_va);
		cur_fake_pmd = *((unsigned long *)(fake_pgd_base + cur_pgd_index * ENTRY_SIZE));
		cur_pmd_index = pmd_index(current_va);
		cur_fake_pte = *((unsigned long *)(cur_fake_pmd + cur_pmd_index * ENTRY_SIZE));
		cur_pte_index = pte_index(current_va);
		table_entry = *((unsigned long *)(cur_fake_pte + cur_pte_index * ENTRY_SIZE));
		
		cur_pa_base = (table_entry & phys_mask) >> PAGE_SHIFT;
		cur_pa = cur_pa_base + pa_offset(current_va);
		printf("%lx\t%lx\n", current_va, cur_pa << PAGE_SHIFT);
		current_va += 4096;
	}
	return 0;


}
