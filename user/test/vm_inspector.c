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
#define PTE_VALID	1UL << 0
#define PTE_PROC_NONE	1UL << 1
#define PTE_DIRTY	1UL << 55
#define PTE_RDONLY	1UL << 7
#define PTE_AF		1UL << 10
#define PTE_UXN		1UL << 54
#define PTE_FILE	1UL << 2
#define pte_present(pte)	(!!(pte & (PTE_VALID | PTE_PROC_NONE)))
#define pte_young(pte)		(!!(pte & (PTE_AF)))
#define pte_file(pte)		(!!(pte & (PTE_FILE)))
#define pte_dirty(pte)		(!!(pte & (PTE_DIRTY)))
#define pte_read_only(pte)	(!!(pte & (PTE_RDONLY)))
#define pte_uxn(pte)		(!!(pte & (PTE_UXN)))

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
	int err;

	pid_t pid;
	char *ptr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
	int verbose;
	
	size_t pgd_len = sysconf(_SC_PAGE_SIZE) * 4096;
	unsigned long fake_pgd_base;
	unsigned long fake_pmd_base;
	unsigned long page_table_addr;

	unsigned long fake_pgd_max;
	unsigned long fake_pmd_max;
	unsigned long fake_pte_max;

	void *tmp;

	if (argc == 5) {
		pid = strtol(argv[2], NULL, 10);
		if (strncmp("-v", argv[1], 2) != 0) {
			printf("Usage: ./vm_inspector -v pid va_begin va_end\n");
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
	
	err = 0;
	tmp = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (tmp == MAP_FAILED) {
		perror("line 69: mmap fail\n");
		err = 1;
		goto rt;
	}
	fake_pgd_base = (unsigned long)tmp;
	fake_pgd_max = fake_pgd_base + pgd_len;

	tmp = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (tmp == MAP_FAILED) {
		perror("line 77:  mmap fail\n");
		err = 1;
		goto free_pgd;
	}
	fake_pmd_base = (unsigned long)tmp;
	fake_pmd_max = fake_pmd_base + pgd_len;

	tmp = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (tmp == MAP_FAILED) {
		perror("line 85: mmap fail\n");
		err = 1;
		goto free_pmd;
	}

	page_table_addr = (unsigned long)tmp;
	fake_pte_max = page_table_addr + pgd_len;
	
	if (syscall(245, pid, fake_pgd_base, fake_pmd_base, page_table_addr, begin_vaddr, end_vaddr)) {
		perror("syscall 245 failed!\n");
		err = 1;
		goto free_pte;
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
	unsigned long phys_mask;
	phys_mask = get_phys();
	
	current_va = begin_vaddr;
	while(current_va <= end_vaddr) {
		cur_pgd_index = pgd_index(current_va);
		if ((fake_pgd_base + cur_pgd_index * ENTRY_SIZE) >= fake_pgd_max)
			goto next_va;

		cur_fake_pmd = *((unsigned long *)(fake_pgd_base + cur_pgd_index * ENTRY_SIZE));
		if (cur_fake_pmd == 0)
			goto next_va;

		cur_pmd_index = pmd_index(current_va);
		if ((cur_fake_pmd + cur_pmd_index * ENTRY_SIZE) >= fake_pmd_max)
			goto next_va;

		cur_fake_pte = *((unsigned long *)(cur_fake_pmd + cur_pmd_index * ENTRY_SIZE));
		if (cur_fake_pte == 0)
			goto next_va;

		if ((cur_fake_pte + cur_pte_index * ENTRY_SIZE) >= fake_pte_max)
			goto next_va;

		cur_pte_index = pte_index(current_va);
		table_entry = *((unsigned long *)(cur_fake_pte + cur_pte_index * ENTRY_SIZE));
		
		if (table_entry == 0)
			goto next_va;

		if (pte_present(table_entry) == 0) 
			goto next_va;
			
		cur_pa_base = (table_entry & phys_mask) >> PAGE_SHIFT;
		cur_pa = (cur_pa_base << PAGE_SHIFT) + pa_offset(current_va);
		printf("0x%lx\t0x%lx\t%d\t%d\t%d\t%d\t%d\n", current_va, cur_pa,
		       pte_young(table_entry), pte_file(table_entry),
		       pte_dirty(table_entry), pte_read_only(table_entry),
		       pte_uxn(table_entry));
		current_va += 4096;
		continue;
next_va:	
		if (verbose)
			printf("0x%lx\t0x%lx\t%d\t%d\t%d\t%d\t%d\n", current_va, 
			       cur_pa, 0, 0, 0, 0, 0);
		current_va += 4096;
	}
free_pte:
	munmap((void *)page_table_addr, pgd_len);
free_pmd:
	munmap((void *)fake_pmd_base, pgd_len);
free_pgd:
	munmap((void *)fake_pgd_base, pgd_len);
rt:
	exit(err);



}
