#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

int main(int argc, char ** argv)
{
	/*
	struct pagetable_layout_info pti;
	syscall(244, &pti, sizeof(struct pagetable_layout_info));
	printf("Pgd_shift = %d\n", pti.pgdir_shift);
	printf("Pmd_shift = %d\n", pti.pmd_shift);
	printf("Page_shift = %d\n", pti.page_shift);
	return 0;
	*/

	size_t pgd_len = 1 << 30;
	unsigned long fake_pgd = (unsigned long)
		mmap(NULL, pgd_len, PROT_READ, MAP_ANONYMOUS, -1, 0);	

	unsigned long fake_pmd = (unsigned long )
		mmap(NULL, pgd_len, PROT_READ, MAP_ANONYMOUS, -1, 0);	

	unsigned long fake_pte = (unsigned long )
		mmap(NULL, pgd_len, PROT_READ, MAP_ANONYMOUS, -1, 0);
	
	pid_t pid =  strtol(argv[1], NULL, 10);
	unsigned long begin_vaddr = strtol(argv[2], NULL, 16);
	unsigned long end_vaddr = strtol(argv[3], NULL, 16);
	printf("before syscall\n");
	syscall(245, pid, fake_pgd, fake_pmd, fake_pte, begin_vaddr, end_vaddr);
	printf("after syscall\n");
	unsigned long i = 0;
	for (i = 0; i < 512; i++) {
		//unsigned long * tmp = (unsigned long *) (fake_pgd + i);	
		//if (!tmp) continue;
		//printf("%lu\n", *tmp);
	}
	return 0;


}
