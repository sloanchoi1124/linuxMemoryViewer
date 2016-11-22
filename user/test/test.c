#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

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

	size_t pgd_len = sysconf(_SC_PAGE_SIZE) * 4096;
	unsigned long fake_pgd;
	unsigned long fake_pmd;
	unsigned long fake_pte;

	void *result = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE| MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		perror("1 mmap fail\n");
		exit(1);
	}
	fake_pgd = (unsigned long)result;

	result = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		perror("2 mmap fail\n");
		exit(1);
	}
	fake_pmd = (unsigned long)result;
	
	result = mmap(NULL, pgd_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		perror("3 mmap fail\n");
		exit(1);
	}
	fake_pte = (unsigned long)result;

	pid_t pid =  strtol(argv[1], NULL, 10);
	char *ptr;

	unsigned long begin_vaddr = strtol(argv[2], &ptr, 16);
	unsigned long end_vaddr = strtol(argv[3], &ptr, 16);

	printf("before syscall\n");
	syscall(245, pid, fake_pgd, fake_pmd, fake_pte, begin_vaddr, end_vaddr);
	//syscall(245, pid, fake_pgd, fake_pmd, fake_pte, fake_pgd, fake_pmd);
	printf("after syscall\n");
	unsigned long i = 0;
	for (i = 0; i < 512; i++) {
		//unsigned long * tmp = (unsigned long *) (fake_pgd + i);	
		//if (!tmp) continue;
		//printf("%lu\n", *tmp);
	}
	return 0;


}
