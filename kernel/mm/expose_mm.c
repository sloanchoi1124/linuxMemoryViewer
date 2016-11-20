
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/syscalls.h>
#include <asm/page.h>
#include <asm/memory.h>
/*
int pgd_entry(pgd_t *pgd, unsigned long addr, unsigned long next, 
	      struct mm_walk *walk);
int pmd_entry(pmd_t *pmd, unsigned long addr, unsigned long next, 
	      struct mm_walk *walk);
*/
struct walk_info {
	pgd_t *kernel_pgd_va_base;
	pmd_t *kernel_pmd_va_base;
	unsigned long user_fake_pmd_base;
};

SYSCALL_DEFINE2(get_pagetable_layout, struct pagetable_layout_info __user *, 
		pgtbl_info, int, size) {
	struct pagetable_layout_info layout_info;
	if (size < sizeof(struct pagetable_layout_info))
		return -EINVAL;
	layout_info.pgdir_shift = PGDIR_SHIFT;
	layout_info.pmd_shift = PMD_SHIFT;
	layout_info.page_shift = PAGE_SHIFT;
	if (copy_to_user(pgtbl_info, &layout_info, size))
		return -EFAULT;
	
	return 0;

}

SYSCALL_DEFINE6(expose_page_table, pid_t, pid, unsigned long, fake_pgd,
		unsigned long, fake_pmds, unsigned long, page_table_addr, 
		unsigned long, begin_vaddr, unsigned long, end_vaddr) {
	struct mm_walk *walk;
	struct walk_info my_walk_info;
	struct task_struct *target_tsk;
	struct vm_area_struct *user_vma;
	unsigned long pgd_pfn = 0;
	pgd_t *kernel_pgd_va_base;

	//TODO: RCU lock
	target_tsk = pid == -1 ? current : find_task_by_vpid(pid);
	if (target_tsk == NULL)
		return -EINVAL;

	kernel_pgd_va_base = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kernel_pgd_va_base)
		return -ENOMEM;

	user_vma = find_vma(current->mm, fake_pgd);
	if (user_vma == NULL)
		return -EINVAL;

	if (!virt_addr_valid(kernel_pgd_va_base))
		return -EINVAL;
	pgd_pfn = (unsigned long) virt_to_phys(kernel_pgd_va_base);
	/*
	//TODO: check if this is the right way to translate PA;
	pgd_pfn = page_to_pfn(pgd_page(kernel_pgd_va_base));
	if (pgd_none(kernel_pgd_va_base) 
	    || pgd_bad(kernel_pgd_va_base) 
	    || !pfn_valid(pgd_pfn))
		return -EINVAL;
	*/
	//TODO: check pgf_pfn validity
	if (!remap_pfn_range(user_vma, fake_pgd, pgd_pfn, PAGE_SIZE, PROT_READ));
		return -EINVAL;
	
	//prepare member functions of struct mm_walk *walk;
	my_walk_info.user_fake_pmd_base = fake_pmds;
	my_walk_info.kernel_pgd_va_base = kernel_pgd_va_base;
	walk->private = (void *)&my_walk_info;
	



	return 0;
}
