#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/syscalls.h>
#include <asm/page.h>
#include <asm/memory.h>
#include <asm/uaccess.h>

struct walk_info {
	unsigned long user_fake_pgd_base;
	unsigned long user_fake_pmd_base;
	unsigned long user_fake_pte_base;
	unsigned long last_written_pgd_val;
	unsigned long last_written_pmd_val;
	unsigned long last_written_pte_val;
};


int my_pgd_entry(pgd_t *pgd, unsigned long addr, unsigned long next, 
	      struct mm_walk *walk)
{
	unsigned long pgd_index = pgd_index(addr);
	//unsigned long pgd_index = pgd - walk->mm->pgd;
	struct walk_info *my_walk_info = (struct walk_info *)walk->private;
	unsigned long current_pgd_base = my_walk_info->user_fake_pgd_base;
	printk("Before put_user addr = %lu\n", addr);
	if (put_user(my_walk_info->last_written_pmd_val, 
		  (pgd_t*)current_pgd_base + pgd_index)) {
		printk("put_user fail = %lu\n", addr);
		return -EFAULT;
	}
	printk("After put_user addr = %lu\n", addr);
	my_walk_info->last_written_pmd_val += PAGE_SIZE;
	return 0;
}

int my_pmd_entry(pmd_t *pmd, unsigned long addr, unsigned long next, 
	      struct mm_walk *walk)
{	
	unsigned long pmd_index = pmd_index(addr);
	struct walk_info *my_walk_info = (struct walk_info *)walk->private;
	
	unsigned long current_pte_base = my_walk_info->last_written_pte_val;
	struct vm_area_struct *user_vma = 
		find_vma(current->mm, current_pte_base);
	if (user_vma == NULL)
		return -EINVAL;
	
	/* TODO: Check how to use PROT_READ flag */
	/* TODO: Think about behavior later*/

	if (pmd == NULL)
		return 0;
		
	if (remap_pfn_range(user_vma, current_pte_base, 
		*pmd, PAGE_SIZE, PROT_READ))
		return -EINVAL;

	unsigned long current_pmd_base = 
		my_walk_info->last_written_pmd_val - PAGE_SIZE;
	//TODO: figure out why put_user might fail!! is it failing because of
	//semaphore?
	put_user(my_walk_info->last_written_pte_val, 
		 (pmd_t*)current_pmd_base + pmd_index);
		//return -EFAULT;
	my_walk_info->last_written_pte_val += PAGE_SIZE;
	
	return 0;
}
SYSCALL_DEFINE2(get_pagetable_layout, struct pagetable_layout_info __user *, 
		pgtbl_info, int, size) 
{
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
		unsigned long, begin_vaddr, unsigned long, end_vaddr) 
{
	struct mm_walk walk;
	struct walk_info my_walk_info;
	struct task_struct *target_tsk;
	struct vm_area_struct *user_vma;

	//TODO: RCU lock
	target_tsk = pid == -1 ? current : find_task_by_vpid(pid);
	if (target_tsk == NULL)
		return -EINVAL;
	down_write(&current->mm->mmap_sem);
	if (pid != -1)
		down_write(&target_tsk->mm->mmap_sem);
	//prepare member functions of struct mm_walk *walk;
	my_walk_info.user_fake_pmd_base = fake_pmds;
	my_walk_info.user_fake_pgd_base = fake_pgd;
	my_walk_info.user_fake_pte_base = page_table_addr;
	my_walk_info.last_written_pgd_val = fake_pgd;
	my_walk_info.last_written_pmd_val = fake_pmds;
	my_walk_info.last_written_pte_val = page_table_addr;

	walk.mm = target_tsk->mm;
	walk.private = &my_walk_info;
	walk.pgd_entry = my_pgd_entry;
	walk.pmd_entry = NULL;
	walk.pte_entry = NULL;
	walk.pud_entry = NULL;
	walk.pte_hole = NULL;
	walk.hugetlb_entry = NULL;
	//walk->pgd_entry = my_pgd_entry;
	//walk->pmd_entry = my_pmd_entry;

	walk_page_range(begin_vaddr, end_vaddr, &walk);
	if (pid != -1)
		up_write(&target_tsk->mm->mmap_sem);
	up_write(&current->mm->mmap_sem);
	return 0;
}
