#include <linux/slab.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/syscalls.h>
#include <asm/page.h>
#include <asm/memory.h>
#include <asm/uaccess.h>

struct walk_info {
	pgd_t *kernel_fake_pgd_base;
	int pmd_counter;
	pmd_t *pmd_buf[512];
	unsigned long user_fake_pte_base;
	unsigned long last_written_pgd_val;
	unsigned long last_written_pmd_val;
	unsigned long last_written_pte_val;
};


int my_pgd_entry(pgd_t *pgd, unsigned long addr, unsigned long next, 
	      struct mm_walk *walk)
{
	unsigned long pgd_index = pgd_index(addr);
	struct walk_info *my_walk_info = (struct walk_info *)walk->private;
	pmd_t* new_pmd;
	int cnt;
	pgd_t *current_kernel_pgd_base =
		my_walk_info->kernel_fake_pgd_base;

	printk("Before kernel pgd buffer addr = %lu\n", addr);
	
	*(current_kernel_pgd_base + pgd_index) =
		my_walk_info->last_written_pmd_val;
	printk("After kernel pgd buffer addr = %lu\n", addr);
	my_walk_info->last_written_pmd_val += PAGE_SIZE;
	new_pmd = (pmd_t *) kcalloc(1, PAGE_SIZE, GFP_KERNEL);
	if (new_pmd == NULL) 
		return -ENOMEM;
	cnt = my_walk_info->pmd_counter;
	my_walk_info->pmd_buf[cnt] = new_pmd;
	my_walk_info->pmd_counter++;
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

	unsigned long pfn;
	int err;
	int pmd_counter;
	if (split_vma(current->mm, user_vma, current_pte_base + PAGE_SIZE, 0))
		return -EFAULT;

	if (user_vma == NULL)
		return -EINVAL;
	
	if (unlikely(user_vma->vm_start != current_pte_base)) {
		printk("vma_start mismatch\n");
		return -EFAULT;
	}
	if (unlikely(user_vma->vm_end != current_pte_base + PAGE_SIZE)) {
		printk("vma_end mismatch\n");
		return -EFAULT;
	}
	/* TODO: Check how to use PROT_READ flag */
	/* TODO: Think about behavior later*/

	if (pmd == NULL)
		return 0;

	pfn = page_to_pfn(pmd_page(*pmd));
	if (pmd_bad(*pmd) || !pfn_valid(pfn)) 
		return -EINVAL;
	
	printk("Before remap_pfn_range %lu\n", addr);
	err = 0;
	err = remap_pfn_range(user_vma, current_pte_base, 
		pfn, PAGE_SIZE, user_vma->vm_page_prot);
	printk("###################### %d\n", PROT_READ);
	printk("###################### %lu\n", (unsigned long) user_vma->vm_page_prot);
	printk("###################### %lu\n", (unsigned long) user_vma->vm_flags);
	if (err) {
		printk("remap_pfn_range errno %d\n", err);
		return -EINVAL;
	}
	printk("After remap_pfn_range %lu\n", addr);

	printk("Before kernel pmd buffer in %lu\n", addr);
	pmd_counter = my_walk_info->pmd_counter - 1;
	*(my_walk_info->pmd_buf[pmd_counter] + pmd_index) =
		my_walk_info->last_written_pte_val;
	printk("After kernel pmd buffer in %lu\n", addr);
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
	struct walk_info *my_walk_info;
	struct task_struct *target_tsk;
	pgd_t * kernel_pgd_base;
	struct vm_area_struct *pgd_vma;
	struct vm_area_struct *pmd_vma;
	struct vm_area_struct *pte_vma;
	
	int i; 
	
	target_tsk = pid == -1 ? current : find_task_by_vpid(pid);
	if (target_tsk == NULL)
		return -EINVAL;
	down_write(&current->mm->mmap_sem);
	if (pid != -1)
		down_write(&target_tsk->mm->mmap_sem);
	
	pgd_vma = find_vma(current->mm, fake_pgd);
	if (pgd_vma == NULL)
		return -EINVAL;
	if (pgd_vma->vm_start < fake_pgd) {
		if (split_vma(current->mm, pgd_vma, fake_pgd, 1))
			return -EFAULT;
	}

	pmd_vma = find_vma(current->mm, fake_pmds);
	if (pmd_vma == NULL)
		return -EINVAL;
	if (pmd_vma->vm_start < fake_pmds) {
		if (split_vma(current->mm, pmd_vma, fake_pmds, 1))
			return -EFAULT;
	}

	pte_vma = find_vma(current->mm, page_table_addr);
	if (pte_vma == NULL)
		return -EINVAL;
	if (pte_vma->vm_start < page_table_addr) {
		if (split_vma(current->mm, pte_vma, page_table_addr, 1))
			return -EFAULT;
	}
	printk("####### %d\n", PROT_READ);
	printk("####### %lu\n", (unsigned long) pte_vma->vm_page_prot);
	printk("####### %lu\n", pte_vma->vm_flags);
	pte_vma->vm_flags &= ~VM_WRITE;
	pte_vma->vm_page_prot = vm_get_page_prot(pte_vma->vm_flags);
	printk("############# %d\n", PROT_READ);
	printk("############# %lu\n", (unsigned long) pte_vma->vm_page_prot);
	printk("############# %lu\n", (unsigned long) pte_vma->vm_flags);


	kernel_pgd_base = (pgd_t *) kcalloc(1, PAGE_SIZE, GFP_KERNEL);
	my_walk_info = kcalloc(1, sizeof(struct walk_info), GFP_KERNEL);
	if (my_walk_info == NULL) 
		return -ENOMEM;
	my_walk_info->user_fake_pte_base = page_table_addr;
	my_walk_info->kernel_fake_pgd_base = kernel_pgd_base;
	my_walk_info->pmd_counter = 0;
	my_walk_info->last_written_pgd_val = fake_pgd;
	my_walk_info->last_written_pmd_val = fake_pmds;
	my_walk_info->last_written_pte_val = page_table_addr;

	walk.mm = target_tsk->mm;
	walk.private = my_walk_info;
	walk.pgd_entry = my_pgd_entry;
	walk.pmd_entry = my_pmd_entry;
	walk.pte_entry = NULL;
	walk.pud_entry = NULL;
	walk.pte_hole = NULL;
	walk.hugetlb_entry = NULL;

	walk_page_range(begin_vaddr, end_vaddr, &walk);
	if (pid != -1)
		up_write(&target_tsk->mm->mmap_sem);
	up_write(&current->mm->mmap_sem);
	
	if (copy_to_user((unsigned long *) fake_pgd, (unsigned long *)
		     kernel_pgd_base, PAGE_SIZE)) 
		return -EFAULT;

	for (i = 0; i < my_walk_info->pmd_counter; i++) {
		unsigned long result;
		pmd_t * source;
		unsigned long * dest;
		source = my_walk_info->pmd_buf[i];
		dest = (unsigned long *) (fake_pmds + i * PAGE_SIZE);
		result = copy_to_user(dest, source, PAGE_SIZE);
		if (result) 
			break;
	}

	for (i = 0; i < my_walk_info->pmd_counter; i++) {
		kfree(my_walk_info->pmd_buf[i]);
	}

	kfree(kernel_pgd_base);
	kfree(my_walk_info);
	return 0;
}
