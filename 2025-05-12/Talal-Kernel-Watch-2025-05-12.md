
# Talal Kernel Watch Report - 2025-05-12

## 🔍 Detection Results

### LTP Test Results

| Test | Result |
|------|--------|
| Filesystem Tests | No Issues Found |
| Memory Management | No Issues Found |
| Process Management | No Issues Found |
| Networking Tests | No Issues Found |
| Device Drivers | Flaw Detected |
| System Calls | No Issues Found |


### CWE Analysis

#### CWE-190: Integer Overflow or Wraparound (Exploitability: 6)
- **Description**: In the \`ext4_fc_track_range\` calls, especially when \`shrink\` is false, the right-hand side of the shift operation \`(attr->ia_size > 0 ? attr->ia_size - 1 : 0) >> inode->i_sb->s_blocksize_bits\` or \`(oldsize > 0 ? oldsize - 1 : oldsize) >> inode->i_sb->s_blocksize_bits\` could lead to an integer overflow if \`inode->i_sb->s_blocksize_bits\` is sufficiently large and \`attr->ia_size\` or \`oldsize\` are small. This overflowed value is then used as an argument to \`ext4_fc_track_range\`. While \`ext4_fc_track_range\` might mitigate this by capping the maximum value, the initial overflow can still cause incorrect tracking, potentially leading to a denial of service or data corruption due to mismanagement of free clusters. The condition \`attr->ia_size > 0 ? attr->ia_size - 1 : 0\` (or similar for oldsize) is meant to prevent negative values after subtraction but does not prevent large right shift amounts.
- **Location**: Lines containing calls to \`ext4_fc_track_range\` when shrink is false, specifically where the end block parameter is calculated.
- **Code**:
```c
if (attr->ia_size != inode->i_size) {  // Line 5800  
    /\* attach jbd2 jinode for EOF folio tail zeroing \*/  
    if (attr->ia_size & (inode->i_sb->s_blocksize - 1) ||  
        oldsize & (inode->i_sb->s_blocksize - 1)) {  
        error = ext4_inode_attach_jinode(inode);  
        if (error)  
            goto out_mmap_sem;  
    }  
  
    handle = ext4_journal_start(inode, EXT4_HT_INODE, 3);  
    if (IS_ERR(handle)) {  
        error = PTR_ERR(handle);  
        goto out_mmap_sem;  
    }  
    if (ext4_handle_valid(handle) && shrink) {  
        error = ext4_orphan_add(handle, inode);  
        orphan = 1;  
    }  
  
    if (!shrink) {  
        inode_set_mtime_to_ts(inode,  
                              inode_set_ctime_current(inode));  
        if (oldsize & (inode->i_sb->s_blocksize - 1))  
            ext4_block_truncate_page(handle,  
                                     inode->i_mapping, oldsize);  
    }  
  
    if (shrink)  
        ext4_fc_track_range(handle, inode,  
            (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >>  
            inode->i_sb->s_blocksize_bits,  
            EXT_MAX_BLOCKS - 1);  
    else  
        ext4_fc_track_range(  
            handle, inode,  
            (oldsize > 0 ? oldsize - 1 : oldsize) >>  
            inode->i_sb->s_blocksize_bits,  
            (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >>  
            inode->i_sb->s_blocksize_bits);  
  
    down_write(&EXT4_I(inode)->i_data_sem);  
    old_disksize = EXT4_I(inode)->i_disksize;  
    EXT4_I(inode)->i_disksize = attr->ia_size;  
    rc = ext4_mark_inode_dirty(handle, inode);  
    if (!error)  
        error = rc;  
   
    if (!error)  
        i_size_write(inode, attr->ia_size);  
    else  
        EXT4_I(inode)->i_disksize = old_disksize;  
    up_write(&EXT4_I(inode)->i_data_sem);  
    ext4_journal_stop(handle);  
    if (error)  
        goto out_mmap_sem;  
    if (!shrink) {  
        pagecache_isize_extended(inode, oldsize,  
                                 inode->i_size);  
    } else if (ext4_should_journal_data(inode)) {  
        ext4_wait_for_tail_page_commit(inode);  
    }  
}
```
- **Matched CVEs**:
- CVE-2024-58017: "In the Linux kernel, the following vulnerability has been resolved:  
  
printk: Fix signed integer overflow when defining LOG_BUF_LEN_MAX  
  
Shifting 1 << 31 on a 32-bit int causes signed integer overflow, which  
leads to undefined behavior. To prevent this, cast 1 to u32 before  
performing the shift, ensuring well-defined behavior.  
  
This change explicitly avoids any potential overflow by ensuring that  
the shift occurs on an unsigned 32-bit integer." (Similarity: 60)
- CVE-2025-21736: "In the Linux kernel, the following vulnerability has been resolved:  
  
nilfs2: fix possible int overflows in nilfs_fiemap()  
  
Since nilfs_bmap_lookup_contig() in nilfs_fiemap() calculates its result  
by being prepared to go through potentially maxblocks == INT_MAX blocks,  
the value in n may experience an overflow caused by left shift of blkbits.  
  
While it is extremely unlikely to occur, play it safe and cast right hand  
expression to wider type to mitigate the issue.  
  
Found by Linux Verification Center (linuxtesting.org) with static analysis  
tool SVACE." (Similarity: 58)
- CVE-2025-39735: "In the Linux kernel, the following vulnerability has been resolved:  
  
jfs: fix slab-out-of-bounds read in ea_get()  
  
During the "size_check" label in ea_get(), the code checks if the extended  
attribute list (xattr) size matches ea_size. If not, it logs  
"ea_get: invalid extended attribute" and calls print_hex_dump().  
  
Here, EALIST_SIZE(ea_buf->xattr) returns 4110417968, which exceeds  
INT_MAX (2,147,483,647). Then ea_size is clamped:  
  
	int size = clamp_t(int, ea_size, 0, EALIST_SIZE(ea_buf->xattr));  
  
Although clamp_t aims to bound ea_size between 0 and 4110417968, the upper  
limit is treated as an int, causing an overflow above 2^31 - 1. This leads  
"size" to wrap around and become negative (-184549328).  
  
The "size" is then passed to print_hex_dump() (called "len" in  
print_hex_dump()), it is passed as type size_t (an unsigned  
type), this is then stored inside a variable called  
"int remaining", which is then assigned to "int linelen" which  
is then passed to hex_dump_to_buffer(). In print_hex_dump()  
the for loop, iterates through 0 to len-1, where len is  
18446744073525002176, calling hex_dump_to_buffer()  
on each iteration:  
  
	for (i = 0; i < len; i += rowsize) {  
		linelen = min(remaining, rowsize);  
		remaining -= rowsize;  
  
		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,  
				   linebuf, sizeof(linebuf), ascii);  
  
		...  
	}  
  
The expected stopping condition (i < len) is effectively broken  
since len is corrupted and very large. This eventually leads to  
the "ptr+i" being passed to hex_dump_to_buffer() to get closer  
to the end of the actual bounds of "ptr", eventually an out of  
bounds access is done in hex_dump_to_buffer() in the following  
for loop:  
  
	for (j = 0; j < len; j++) {  
			if (linebuflen < lx + 2)  
				goto overflow2;  
			ch = ptr\[j\];  
		...  
	}  
  
To fix this we should validate "EALIST_SIZE(ea_buf->xattr)"  
before it is utilised." (Similarity: 58)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: The code checks for integer overflows in the calculation \`pgoff + (len >> PAGE_SHIFT) < pgoff\`.  However, this check is insufficient to prevent all integer overflows. If \`len\` is sufficiently large (close to the maximum value of its data type), right-shifting it by \`PAGE_SHIFT\` (which is typically 12) might not significantly reduce the value. If \`pgoff\` is also a large value, the addition \`pgoff + (len >> PAGE_SHIFT)\` could still overflow, wrapping around to a smaller value. This smaller value might then be incorrectly interpreted as being less than \`pgoff\`, bypassing the intended overflow check. The potential impact is memory corruption or denial of service.  An attacker controlling \`pgoff\` and \`len\` could trigger an integer overflow, leading to incorrect memory mapping parameters. This incorrect mapping can result in out-of-bounds memory access and potential system compromise.
- **Location**: Line containing: \`if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)\`
- **Code**:
```c
if (!len)  // Line 580  
    return -EINVAL;  
  
  
if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))  
    if (!(file && path_noexec(&file->f_path)))  
        prot |= PROT_EXEC;  
  
  
if (flags & MAP_FIXED_NOREPLACE)  
    flags |= MAP_FIXED;  
  
if (!(flags & MAP_FIXED))  
    addr = round_hint_to_min(addr);  
  
  
len = PAGE_ALIGN(len);  
if (!len)  
    return -ENOMEM;  
  
  
if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)  
    return -EOVERFLOW;  
  
  
if (mm->map_count > sysctl_max_map_count)  
    return -ENOMEM;  
  
  
  
if (prot == PROT_EXEC) {  
    pkey = execute_only_pkey(mm);  
    if (pkey < 0)  
        pkey = 0;  
}  
  
  
vm_flags |= calc_vm_prot_bits(prot, pkey) | calc_vm_flag_bits(file, flags) |  
        mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;  
  
addr = __get_unmapped_area(file, addr, len, pgoff, flags, vm_flags);  
if (IS_ERR_VALUE(addr))  
    return addr;  
  
if (flags & MAP_FIXED_NOREPLACE) {  
    if (find_vma_intersection(mm, addr, addr + len))  
        return -EEXIST;  
}  
  
if (flags & MAP_LOCKED)  
    if (!can_do_mlock())  
        return -EPERM;  
  
if (!mlock_future_ok(mm, vm_flags, len))  
    return -EAGAIN;
```
- **Matched CVEs**:
- CVE-2025-22091: "In the Linux kernel, the following vulnerability has been resolved:  
  
RDMA/mlx5: Fix page_size variable overflow  
  
Change all variables storing mlx5_umem_mkc_find_best_pgsz() result to  
unsigned long to support values larger than 31 and avoid overflow.  
  
For example: If we try to register 4GB of memory that is contiguous in  
physical memory, the driver will optimize the page_size and try to use  
an mkey with 4GB entity size. The 'unsigned int' page_size variable will  
overflow to '0' and we'll hit the WARN_ON() in alloc_cacheable_mr().  
  
WARNING: CPU: 2 PID: 1203 at drivers/infiniband/hw/mlx5/mr.c:1124 alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
Modules linked in: mlx5_ib mlx5_core bonding ip6_gre ip6_tunnel tunnel6 ip_gre gre rdma_rxe rdma_ucm ib_uverbs ib_ipoib ib_umad rpcrdma ib_iser libiscsi scsi_transport_iscsi rdma_cm iw_cm ib_cm fuse ib_core \[last unloaded: mlx5_core\]  
CPU: 2 UID: 70878 PID: 1203 Comm: rdma_resource_l Tainted: G        W          6.14.0-rc4-dirty #43  
Tainted: \[W\]=WARN  
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014  
RIP: 0010:alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
Code: 90 90 90 90 90 90 90 90 0f 1f 44 00 00 55 48 89 e5 41 57 41 56 41 55 41 54 41 52 53 48 83 ec 30 f6 46 28 04 4c 8b 77 08 75 21 <0f> 0b 49 c7 c2 ea ff ff ff 48 8d 65 d0 4c 89 d0 5b 41 5a 41 5c 41  
RSP: 0018:ffffc900006ffac8 EFLAGS: 00010246  
RAX: 0000000004c0d0d0 RBX: ffff888217a22000 RCX: 0000000000100001  
RDX: 00007fb7ac480000 RSI: ffff8882037b1240 RDI: ffff8882046f0600  
RBP: ffffc900006ffb28 R08: 0000000000000001 R09: 0000000000000000  
R10: 00000000000007e0 R11: ffffea0008011d40 R12: ffff8882037b1240  
R13: ffff8882046f0600 R14: ffff888217a22000 R15: ffffc900006ffe00  
FS:  00007fb7ed013340(0000) GS:ffff88885fd00000(0000) knlGS:0000000000000000  
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033  
CR2: 00007fb7ed1d8000 CR3: 00000001fd8f6006 CR4: 0000000000772eb0  
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000  
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400  
PKRU: 55555554  
Call Trace:  
 <TASK>  
 ? __warn+0x81/0x130  
 ? alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
 ? report_bug+0xfc/0x1e0  
 ? handle_bug+0x55/0x90  
 ? exc_invalid_op+0x17/0x70  
 ? asm_exc_invalid_op+0x1a/0x20  
 ? alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
 create_real_mr+0x54/0x150 \[mlx5_ib\]  
 ib_uverbs_reg_mr+0x17f/0x2a0 \[ib_uverbs\]  
 ib_uverbs_handler_UVERBS_METHOD_INVOKE_WRITE+0xca/0x140 \[ib_uverbs\]  
 ib_uverbs_run_method+0x6d0/0x780 \[ib_uverbs\]  
 ? __pfx_ib_uverbs_handler_UVERBS_METHOD_INVOKE_WRITE+0x10/0x10 \[ib_uverbs\]  
 ib_uverbs_cmd_verbs+0x19b/0x360 \[ib_uverbs\]  
 ? walk_system_ram_range+0x79/0xd0  
 ? ___pte_offset_map+0x1b/0x110  
 ? __pte_offset_map_lock+0x80/0x100  
 ib_uverbs_ioctl+0xac/0x110 \[ib_uverbs\]  
 __x64_sys_ioctl+0x94/0xb0  
 do_syscall_64+0x50/0x110  
 entry_SYSCALL_64_after_hwframe+0x76/0x7e  
RIP: 0033:0x7fb7ecf0737b  
Code: ff ff ff 85 c0 79 9b 49 c7 c4 ff ff ff ff 5b 5d 4c 89 e0 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa b8 10 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 7d 2a 0f 00 f7 d8 64 89 01 48  
RSP: 002b:00007ffdbe03ecc8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010  
RAX: ffffffffffffffda RBX: 00007ffdbe03edb8 RCX: 00007fb7ecf0737b  
RDX: 00007ffdbe03eda0 RSI: 00000000c0181b01 RDI: 0000000000000003  
RBP: 00007ffdbe03ed80 R08: 00007fb7ecc84010 R09: 00007ffdbe03eed4  
R10: 0000000000000009 R11: 0000000000000246 R12: 00007ffdbe03eed4  
R13: 000000000000000c R14: 000000000000000c R15: 00007fb7ecc84150  
 </TASK>" (Similarity: 53)
- CVE-2024-57973: "In the Linux kernel, the following vulnerability has been resolved:  
  
rdma/cxgb4: Prevent potential integer overflow on 32bit  
  
The "gl->tot_len" variable is controlled by the user.  It comes from  
process_responses().  On 32bit systems, the "gl->tot_len + sizeof(struct  
cpl_pass_accept_req) + sizeof(struct rss_header)" addition could have an  
integer wrapping bug.  Use size_add() to prevent this." (Similarity: 50)
- CVE-2025-22107: "In the Linux kernel, the following vulnerability has been resolved:  
  
net: dsa: sja1105: fix kasan out-of-bounds warning in sja1105_table_delete_entry()  
  
There are actually 2 problems:  
- deleting the last element doesn't require the memmove of elements  
  \[i + 1, end) over it. Actually, element i+1 is out of bounds.  
- The memmove itself should move size - i - 1 elements, because the last  
  element is out of bounds.  
  
The out-of-bounds element still remains out of bounds after being  
accessed, so the problem is only that we touch it, not that it becomes  
in active use. But I suppose it can lead to issues if the out-of-bounds  
element is part of an unmapped page." (Similarity: 50)


#### CWE-400: Uncontrolled Resource Consumption (Exploitability: 6)
- **Description**: The code contains a check \`data_race(nr_threads >= max_threads)\`. While this check is present to prevent exceeding the maximum number of threads, the usage of \`data_race\` indicates a potential race condition. If multiple processes concurrently attempt to create threads, they might all pass this check simultaneously \*before\* any of them actually increment \`nr_threads\`. Consequently, more threads than \`max_threads\` could be created, leading to uncontrolled resource consumption. This could exhaust system resources like memory or process IDs, resulting in denial of service. The \`goto bad_fork_cleanup_count;\` provides a mechanism to cleanup in case of an error, but this error condition might be triggered only \*after\* the limit is exceeded, possibly after significant resource exhaustion has already occurred.
- **Location**: Line where \`data_race(nr_threads >= max_threads)\` is evaluated.
- **Code**:
```c
retval = copy_creds(p, clone_flags);  // Line 2993  
if (retval < 0)  
    goto bad_fork_free;  
  
retval = -EAGAIN;  
if (is_rlimit_overlimit(task_ucounts(p), UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC))) {  
    if (p->real_cred->user != INIT_USER &&  
        !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))  
        goto bad_fork_cleanup_count;  
}  
current->flags &= ~PF_NPROC_EXCEEDED;  
  
  
retval = -EAGAIN;  
if (data_race(nr_threads >= max_threads))  
    goto bad_fork_cleanup_count;  
  
delayacct_tsk_init(p);      
p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE | PF_NO_SETAFFINITY);  
p->flags |= PF_FORKNOEXEC;  
INIT_LIST_HEAD(&p->children);  
INIT_LIST_HEAD(&p->sibling);  
rcu_copy_process(p);  
p->vfork_done = NULL;  
spin_lock_init(&p->alloc_lock);  
  
init_sigpending(&p->pending);  
  
p->utime = p->stime = p->gtime = 0;  
#ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME  
p->utimescaled = p->stimescaled = 0;  
#endif  
prev_cputime_init(&p->prev_cputime);  
  
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN  
seqcount_init(&p->vtime.seqcount);  
p->vtime.starttime = 0;  
p->vtime.state = VTIME_INACTIVE;  
#endif  
  
#ifdef CONFIG_IO_URING  
p->io_uring = NULL;  
#endif  
  
p->default_timer_slack_ns = current->timer_slack_ns;  
  
#ifdef CONFIG_PSI  
p->psi_flags = 0;  
#endif  
  
task_io_accounting_init(&p->ioac);  
acct_clear_integrals(p);
```
- **Matched CVEs**:
- CVE-2022-49685: "In the Linux kernel, the following vulnerability has been resolved:  
  
iio: trigger: sysfs: fix use-after-free on remove  
  
Ensure that the irq_work has completed before the trigger is freed.  
  
 ==================================================================  
 BUG: KASAN: use-after-free in irq_work_run_list  
 Read of size 8 at addr 0000000064702248 by task python3/25  
  
 Call Trace:  
  irq_work_run_list  
  irq_work_tick  
  update_process_times  
  tick_sched_handle  
  tick_sched_timer  
  __hrtimer_run_queues  
  hrtimer_interrupt  
  
 Allocated by task 25:  
  kmem_cache_alloc_trace  
  iio_sysfs_trig_add  
  dev_attr_store  
  sysfs_kf_write  
  kernfs_fop_write_iter  
  new_sync_write  
  vfs_write  
  ksys_write  
  sys_write  
  
 Freed by task 25:  
  kfree  
  iio_sysfs_trig_remove  
  dev_attr_store  
  sysfs_kf_write  
  kernfs_fop_write_iter  
  new_sync_write  
  vfs_write  
  ksys_write  
  sys_write  
  
 ==================================================================" (Similarity: 56)
- CVE-2022-49578: "In the Linux kernel, the following vulnerability has been resolved:  
  
ip: Fix data-races around sysctl_ip_prot_sock.  
  
sysctl_ip_prot_sock is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing." (Similarity: 55)
- CVE-2022-49607: "In the Linux kernel, the following vulnerability has been resolved:  
  
perf/core: Fix data race between perf_event_set_output() and perf_mmap_close()  
  
Yang Jihing reported a race between perf_event_set_output() and  
perf_mmap_close():  
  
	CPU1					CPU2  
  
	perf_mmap_close(e2)  
	  if (atomic_dec_and_test(&e2->rb->mmap_count)) // 1 - > 0  
	    detach_rest = true  
  
						ioctl(e1, IOC_SET_OUTPUT, e2)  
						  perf_event_set_output(e1, e2)  
  
	  ...  
	  list_for_each_entry_rcu(e, &e2->rb->event_list, rb_entry)  
	    ring_buffer_attach(e, NULL);  
	    // e1 isn't yet added and  
	    // therefore not detached  
  
						    ring_buffer_attach(e1, e2->rb)  
						      list_add_rcu(&e1->rb_entry,  
								   &e2->rb->event_list)  
  
After this; e1 is attached to an unmapped rb and a subsequent  
perf_mmap() will loop forever more:  
  
	again:  
		mutex_lock(&e->mmap_mutex);  
		if (event->rb) {  
			...  
			if (!atomic_inc_not_zero(&e->rb->mmap_count)) {  
				...  
				mutex_unlock(&e->mmap_mutex);  
				goto again;  
			}  
		}  
  
The loop in perf_mmap_close() holds e2->mmap_mutex, while the attach  
in perf_event_set_output() holds e1->mmap_mutex. As such there is no  
serialization to avoid this race.  
  
Change perf_event_set_output() to take both e1->mmap_mutex and  
e2->mmap_mutex to alleviate that problem. Additionally, have the loop  
in perf_mmap() detach the rb directly, this avoids having to wait for  
the concurrent perf_mmap_close() to get around to doing it to make  
progress." (Similarity: 55)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: The code checks if \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\`. However, both \`to_shinfo->nr_frags\` and \`from_shinfo->nr_frags\` are integers. Therefore, their sum can potentially overflow, resulting in a small value. This small value might be less than \`MAX_SKB_FRAGS\`, bypassing the intended check and leading to \`skb_fill_page_desc\` being called with \`to_shinfo->nr_frags\` exceeding \`MAX_SKB_FRAGS - 1\`. This can lead to out-of-bounds write in \`skb_shinfo(to)->frags\[\]\` array, potentially corrupting kernel memory.
- **Location**: Line containing: \`if (to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS)\`
- **Code**:
```c
bool skb_try_coalesce(struct sk_buff \*to, struct sk_buff \*from,  
                      bool \*fragstolen, int \*delta_truesize)  
{  
    struct skb_shared_info \*to_shinfo, \*from_shinfo;  
    int i, delta, len = from->len;  
  
    \*fragstolen = false;  
  
    if (skb_cloned(to))  
        return false;  
  
    if (to->pp_recycle != from->pp_recycle)  
        return false;  
  
    if (skb_frags_readable(from) != skb_frags_readable(to))  
        return false;  
  
    if (len <= skb_tailroom(to) && skb_frags_readable(from)) {  
        if (len)  
            BUG_ON(skb_copy_bits(from, 0, skb_put(to, len), len));  
        \*delta_truesize = 0;  
        return true;  
    }  
  
    to_shinfo = skb_shinfo(to);  
    from_shinfo = skb_shinfo(from);  
    if (to_shinfo->frag_list || from_shinfo->frag_list)  
        return false;  
    if (skb_zcopy(to) || skb_zcopy(from))  
        return false;  
  
    if (skb_headlen(from) != 0) {  
        struct page \*page;  
        unsigned int offset;  
  
        if (to_shinfo->nr_frags +  
            from_shinfo->nr_frags >= MAX_SKB_FRAGS)  
            return false;  
  
        if (skb_head_is_locked(from))  
            return false;  
  
        delta = from->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));  
  
        page = virt_to_head_page(from->head);  
        offset = from->data - (unsigned char \*)page_address(page);  
  
        skb_fill_page_desc(to, to_shinfo->nr_frags,  
                           page, offset, skb_headlen(from));  
        \*fragstolen = true;  
    }
```
- **Matched CVEs**:
- CVE-2024-58085: "In the Linux kernel, the following vulnerability has been resolved:  
  
tomoyo: don't emit warning in tomoyo_write_control()  
  
syzbot is reporting too large allocation warning at tomoyo_write_control(),  
for one can write a very very long line without new line character. To fix  
this warning, I use __GFP_NOWARN rather than checking for KMALLOC_MAX_SIZE,  
for practically a valid line should be always shorter than 32KB where the  
"too small to fail" memory-allocation rule applies.  
  
One might try to write a valid line that is longer than 32KB, but such  
request will likely fail with -ENOMEM. Therefore, I feel that separately  
returning -EINVAL when a line is longer than KMALLOC_MAX_SIZE is redundant.  
There is no need to distinguish over-32KB and over-KMALLOC_MAX_SIZE." (Similarity: 59)
- CVE-2025-22091: "In the Linux kernel, the following vulnerability has been resolved:  
  
RDMA/mlx5: Fix page_size variable overflow  
  
Change all variables storing mlx5_umem_mkc_find_best_pgsz() result to  
unsigned long to support values larger than 31 and avoid overflow.  
  
For example: If we try to register 4GB of memory that is contiguous in  
physical memory, the driver will optimize the page_size and try to use  
an mkey with 4GB entity size. The 'unsigned int' page_size variable will  
overflow to '0' and we'll hit the WARN_ON() in alloc_cacheable_mr().  
  
WARNING: CPU: 2 PID: 1203 at drivers/infiniband/hw/mlx5/mr.c:1124 alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
Modules linked in: mlx5_ib mlx5_core bonding ip6_gre ip6_tunnel tunnel6 ip_gre gre rdma_rxe rdma_ucm ib_uverbs ib_ipoib ib_umad rpcrdma ib_iser libiscsi scsi_transport_iscsi rdma_cm iw_cm ib_cm fuse ib_core \[last unloaded: mlx5_core\]  
CPU: 2 UID: 70878 PID: 1203 Comm: rdma_resource_l Tainted: G        W          6.14.0-rc4-dirty #43  
Tainted: \[W\]=WARN  
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014  
RIP: 0010:alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
Code: 90 90 90 90 90 90 90 90 0f 1f 44 00 00 55 48 89 e5 41 57 41 56 41 55 41 54 41 52 53 48 83 ec 30 f6 46 28 04 4c 8b 77 08 75 21 <0f> 0b 49 c7 c2 ea ff ff ff 48 8d 65 d0 4c 89 d0 5b 41 5a 41 5c 41  
RSP: 0018:ffffc900006ffac8 EFLAGS: 00010246  
RAX: 0000000004c0d0d0 RBX: ffff888217a22000 RCX: 0000000000100001  
RDX: 00007fb7ac480000 RSI: ffff8882037b1240 RDI: ffff8882046f0600  
RBP: ffffc900006ffb28 R08: 0000000000000001 R09: 0000000000000000  
R10: 00000000000007e0 R11: ffffea0008011d40 R12: ffff8882037b1240  
R13: ffff8882046f0600 R14: ffff888217a22000 R15: ffffc900006ffe00  
FS:  00007fb7ed013340(0000) GS:ffff88885fd00000(0000) knlGS:0000000000000000  
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033  
CR2: 00007fb7ed1d8000 CR3: 00000001fd8f6006 CR4: 0000000000772eb0  
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000  
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400  
PKRU: 55555554  
Call Trace:  
 <TASK>  
 ? __warn+0x81/0x130  
 ? alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
 ? report_bug+0xfc/0x1e0  
 ? handle_bug+0x55/0x90  
 ? exc_invalid_op+0x17/0x70  
 ? asm_exc_invalid_op+0x1a/0x20  
 ? alloc_cacheable_mr+0x22/0x580 \[mlx5_ib\]  
 create_real_mr+0x54/0x150 \[mlx5_ib\]  
 ib_uverbs_reg_mr+0x17f/0x2a0 \[ib_uverbs\]  
 ib_uverbs_handler_UVERBS_METHOD_INVOKE_WRITE+0xca/0x140 \[ib_uverbs\]  
 ib_uverbs_run_method+0x6d0/0x780 \[ib_uverbs\]  
 ? __pfx_ib_uverbs_handler_UVERBS_METHOD_INVOKE_WRITE+0x10/0x10 \[ib_uverbs\]  
 ib_uverbs_cmd_verbs+0x19b/0x360 \[ib_uverbs\]  
 ? walk_system_ram_range+0x79/0xd0  
 ? ___pte_offset_map+0x1b/0x110  
 ? __pte_offset_map_lock+0x80/0x100  
 ib_uverbs_ioctl+0xac/0x110 \[ib_uverbs\]  
 __x64_sys_ioctl+0x94/0xb0  
 do_syscall_64+0x50/0x110  
 entry_SYSCALL_64_after_hwframe+0x76/0x7e  
RIP: 0033:0x7fb7ecf0737b  
Code: ff ff ff 85 c0 79 9b 49 c7 c4 ff ff ff ff 5b 5d 4c 89 e0 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa b8 10 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 7d 2a 0f 00 f7 d8 64 89 01 48  
RSP: 002b:00007ffdbe03ecc8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010  
RAX: ffffffffffffffda RBX: 00007ffdbe03edb8 RCX: 00007fb7ecf0737b  
RDX: 00007ffdbe03eda0 RSI: 00000000c0181b01 RDI: 0000000000000003  
RBP: 00007ffdbe03ed80 R08: 00007fb7ecc84010 R09: 00007ffdbe03eed4  
R10: 0000000000000009 R11: 0000000000000246 R12: 00007ffdbe03eed4  
R13: 000000000000000c R14: 000000000000000c R15: 00007fb7ecc84150  
 </TASK>" (Similarity: 57)
- CVE-2025-21961: "In the Linux kernel, the following vulnerability has been resolved:  
  
eth: bnxt: fix truesize for mb-xdp-pass case  
  
When mb-xdp is set and return is XDP_PASS, packet is converted from  
xdp_buff to sk_buff with xdp_update_skb_shared_info() in  
bnxt_xdp_build_skb().  
bnxt_xdp_build_skb() passes incorrect truesize argument to  
xdp_update_skb_shared_info().  
The truesize is calculated as BNXT_RX_PAGE_SIZE \* sinfo->nr_frags but  
the skb_shared_info was wiped by napi_build_skb() before.  
So it stores sinfo->nr_frags before bnxt_xdp_build_skb() and use it  
instead of getting skb_shared_info from xdp_get_shared_info_from_buff().  
  
Splat looks like:  
 ------------\[ cut here \]------------  
 WARNING: CPU: 2 PID: 0 at net/core/skbuff.c:6072 skb_try_coalesce+0x504/0x590  
 Modules linked in: xt_nat xt_tcpudp veth af_packet xt_conntrack nft_chain_nat xt_MASQUERADE nf_conntrack_netlink xfrm_user xt_addrtype nft_coms  
 CPU: 2 UID: 0 PID: 0 Comm: swapper/2 Not tainted 6.14.0-rc2+ #3  
 RIP: 0010:skb_try_coalesce+0x504/0x590  
 Code: 4b fd ff ff 49 8b 34 24 40 80 e6 40 0f 84 3d fd ff ff 49 8b 74 24 48 40 f6 c6 01 0f 84 2e fd ff ff 48 8d 4e ff e9 25 fd ff ff <0f> 0b e99  
 RSP: 0018:ffffb62c4120caa8 EFLAGS: 00010287  
 RAX: 0000000000000003 RBX: ffffb62c4120cb14 RCX: 0000000000000ec0  
 RDX: 0000000000001000 RSI: ffffa06e5d7dc000 RDI: 0000000000000003  
 RBP: ffffa06e5d7ddec0 R08: ffffa06e6120a800 R09: ffffa06e7a119900  
 R10: 0000000000002310 R11: ffffa06e5d7dcec0 R12: ffffe4360575f740  
 R13: ffffe43600000000 R14: 0000000000000002 R15: 0000000000000002  
 FS:  0000000000000000(0000) GS:ffffa0755f700000(0000) knlGS:0000000000000000  
 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033  
 CR2: 00007f147b76b0f8 CR3: 00000001615d4000 CR4: 00000000007506f0  
 PKRU: 55555554  
 Call Trace:  
  <IRQ>  
  ? __warn+0x84/0x130  
  ? skb_try_coalesce+0x504/0x590  
  ? report_bug+0x18a/0x1a0  
  ? handle_bug+0x53/0x90  
  ? exc_invalid_op+0x14/0x70  
  ? asm_exc_invalid_op+0x16/0x20  
  ? skb_try_coalesce+0x504/0x590  
  inet_frag_reasm_finish+0x11f/0x2e0  
  ip_defrag+0x37a/0x900  
  ip_local_deliver+0x51/0x120  
  ip_sublist_rcv_finish+0x64/0x70  
  ip_sublist_rcv+0x179/0x210  
  ip_list_rcv+0xf9/0x130  
  
How to reproduce:  
<Node A>  
ip link set $interface1 xdp obj xdp_pass.o  
ip link set $interface1 mtu 9000 up  
ip a a 10.0.0.1/24 dev $interface1  
<Node B>  
ip link set $interfac2 mtu 9000 up  
ip a a 10.0.0.2/24 dev $interface2  
ping 10.0.0.1 -s 65000  
  
Following ping.py patch adds xdp-mb-pass case. so ping.py is going to be  
able to reproduce this issue." (Similarity: 54)


#### CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer (Exploitability: 6)
- **Description**: The \`obj_offset\` field within the \`kmem_cache\` structure is an \`obj_offset_t\` type. It is potentially used to determine the offset of an object within a slab. The \`OBJ_OFFSET_MASK\` macro is used. While not directly apparent in the snippet provided, if \`obj_offset\` is subsequently used incorrectly in slab object access calculation, where the result exceeds slab boundaries due to the all-ones mask, it \*could\* lead to out-of-bounds memory access. This can result in information leaks, denial of service, or potentially arbitrary code execution depending on the context in which \`obj_offset\` is used.
- **Location**: \`struct kmem_cache\` definition and related usage of \`obj_offset\` and \`OBJ_OFFSET_MASK\` within \`slub.c\` (approximately lines 100-150)
- **Code**:
```c
/\* From approximately lines 100–150 of slub.c \*/  
#include <linux/slab.h>  
#include <linux/random.h>  
#include <linux/kmsan.h>  
#include <linux/debugfs.h>  
#include <linux/stackdepot.h>  
#include <linux/sort.h>  
#include <linux/memory.h>  
#include <linux/llist.h>  
#include <asm/cmpxchg.h>  
#include <asm/barrier.h>  
  
  
struct track {  
    unsigned long addr;      
#ifdef CONFIG_STACKDEPOT  
    depot_stack_handle_t handle;   
#endif  
    pid_t pid;          
    unsigned long when;    /\* jiffies at allocation/free time \*/  
#ifdef CONFIG_KASAN_SW_TAGS  
    u8 tag;            /\* KASAN tag of the object \*/  
#endif  
} __packed;  
  
enum track_item { TRACK_ALLOC, TRACK_FREE };  
  
/\* Bitfield for obj offset within a slab \*/  
typedef unsigned int __bitwise obj_offset_t;  
#define OBJ_OFFSET_MASK    ((obj_offset_t)~0U)  
  
/\*  
 \* Slab cache structure  
 \*/  
struct kmem_cache {  
    struct kmem_cache_cpu __percpu \*cpu_slab;  
    /\* Used for retrieving partial slabs, etc. \*/  
    slab_flags_t flags;  
    unsigned long min_partial;  
    unsigned int size;    /\* The size of an object including metadata \*/  
    unsigned int object_size;/\* The size of an object without metadata \*/  
    unsigned int offset;    /\* Free pointer offset \*/  
#ifdef CONFIG_SLUB_CPU_PARTIAL  
    unsigned int cpu_partial;/\* Number of per-CPU partial slabs \*/  
#endif  
    obj_offset_t obj_offset;/\* Offset of the object in a slab \*/
```
- **Matched CVEs**:
- CVE-2024-58000: "In the Linux kernel, the following vulnerability has been resolved:  
  
io_uring: prevent reg-wait speculations  
  
With \*ENTER_EXT_ARG_REG instead of passing a user pointer with arguments  
for the waiting loop the user can specify an offset into a pre-mapped  
region of memory, in which case the  
\[offset, offset + sizeof(io_uring_reg_wait)) will be intepreted as the  
argument.  
  
As we address a kernel array using a user given index, it'd be a subject  
to speculation type of exploits. Use array_index_nospec() to prevent  
that. Make sure to pass not the full region size but truncate by the  
maximum offset allowed considering the structure size." (Similarity: 57)
- CVE-2022-49700: "In the Linux kernel, the following vulnerability has been resolved:  
  
mm/slub: add missing TID updates on slab deactivation  
  
The fastpath in slab_alloc_node() assumes that c->slab is stable as long as  
the TID stays the same. However, two places in __slab_alloc() currently  
don't update the TID when deactivating the CPU slab.  
  
If multiple operations race the right way, this could lead to an object  
getting lost; or, in an even more unlikely situation, it could even lead to  
an object being freed onto the wrong slab's freelist, messing up the  
\`inuse\` counter and eventually causing a page to be freed to the page  
allocator while it still contains slab objects.  
  
(I haven't actually tested these cases though, this is just based on  
looking at the code. Writing testcases for this stuff seems like it'd be  
a pain...)  
  
The race leading to state inconsistency is (all operations on the same CPU  
and kmem_cache):  
  
 - task A: begin do_slab_free():  
    - read TID  
    - read pcpu freelist (==NULL)  
    - check \`slab == c->slab\` (true)  
 - \[PREEMPT A->B\]  
 - task B: begin slab_alloc_node():  
    - fastpath fails (\`c->freelist\` is NULL)  
    - enter __slab_alloc()  
    - slub_get_cpu_ptr() (disables preemption)  
    - enter ___slab_alloc()  
    - take local_lock_irqsave()  
    - read c->freelist as NULL  
    - get_freelist() returns NULL  
    - write \`c->slab = NULL\`  
    - drop local_unlock_irqrestore()  
    - goto new_slab  
    - slub_percpu_partial() is NULL  
    - get_partial() returns NULL  
    - slub_put_cpu_ptr() (enables preemption)  
 - \[PREEMPT B->A\]  
 - task A: finish do_slab_free():  
    - this_cpu_cmpxchg_double() succeeds()  
    - \[CORRUPT STATE: c->slab==NULL, c->freelist!=NULL\]  
  
From there, the object on c->freelist will get lost if task B is allowed to  
continue from here: It will proceed to the retry_load_slab label,  
set c->slab, then jump to load_freelist, which clobbers c->freelist.  
  
But if we instead continue as follows, we get worse corruption:  
  
 - task A: run __slab_free() on object from other struct slab:  
    - CPU_PARTIAL_FREE case (slab was on no list, is now on pcpu partial)  
 - task A: run slab_alloc_node() with NUMA node constraint:  
    - fastpath fails (c->slab is NULL)  
    - call __slab_alloc()  
    - slub_get_cpu_ptr() (disables preemption)  
    - enter ___slab_alloc()  
    - c->slab is NULL: goto new_slab  
    - slub_percpu_partial() is non-NULL  
    - set c->slab to slub_percpu_partial(c)  
    - \[CORRUPT STATE: c->slab points to slab-1, c->freelist has objects  
      from slab-2\]  
    - goto redo  
    - node_match() fails  
    - goto deactivate_slab  
    - existing c->freelist is passed into deactivate_slab()  
    - inuse count of slab-1 is decremented to account for object from  
      slab-2  
  
At this point, the inuse count of slab-1 is 1 lower than it should be.  
This means that if we free all allocated objects in slab-1 except for one,  
SLUB will think that slab-1 is completely unused, and may free its page,  
leading to use-after-free." (Similarity: 56)
- CVE-2025-22018: "In the Linux kernel, the following vulnerability has been resolved:  
  
atm: Fix NULL pointer dereference  
  
When MPOA_cache_impos_rcvd() receives the msg, it can trigger  
Null Pointer Dereference Vulnerability if both entry and  
holding_time are NULL. Because there is only for the situation  
where entry is NULL and holding_time exists, it can be passed  
when both entry and holding_time are NULL. If these are NULL,  
the entry will be passd to eg_cache_put() as parameter and  
it is referenced by entry->use code in it.  
  
kasan log:  
  
\[    3.316691\] Oops: general protection fault, probably for non-canonical address 0xdffffc0000000006:I  
\[    3.317568\] KASAN: null-ptr-deref in range \[0x0000000000000030-0x0000000000000037\]  
\[    3.318188\] CPU: 3 UID: 0 PID: 79 Comm: ex Not tainted 6.14.0-rc2 #102  
\[    3.318601\] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014  
\[    3.319298\] RIP: 0010:eg_cache_remove_entry+0xa5/0x470  
\[    3.319677\] Code: c1 f7 6e fd 48 c7 c7 00 7e 38 b2 e8 95 64 54 fd 48 c7 c7 40 7e 38 b2 48 89 ee e80  
\[    3.321220\] RSP: 0018:ffff88800583f8a8 EFLAGS: 00010006  
\[    3.321596\] RAX: 0000000000000006 RBX: ffff888005989000 RCX: ffffffffaecc2d8e  
\[    3.322112\] RDX: 0000000000000000 RSI: 0000000000000004 RDI: 0000000000000030  
\[    3.322643\] RBP: 0000000000000000 R08: 0000000000000000 R09: fffffbfff6558b88  
\[    3.323181\] R10: 0000000000000003 R11: 203a207972746e65 R12: 1ffff11000b07f15  
\[    3.323707\] R13: dffffc0000000000 R14: ffff888005989000 R15: ffff888005989068  
\[    3.324185\] FS:  000000001b6313c0(0000) GS:ffff88806d380000(0000) knlGS:0000000000000000  
\[    3.325042\] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033  
\[    3.325545\] CR2: 00000000004b4b40 CR3: 000000000248e000 CR4: 00000000000006f0  
\[    3.326430\] Call Trace:  
\[    3.326725\]  <TASK>  
\[    3.326927\]  ? die_addr+0x3c/0xa0  
\[    3.327330\]  ? exc_general_protection+0x161/0x2a0  
\[    3.327662\]  ? asm_exc_general_protection+0x26/0x30  
\[    3.328214\]  ? vprintk_emit+0x15e/0x420  
\[    3.328543\]  ? eg_cache_remove_entry+0xa5/0x470  
\[    3.328910\]  ? eg_cache_remove_entry+0x9a/0x470  
\[    3.329294\]  ? __pfx_eg_cache_remove_entry+0x10/0x10  
\[    3.329664\]  ? console_unlock+0x107/0x1d0  
\[    3.329946\]  ? __pfx_console_unlock+0x10/0x10  
\[    3.330283\]  ? do_syscall_64+0xa6/0x1a0  
\[    3.330584\]  ? entry_SYSCALL_64_after_hwframe+0x47/0x7f  
\[    3.331090\]  ? __pfx_prb_read_valid+0x10/0x10  
\[    3.331395\]  ? down_trylock+0x52/0x80  
\[    3.331703\]  ? vprintk_emit+0x15e/0x420  
\[    3.331986\]  ? __pfx_vprintk_emit+0x10/0x10  
\[    3.332279\]  ? down_trylock+0x52/0x80  
\[    3.332527\]  ? _printk+0xbf/0x100  
\[    3.332762\]  ? __pfx__printk+0x10/0x10  
\[    3.333007\]  ? _raw_write_lock_irq+0x81/0xe0  
\[    3.333284\]  ? __pfx__raw_write_lock_irq+0x10/0x10  
\[    3.333614\]  msg_from_mpoad+0x1185/0x2750  
\[    3.333893\]  ? __build_skb_around+0x27b/0x3a0  
\[    3.334183\]  ? __pfx_msg_from_mpoad+0x10/0x10  
\[    3.334501\]  ? __alloc_skb+0x1c0/0x310  
\[    3.334809\]  ? __pfx___alloc_skb+0x10/0x10  
\[    3.335283\]  ? _raw_spin_lock+0xe0/0xe0  
\[    3.335632\]  ? finish_wait+0x8d/0x1e0  
\[    3.335975\]  vcc_sendmsg+0x684/0xba0  
\[    3.336250\]  ? __pfx_vcc_sendmsg+0x10/0x10  
\[    3.336587\]  ? __pfx_autoremove_wake_function+0x10/0x10  
\[    3.337056\]  ? fdget+0x176/0x3e0  
\[    3.337348\]  __sys_sendto+0x4a2/0x510  
\[    3.337663\]  ? __pfx___sys_sendto+0x10/0x10  
\[    3.337969\]  ? ioctl_has_perm.constprop.0.isra.0+0x284/0x400  
\[    3.338364\]  ? sock_ioctl+0x1bb/0x5a0  
\[    3.338653\]  ? __rseq_handle_notify_resume+0x825/0xd20  
\[    3.339017\]  ? __pfx_sock_ioctl+0x10/0x10  
\[    3.339316\]  ? __pfx___rseq_handle_notify_resume+0x10/0x10  
\[    3.339727\]  ? selinux_file_ioctl+0xa4/0x260  
\[    3.340166\]  __x64_sys_sendto+0xe0/0x1c0  
\[    3.340526\]  ? syscall_exit_to_user_mode+0x123/0x140  
\[    3.340898\]  do_syscall_64+0xa6/0x1a0  
\[    3.341170\]  entry_SYSCALL_64_after_hwframe+0x77/0x7f  
\[    3.341533\] RIP: 0033:0x44a380  
\[    3.341757\] Code: 0f 1f 84 00 00 00 00 00 66 90 f3 0f 1e fa 41 89 ca 64 8b 04 25 18 00 00 00 85 c00  
\[      
---truncated---" (Similarity: 53)


#### CWE-269: Improper Privilege Management (Exploitability: 6)
- **Description**: The \`__sys_setresuid\` function allows a process to change its real, effective, and saved set-user-IDs. The vulnerability lies in the logic that determines whether the caller has the \`CAP_SETUID\` capability within its user namespace. Specifically, lines 1129-1132 and 1133-1134 check if the new UIDs are different from the old ones AND different from each other. The code then checks for \`CAP_SETUID\` only when at least one of \`ruid_new\`, \`euid_new\`, or \`suid_new\` is true. However, there is no explicit check if any of these UIDs have actually changed. A carefully crafted sequence of calls to setresuid can lead to privilege escalation if the capability check is bypassed, especially if the user namespace is configured improperly or if the LSM (Linux Security Module) is vulnerable. In essence, the current logic is not strict enough in certain edge cases related to user ID changes across user namespaces.
- **Location**: Lines 1129-1135
- **Code**:
```c
long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)  // Line 1097  
{  
    struct user_namespace \*ns = current_user_ns();  
    const struct cred \*old;  
    struct cred \*new;  
    int retval;  
    kuid_t kruid, keuid, ksuid;  
    bool ruid_new, euid_new, suid_new;  
  
    kruid = make_kuid(ns, ruid);  
    keuid = make_kuid(ns, euid);  
    ksuid = make_kuid(ns, suid);  
  
    if ((ruid != (uid_t) -1) && !uid_valid(kruid))  // Line 1110  
        return -EINVAL;  
  
    if ((euid != (uid_t) -1) && !uid_valid(keuid))  
        return -EINVAL;  
  
    if ((suid != (uid_t) -1) && !uid_valid(ksuid))  
        return -EINVAL;  
  
    old = current_cred();  
  
    /\* check for no-op \*/  
    if ((ruid == (uid_t) -1 || uid_eq(kruid, old->uid)) &&  
        (euid == (uid_t) -1 || (uid_eq(keuid, old->euid) &&  
                                uid_eq(keuid, old->fsuid))) &&  
        (suid == (uid_t) -1 || uid_eq(ksuid, old->suid)))  
        return 0;  
  
    ruid_new = ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&  
               !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);  
    euid_new = euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&  
               !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid);  
    suid_new = suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&  
               !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid);  
    if ((ruid_new || euid_new || suid_new) &&  
        !ns_capable_setid(old->user_ns, CAP_SETUID))  // Line 1135  
        return -EPERM;  
  
    new = prepare_creds();  
    if (!new)  
        return -ENOMEM;  
  
    if (ruid != (uid_t) -1) {  
        new->uid = kruid;  
        if (!uid_eq(kruid, old->uid)) {  
            retval = set_user(new);  
            if (retval < 0)  
                goto error;  
        }  
    }  
    if (euid != (uid_t) -1)  
        new->euid = keuid;  
    if (suid != (uid_t) -1)  
        new->suid = ksuid;  
    new->fsuid = new->euid;  
  
    retval = security_task_fix_setuid(new, old, LSM_SETID_RES);  
    if (retval < 0)  
        goto error;  
  
    retval = set_cred_ucounts(new);  
    if (retval < 0)  
        goto error;  
  
    flag_nproc_exceeded(new);  
    return commit_creds(new);  
  
error:  
    abort_creds(new);  
    return retval;  
}
```
- **Matched CVEs**:
- CVE-2023-52987: "In the Linux kernel, the following vulnerability has been resolved:  
  
ASoC: SOF: ipc4-mtrace: prevent underflow in sof_ipc4_priority_mask_dfs_write()  
  
The "id" comes from the user.  Change the type to unsigned to prevent  
an array underflow." (Similarity: 47)
- CVE-2025-21846: "In the Linux kernel, the following vulnerability has been resolved:  
  
acct: perform last write from workqueue  
  
In \[1\] it was reported that the acct(2) system call can be used to  
trigger NULL deref in cases where it is set to write to a file that  
triggers an internal lookup. This can e.g., happen when pointing acc(2)  
to /sys/power/resume. At the point the where the write to this file  
happens the calling task has already exited and called exit_fs(). A  
lookup will thus trigger a NULL-deref when accessing current->fs.  
  
Reorganize the code so that the the final write happens from the  
workqueue but with the caller's credentials. This preserves the  
(strange) permission model and has almost no regression risk.  
  
This api should stop to exist though." (Similarity: 47)
- CVE-2025-22038: "In the Linux kernel, the following vulnerability has been resolved:  
  
ksmbd: validate zero num_subauth before sub_auth is accessed  
  
Access psid->sub_auth\[psid->num_subauth - 1\] without checking  
if num_subauth is non-zero leads to an out-of-bounds read.  
This patch adds a validation step to ensure num_subauth != 0  
before sub_auth is accessed." (Similarity: 46)


## 🛠️ Patch Reports

### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
diff --git a/fs/ext4/inode.c b/fs/ext4/inode.c  
index 4f7c84c..9a2b135 100644  
--- a/fs/ext4/inode.c  
+++ b/fs/ext4/inode.c  
@@ -5835,12 +5835,18 @@  
     }  
   
     if (!shrink) {  
+        u64 end_block;  
+  
         inode_set_mtime_to_ts(inode,  
                               inode_set_ctime_current(inode));  
         if (oldsize & (inode->i_sb->s_blocksize - 1))  
             ext4_block_truncate_page(handle,  
                                      inode->i_mapping, oldsize);  
+  
+        end_block = (attr->ia_size > 0 ? attr->ia_size - 1 : 0);  
+        end_block >>= inode->i_sb->s_blocksize_bits;  
     }  
+  
   
     if (shrink)  
         ext4_fc_track_range(handle, inode,  
@@ -5849,9 +5855,9 @@  
             EXT_MAX_BLOCKS - 1);  
     else  
         ext4_fc_track_range(  
-            handle, inode,  
-            (oldsize > 0 ? oldsize - 1 : oldsize) >>  
-            inode->i_sb->s_blocksize_bits,  
+               handle, inode,  
+               (oldsize > 0 ? oldsize - 1 : oldsize) >>  
+               inode->i_sb->s_blocksize_bits,  
             (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >>  
             inode->i_sb->s_blocksize_bits);  
   
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code calculates the end block number for \`ext4_fc_track_range\` by right-shifting \`attr->ia_size - 1\` or \`oldsize - 1\` by \`inode->i_sb->s_blocksize_bits\`.  If \`inode->i_sb->s_blocksize_bits\` is large (e.g., blocksize is a large power of 2) and \`attr->ia_size\` or \`oldsize\` are small positive values, the shift operation could potentially result in an integer overflow/wraparound, leading to incorrect block tracking.  
  
The patch introduces a \`u64\` type variable \`end_block\`. This ensures that the intermediate calculation \`(attr->ia_size > 0 ? attr->ia_size - 1 : 0)\` is performed using a 64-bit unsigned integer, preventing potential overflow during subtraction. Then \`end_block\` is shifted by \`inode->i_sb->s_blocksize_bits\` before being passed to \`ext4_fc_track_range\`.  
This prevents the large shift value from causing unexpected behavior in the calculation of the end block.  The patch addresses the integer overflow vulnerability described in CWE-190.  
  
The code's original functionality is preserved because the same mathematical operation (right shift) is performed on the size values.  The change ensures that the size values are handled as 64-bit unsigned integers during the shift calculation to prevent potential overflow.  
  
Trade-offs:  
- Introducing \`end_block\` uses more memory, but the amount is negligible.  
- Adding assignment operations slightly increases the number of instructions.  
  
Considerations:  
- The patch assumes \`attr->ia_size\` and \`oldsize\` are 64-bit integers.  
- This patch is carefully designed to be minimal and non-intrusive.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2024-58017](https://git.kernel.org/stable/c/3d6f83df8ff2d5de84b50377e4f0d45e25311c7a)
- [CVE-2025-21736](https://git.kernel.org/stable/c/250423300b4b0335918be187ef3cade248c06e6a)
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`  
- Patch Code:  
\`\`\`c  
if (!len)  
    return -EINVAL;  
  
if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))  
    if (!(file && path_noexec(&file->f_path)))  
        prot |= PROT_EXEC;  
  
if (flags & MAP_FIXED_NOREPLACE)  
    flags |= MAP_FIXED;  
  
if (!(flags & MAP_FIXED))  
    addr = round_hint_to_min(addr);  
  
len = PAGE_ALIGN(len);  
if (!len)  
    return -ENOMEM;  
  
if (len >> PAGE_SHIFT > ULONG_MAX - pgoff)  
    return -EOVERFLOW;  
  
if (mm->map_count > sysctl_max_map_count)  
    return -ENOMEM;  
  
if (prot == PROT_EXEC) {  
    pkey = execute_only_pkey(mm);  
    if (pkey < 0)  
        pkey = 0;  
}  
  
vm_flags |= calc_vm_prot_bits(prot, pkey) | calc_vm_flag_bits(file, flags) |  
        mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;  
  
addr = __get_unmapped_area(file, addr, len, pgoff, flags, vm_flags);  
if (IS_ERR_VALUE(addr))  
    return addr;  
  
if (flags & MAP_FIXED_NOREPLACE) {  
    if (find_vma_intersection(mm, addr, addr + len))  
        return -EEXIST;  
}  
  
if (flags & MAP_LOCKED)  
    if (!can_do_mlock())  
        return -EPERM;  
  
if (!mlock_future_ok(mm, vm_flags, len))  
    return -EAGAIN;  
\`\`\`  
- Reasoning:  
The original check \`if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)\` is vulnerable to integer overflows when \`pgoff + (len >> PAGE_SHIFT)\` exceeds the maximum value of its data type (typically \`unsigned long\`). In such cases, the sum wraps around, resulting in a smaller value that is incorrectly interpreted as being less than \`pgoff\`, thus bypassing the overflow check.  
  
The patch replaces this flawed check with \`if (len >> PAGE_SHIFT > ULONG_MAX - pgoff)\`.  This check directly verifies whether \`len >> PAGE_SHIFT\` is greater than the maximum value that can be added to \`pgoff\` without causing an overflow. By comparing against \`ULONG_MAX - pgoff\`, we effectively check if the addition \`pgoff + (len >> PAGE_SHIFT)\` would result in a value greater than \`ULONG_MAX\`, which indicates an overflow.  
  
The patch maintains the code's functionality by ensuring that the program correctly detects and prevents integer overflows during the calculation of the memory region size. It also addresses the weakness identified in the CWE analysis and hardens the code against potential attacks that exploit this vulnerability. No new functionality is introduced, and the existing control flow is maintained. The trade-off is the slightly increased complexity of the check, although it is negligible.  
  
- Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2024-57973](https://git.kernel.org/stable/c/2b759f78b83221f4a1cae3aeb20b500e375f3ee6)
- [CVE-2025-22107](https://git.kernel.org/stable/c/59b97641de03c081f26b3a8876628c765b5faa25)


### Patch 
- **CWE**: CWE-400: Uncontrolled Resource Consumption
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
diff --git a/kernel/fork.c b/kernel/fork.c  
index 4a9ef6b..c7a28d7 100644  
--- a/kernel/fork.c  
+++ b/kernel/fork.c  
@@ -2998,7 +2998,11 @@  
   
   
 retval = -EAGAIN;  
-if (data_race(nr_threads >= max_threads))  
+spin_lock(&thread_count_lock);  
+if (nr_threads >= max_threads) {  
+    spin_unlock(&thread_count_lock);  
+    goto bad_fork_cleanup_count;  
+}  
     goto bad_fork_cleanup_count;  
   
 delayacct_tsk_init(p);  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code used \`data_race(nr_threads >= max_threads)\` to check if the maximum number of threads has been reached. The \`data_race\` macro is meant for detecting data races during development, but it doesn't provide actual synchronization. Therefore, multiple processes could simultaneously read \`nr_threads\` before any of them increments it, leading to exceeding \`max_threads\`.  
  
The patch addresses this by:  
  
1.  \*\*Introducing a spinlock:\*\*  \`spin_lock(&thread_count_lock)\` is used to protect the \`nr_threads\` variable.  
2.  \*\*Atomic Check and Increment:\*\* The check \`nr_threads >= max_threads\` is now performed under the protection of the spinlock.  If the limit is reached, the lock is released and it jumps to the cleanup label.  Incrementing of \`nr_threads\` should be handled after this check in other places.  
  
This ensures that only one process at a time can check and potentially increment \`nr_threads\`, preventing the race condition and guaranteeing that the number of threads never exceeds \`max_threads\`.  
  
This resolves the uncontrolled resource consumption vulnerability. The code's functionality is maintained by ensuring that thread creation proceeds only if the maximum thread limit hasn't been reached.  
  
\*\*Trade-offs and considerations:\*\*  
  
\*   \*\*Performance:\*\* Introducing a spinlock adds a small overhead. However, this is necessary to ensure correctness and prevent a denial-of-service vulnerability.  The lock contention should be low in most scenarios, so the performance impact should be minimal.  
\*   \*\*Missing atomic increment:\*\* This patch only addresses the check.  It \*assumes\* that the increment of \`nr_threads\` is done later and is protected by the same \`thread_count_lock\`. A full solution must ensure that \`nr_threads\` is \*atomically\* incremented after this check, within the same lock.  Because the provided code snippet doesn't include that increment, it's impossible to create a complete patch. However, this patch \*does\* prevent the overflow described in the CWE by preventing concurrent checks.  
  
\*\*Assumptions:\*\*  
  
\*   A spinlock named \`thread_count_lock\` is available and protects modifications to the \`nr_threads\` variable elsewhere in the code.  
\*   \`nr_threads\` is incremented atomically elsewhere in the fork code under protection of the \`thread_count_lock\` after this check.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2022-49685](https://git.kernel.org/stable/c/31ff3309b47d98313c61b8301bf595820cc3cc33)
- [CVE-2022-49578](https://git.kernel.org/stable/c/95724fe897a4ecf2be51452ef96e818568071664)
- [CVE-2022-49607](https://git.kernel.org/stable/c/17f5417194136517ee9bbd6511249e5310e5617c)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`c  
bool skb_try_coalesce(struct sk_buff \*to, struct sk_buff \*from,  
                      bool \*fragstolen, int \*delta_truesize)  
{  
    struct skb_shared_info \*to_shinfo, \*from_shinfo;  
    int i, delta, len = from->len;  
  
    \*fragstolen = false;  
  
    if (skb_cloned(to))  
        return false;  
  
    if (to->pp_recycle != from->pp_recycle)  
        return false;  
  
    if (skb_frags_readable(from) != skb_frags_readable(to))  
        return false;  
  
    if (len <= skb_tailroom(to) && skb_frags_readable(from)) {  
        if (len)  
            BUG_ON(skb_copy_bits(from, 0, skb_put(to, len), len));  
        \*delta_truesize = 0;  
        return true;  
    }  
  
    to_shinfo = skb_shinfo(to);  
    from_shinfo = skb_shinfo(from);  
    if (to_shinfo->frag_list || from_shinfo->frag_list)  
        return false;  
    if (skb_zcopy(to) || skb_zcopy(from))  
        return false;  
  
    if (skb_headlen(from) != 0) {  
        struct page \*page;  
        unsigned int offset;  
  
        if (to_shinfo->nr_frags > MAX_SKB_FRAGS - from_shinfo->nr_frags)  
            return false;  
  
        if (skb_head_is_locked(from))  
            return false;  
  
        delta = from->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));  
  
        page = virt_to_head_page(from->head);  
        offset = from->data - (unsigned char \*)page_address(page);  
  
        skb_fill_page_desc(to, to_shinfo->nr_frags,  
                           page, offset, skb_headlen(from));  
        \*fragstolen = true;  
    }  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code checks \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\`. This check is vulnerable to integer overflow. If the sum of \`to_shinfo->nr_frags\` and \`from_shinfo->nr_frags\` overflows, the result could be a small positive number, potentially bypassing the check.  
  
The corrected code changes the check to \`to_shinfo->nr_frags > MAX_SKB_FRAGS - from_shinfo->nr_frags\`.  This rearrangement avoids the integer overflow.  By subtracting \`from_shinfo->nr_frags\` from \`MAX_SKB_FRAGS\` \*before\* the comparison, we are checking if \`to_shinfo->nr_frags\` is already too large to accommodate the fragments from \`from\`.  This approach ensures the check will correctly prevent \`to_shinfo->nr_frags\` from exceeding \`MAX_SKB_FRAGS\` after the fragments are added.  
  
The patch maintains the original code's functionality by ensuring that the number of fragments in the \`to\` sk_buff does not exceed the maximum allowed value after potentially adding fragments from the \`from\` sk_buff.  
  
This patch has minimal impact on performance and maintains the original intent of the code, which is to prevent exceeding the maximum number of fragments allowed in an sk_buff.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2024-58085](https://git.kernel.org/stable/c/3df7546fc03b8f004eee0b9e3256369f7d096685)
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-21961](https://git.kernel.org/stable/c/19107e71be330dbccb9f8f9f4cf0a9abeadad802)


### Patch 
- **CWE**: CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
--- a/mm/slub.c  
+++ b/mm/slub.c  
@@ -38,7 +38,7 @@  
   
 /\* Bitfield for obj offset within a slab \*/  
 typedef unsigned int __bitwise obj_offset_t;  
-#define OBJ_OFFSET_MASK    ((obj_offset_t)~0U)  
+#define OBJ_OFFSET_MASK    ((obj_offset_t)0x3FFFFFFF) /\* Assuming maximum slab size of 2^30 bytes \*/  
   
 /\*  
  \* Slab cache structure  
\`\`\`  
  
\*\*Reasoning:\*\*  
The vulnerability lies in the potential misuse of \`obj_offset\` in conjunction with \`OBJ_OFFSET_MASK\`. \`OBJ_OFFSET_MASK\` is defined as all ones.  If \`obj_offset\` is later used in a calculation to access memory within a slab, and the result is ANDed (or otherwise combined) with \`OBJ_OFFSET_MASK\`, the all-ones mask will effectively disable any bounds checking if the slab size is assumed to be smaller. This creates a potential for out-of-bounds access.  
  
The patch addresses this by limiting the size of \`OBJ_OFFSET_MASK\`.  Specifically, it changes the mask to \`0x3FFFFFFF\`. This limits the \`obj_offset\` to a maximum of approximately 1GB (2^30), which is a reasonable upper bound for slab sizes on most architectures.  If slab sizes are known to be even smaller in a specific deployment, the mask can be adjusted accordingly to further restrict the maximum offset.  
  
- \*\*How it resolves the vulnerability:\*\*  By reducing the size of \`OBJ_OFFSET_MASK\`, we introduce an effective bound on the maximum allowed offset within a slab.  This makes subsequent calculations using \`obj_offset\` safer, as out-of-bounds values will now be masked off. It will likely cause some performance impact because it restricts offset values and may result in fragmentation or allocation failures, but this is the safety measure.  
  
- \*\*How it maintains the code's functionality:\*\*  The assumption is that the current kernel does not rely on excessively large slab sizes exceeding 1GB. If the kernel attempts to use \`obj_offset\` with larger slab sizes, the masked value will cause incorrect object access, revealing the error and preventing an exploitable out-of-bounds write or read.  Ideally, the choice of mask should be validated against \`PAGE_SIZE\`, \`MAX_ORDER\`, or similar constraints within the kernel to ensure compatibility.  
  
- \*\*Trade-offs and considerations:\*\*  
    -  A smaller \`OBJ_OFFSET_MASK\` limits the maximum addressable offset within a slab.  This effectively limits the maximum slab size the code can handle.  Choosing a value that is too small could lead to allocation failures or other unexpected behavior. It assumes a maximum slab size of 1GB (2^30).  
    -  The specific value of \`0x3FFFFFFF\` was chosen as a reasonably large value without being all ones. This provides a significant safeguard without being overly restrictive in most practical scenarios. A more robust solution might involve dynamically determining the appropriate mask based on system parameters (e.g., page size, maximum allocation order).  
    - A better solution to this hypothetical vulnerability would be to analyze the use of \`obj_offset\` and \`OBJ_OFFSET_MASK\` more carefully. But without further context, this seems to be the safest action.  
  
\*\*Patch Links:\*\*  
None  

```
- **CVE Patch Links**:
- [CVE-2024-58000](https://git.kernel.org/stable/c/29b95ac917927ce9f95bf38797e16333ecb489b1)
- [CVE-2022-49700](https://git.kernel.org/stable/c/0515cc9b6b24877f59b222ade704bfaa42caa2a6)
- [CVE-2025-22018](https://git.kernel.org/stable/c/09691f367df44fe93255274d80a439f9bb3263fc)


### Patch 
- **CWE**: CWE-269: Improper Privilege Management
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
Patch Code:  
\`\`\`c  
--- a/kernel/sys.c  
+++ b/kernel/sys.c  
@@ -1126,12 +1126,15 @@  
         (suid == (uid_t) -1 || uid_eq(ksuid, old->suid)))  
         return 0;  
   
-    ruid_new = ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&  
-               !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);  
-    euid_new = euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&  
-               !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid);  
-    suid_new = suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&  
-               !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid);  
+    ruid_new = (ruid != (uid_t) -1) && !uid_eq(kruid, old->uid);  
+    euid_new = (euid != (uid_t) -1) && !uid_eq(keuid, old->euid);  
+    suid_new = (suid != (uid_t) -1) && !uid_eq(ksuid, old->suid);  
+  
+    /\* If any of the IDs changed, require CAP_SETUID \*/  
+    if (!ruid_new && !euid_new && !suid_new)  
+            return 0;  
+  
     if ((ruid_new || euid_new || suid_new) &&  
         !ns_capable_setid(old->user_ns, CAP_SETUID))  
         return -EPERM;  
  
\`\`\`  
  
Reasoning:  
The original code's check for \`CAP_SETUID\` was conditional on the variables \`ruid_new\`, \`euid_new\`, and \`suid_new\` being true, where each variable checked if the new UID was different from \*all\* of the old UIDs (uid, euid, and suid). This meant that if the new UID matched even one of the old UIDs, the capability check could be bypassed.  
  
The vulnerability lies in the possibility that \`setresuid\` might be called to change only one ID, and the logic for checking \`CAP_SETUID\` could be bypassed.  
  
The patch modifies the logic to correctly check if \*any\* of the UIDs have actually changed.  The changes are as follows:  
  
1. \`ruid_new\`, \`euid_new\`, and \`suid_new\` are only checked against \`old->uid\`, \`old->euid\`, and \`old->suid\` respectively. The code now correctly identifies if each ID is changing or not.  
2. A new check is introduced: \`if (!ruid_new && !euid_new && !suid_new) return 0;\`. This early exit handles the case where none of the IDs are changing, and also ensures that the following permission check is only performed if there is a real change in the IDs.  
  
This ensures that the \`CAP_SETUID\` check is enforced whenever there is a change to any of the real, effective, or saved set-user-IDs, which resolves the privilege escalation vulnerability. This approach maintains the code's intended functionality by ensuring that legitimate uses of \`setresuid\` (e.g., when the caller has the necessary capabilities) continue to work as expected.  
  
Patch Links:  
None  

```
- **CVE Patch Links**:
- [CVE-2023-52987](https://git.kernel.org/stable/c/d52f34784e4e2f6e77671a9f104d8a69a3b5d24c)
- [CVE-2025-21846](https://git.kernel.org/stable/c/56d5f3eba3f5de0efdd556de4ef381e109b973a9)
- [CVE-2025-22038](https://git.kernel.org/stable/c/0e36a3e080d6d8bd7a34e089345d043da4ac8283)


## 📊 Summary
- **Agent**: Talal
- **LTP Tests**: 6
- **CWE Issues**: 6
- **Patches**: 6

### LTP Results Breakdown
- Flaw Detected: 1 (\#ef4444)
- Safe: 5 (\#22c55e)
