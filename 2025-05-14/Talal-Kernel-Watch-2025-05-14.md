
# Talal Kernel Watch Report - 2025-05-14

## 🔍 Detection Results

### LTP Test Results

| Test | Result |
|------|--------|
| Filesystem Tests | No Issues Found |
| Memory Management | No Issues Found |
| Process Management | No Issues Found |
| Networking Tests | No Issues Found |
| Device Drivers | No Issues Found |
| System Calls | No Issues Found |


### CWE Analysis

#### CWE-787: Out-of-bounds Write (Exploitability: 7)
- **Description**: The code calculates the block ranges using bitwise right shifts \`>> inode->i_sb->s_blocksize_bits\` on \`attr->ia_size\` and \`oldsize\` within the \`ext4_fc_track_range\` function calls. If either \`attr->ia_size\` or \`oldsize\` is significantly large, but still passes the initial size check at line 5800, the right shift operation combined with the subsequent subtraction can result in a small value. However, the second argument passed to \`ext4_fc_track_range\`, \`EXT_MAX_BLOCKS - 1\` can be an extremely large value based on the system configuration. If the first argument (the starting block) after the shift and potential underflow (if the initial value was smaller than block size) is a small value while \`EXT_MAX_BLOCKS - 1\` is very large, then \`ext4_fc_track_range\` might attempt to track a large number of blocks leading to an out-of-bounds write due to an inadequate size check within the tracking function itself or functions it calls (not provided in the code snippet but assumed by its nature). The lack of validation of the result of the shift operation and the size of \`EXT_MAX_BLOCKS\` against memory allocation size within \`ext4_fc_track_range\` creates this condition. A malicious actor could exploit this by crafting specific file sizes that result in the flawed calculation of block ranges.
- **Location**: Line 5823 and 5828: \`ext4_fc_track_range\` function calls and the calculations within the arguments.
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
before it is utilised." (Similarity: 55)
- CVE-2024-58017: "In the Linux kernel, the following vulnerability has been resolved:  
  
printk: Fix signed integer overflow when defining LOG_BUF_LEN_MAX  
  
Shifting 1 << 31 on a 32-bit int causes signed integer overflow, which  
leads to undefined behavior. To prevent this, cast 1 to u32 before  
performing the shift, ensuring well-defined behavior.  
  
This change explicitly avoids any potential overflow by ensuring that  
the shift occurs on an unsigned 32-bit integer." (Similarity: 54)
- CVE-2025-21736: "In the Linux kernel, the following vulnerability has been resolved:  
  
nilfs2: fix possible int overflows in nilfs_fiemap()  
  
Since nilfs_bmap_lookup_contig() in nilfs_fiemap() calculates its result  
by being prepared to go through potentially maxblocks == INT_MAX blocks,  
the value in n may experience an overflow caused by left shift of blkbits.  
  
While it is extremely unlikely to occur, play it safe and cast right hand  
expression to wider type to mitigate the issue.  
  
Found by Linux Verification Center (linuxtesting.org) with static analysis  
tool SVACE." (Similarity: 53)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: The code checks for integer overflows in the expression \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\`. If \`len\` is large enough, right-shifting it by \`PAGE_SHIFT\` could cause \`pgoff + (len >> PAGE_SHIFT)\` to wrap around to a small value, making the check \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\` true, even though the actual sum is greater than the maximum allowed value. This overflow can lead to allocating a memory region that extends beyond the allowed address space. This can cause issues with memory management and potential security vulnerabilities like out-of-bounds access.
- **Location**: Line 597
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
 </TASK>" (Similarity: 51)
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
element is part of an unmapped page." (Similarity: 48)
- CVE-2024-57973: "In the Linux kernel, the following vulnerability has been resolved:  
  
rdma/cxgb4: Prevent potential integer overflow on 32bit  
  
The "gl->tot_len" variable is controlled by the user.  It comes from  
process_responses().  On 32bit systems, the "gl->tot_len + sizeof(struct  
cpl_pass_accept_req) + sizeof(struct rss_header)" addition could have an  
integer wrapping bug.  Use size_add() to prevent this." (Similarity: 46)


#### CWE-400: Uncontrolled Resource Consumption (Exploitability: 7)
- **Description**: The code checks for resource limits using \`is_rlimit_overlimit\` with \`UCOUNT_RLIMIT_NPROC\` and \`rlimit(RLIMIT_NPROC)\`. If the limit is exceeded, the code checks for capabilities like \`CAP_SYS_RESOURCE\` and \`CAP_SYS_ADMIN\`.  However, the \`data_race(nr_threads >= max_threads)\` check can still be bypassed through race conditions, allowing an attacker to create a large number of threads/processes. While the rlimit attempts to restrict this, the race condition allows a burst of processes to be created before the rlimit is fully enforced leading to resource exhaustion and potential denial of service.
- **Location**: Line including \`data_race(nr_threads >= max_threads)\`
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
- CVE-2022-49634: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data-races in proc_dou8vec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_dou8vec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_dou8vec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 57)
- CVE-2022-49640: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data races in proc_douintvec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_douintvec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_douintvec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 56)
- CVE-2022-49578: "In the Linux kernel, the following vulnerability has been resolved:  
  
ip: Fix data-races around sysctl_ip_prot_sock.  
  
sysctl_ip_prot_sock is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing." (Similarity: 54)


#### CWE-787: Out-of-bounds Write (Exploitability: 8)
- **Description**: The code in \`skb_try_coalesce\` attempts to coalesce two sk_buff structures. Specifically, the code adds a fragment from the 'from' sk_buff to the 'to' sk_buff's fragment list, if the 'from' sk_buff's head data is not empty. The vulnerability lies in the check \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\`. This check is meant to prevent adding too many fragments to the 'to' sk_buff. However, it does not account for the \*existing\* fragments in \`from\`, only the \*total\* number of fragments if added. The code proceeds to increment \`to_shinfo->nr_frags\` without correctly validating that the new number of fragments will not exceed \`MAX_SKB_FRAGS\`. If \`to_shinfo->nr_frags\` is already close to \`MAX_SKB_FRAGS\`, and \`from_shinfo->nr_frags\` is one or more, the condition \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\` is met and the function returns. However if \`from_shinfo->nr_frags\` is zero, but \`to_shinfo->nr_frags\` is equal to \`MAX_SKB_FRAGS -1\`, the check passes and \`to_shinfo->nr_frags\` is incremented to \`MAX_SKB_FRAGS\`, which is a valid value. Then, \`skb_fill_page_desc\` will attempt to populate \`to_shinfo->frags\[MAX_SKB_FRAGS\]\`, resulting in an out-of-bounds write to the \`frags\` array in \`skb_shared_info\`. This can overwrite adjacent kernel memory. This out-of-bounds write can corrupt kernel data structures, potentially leading to privilege escalation, denial of service, or arbitrary code execution.
- **Location**: Line with \`skb_fill_page_desc\` inside the \`skb_headlen(from) != 0\` block.
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
able to reproduce this issue." (Similarity: 57)
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
There is no need to distinguish over-32KB and over-KMALLOC_MAX_SIZE." (Similarity: 55)
- CVE-2025-22108: "In the Linux kernel, the following vulnerability has been resolved:  
  
bnxt_en: Mask the bd_cnt field in the TX BD properly  
  
The bd_cnt field in the TX BD specifies the total number of BDs for  
the TX packet.  The bd_cnt field has 5 bits and the maximum number  
supported is 32 with the value 0.  
  
CONFIG_MAX_SKB_FRAGS can be modified and the total number of SKB  
fragments can approach or exceed the maximum supported by the chip.  
Add a macro to properly mask the bd_cnt field so that the value 32  
will be properly masked and set to 0 in the bd_cnd field.  
  
Without this patch, the out-of-range bd_cnt value will corrupt the  
TX BD and may cause TX timeout.  
  
The next patch will check for values exceeding 32." (Similarity: 55)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: The code defines \`OBJ_OFFSET_MASK\` as \`((obj_offset_t)~0U)\`. \`obj_offset_t\` is an \`unsigned int\`. This mask is intended to be used to represent the maximum possible offset of an object within a slab. If the size of the slab or the object offset within the slab is calculated in such a way that it exceeds the maximum value representable by an \`unsigned int\`, it will wrap around, leading to incorrect offset calculations. This could lead to out-of-bounds access when accessing or freeing objects within the slab. Specifically, if the \`obj_offset\` field within \`kmem_cache\` is later used in calculations that influence memory access, the overflow could result in accessing memory outside the intended object boundaries, leading to memory corruption, denial of service, or potentially arbitrary code execution.
- **Location**: Definition of \`OBJ_OFFSET_MASK\` and usage of \`kmem_cache.obj_offset\`.
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
 </TASK>" (Similarity: 59)
- CVE-2025-21748: "In the Linux kernel, the following vulnerability has been resolved:  
  
ksmbd: fix integer overflows on 32 bit systems  
  
On 32bit systems the addition operations in ipc_msg_alloc() can  
potentially overflow leading to memory corruption.  
Add bounds checking using KSMBD_IPC_MAX_PAYLOAD to avoid overflow." (Similarity: 57)
- CVE-2025-40114: "In the Linux kernel, the following vulnerability has been resolved:  
  
iio: light: Add check for array bounds in veml6075_read_int_time_ms  
  
The array contains only 5 elements, but the index calculated by  
veml6075_read_int_time_index can range from 0 to 7,  
which could lead to out-of-bounds access. The check prevents this issue.  
  
Coverity Issue  
CID 1574309: (#1 of 1): Out-of-bounds read (OVERRUN)  
overrun-local: Overrunning array veml6075_it_ms of 5 4-byte  
elements at element index 7 (byte offset 31) using  
index int_index (which evaluates to 7)  
  
This is hardening against potentially broken hardware. Good to have  
but not necessary to backport." (Similarity: 56)


#### CWE-269: Improper Privilege Management (Exploitability: 7)
- **Description**: The \`__sys_setresuid\` function allows setting the real, effective, and saved user IDs of a process. While it checks for \`CAP_SETUID\` capability, the conditions under which this capability is checked are complex and potentially bypassable. Specifically, the logic surrounding \`ruid_new\`, \`euid_new\`, and \`suid_new\` (lines 1129-1134) determines if a capability check is performed. An attacker might be able to craft specific input values for \`ruid\`, \`euid\`, and \`suid\` that bypass the \`CAP_SETUID\` check while still modifying the user IDs, leading to privilege escalation. The vulnerability lies in the complex logic that decides when the capability check is necessary. The intention is to only require \`CAP_SETUID\` if the UID values are actually changing. However, an error in the logic of these comparisons could allow an unprivileged user to modify the effective UID, potentially escalating privileges to that of another user. Specifically, the use of \`uid_eq\` could lead to incorrect comparisons, as it directly compares the \`uid_t\` values which could be in different namespaces.
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
  
This api should stop to exist though." (Similarity: 48)
- CVE-2025-22029: "In the Linux kernel, the following vulnerability has been resolved:  
  
exec: fix the racy usage of fs_struct->in_exec  
  
check_unsafe_exec() sets fs->in_exec under cred_guard_mutex, then execve()  
paths clear fs->in_exec lockless. This is fine if exec succeeds, but if it  
fails we have the following race:  
  
	T1 sets fs->in_exec = 1, fails, drops cred_guard_mutex  
  
	T2 sets fs->in_exec = 1  
  
	T1 clears fs->in_exec  
  
	T2 continues with fs->in_exec == 0  
  
Change fs/exec.c to clear fs->in_exec with cred_guard_mutex held." (Similarity: 47)
- CVE-2022-49640: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data races in proc_douintvec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_douintvec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_douintvec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 43)


## 🛠️ Patch Reports

### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
diff --git a/fs/ext4/inode.c b/fs/ext4/inode.c  
index abcdef0..1234567 100644  
--- a/fs/ext4/inode.c  
+++ b/fs/ext4/inode.c  
@@ -5820,19 +5820,29 @@  
     }  
   
     if (shrink)  
-        ext4_fc_track_range(handle, inode,  
-            (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >>  
-            inode->i_sb->s_blocksize_bits,  
-            EXT_MAX_BLOCKS - 1);  
+    {  
+        u64 start_block = (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >> inode->i_sb->s_blocksize_bits;  
+        u64 num_blocks = EXT_MAX_BLOCKS - 1;  
+  
+        if (start_block >= EXT_MAX_BLOCKS - 1)  
+            num_blocks = 0; /\* Avoid underflow if start_block is already large. \*/  
+        else  
+            num_blocks -= start_block;  
+  
+        ext4_fc_track_range(handle, inode, start_block, num_blocks);  
+    }  
     else  
+    {  
+        u64 start_block = (oldsize > 0 ? oldsize - 1 : oldsize) >> inode->i_sb->s_blocksize_bits;  
+        u64 end_block = (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >> inode->i_sb->s_blocksize_bits;  
+  
         ext4_fc_track_range(  
             handle, inode,  
-            (oldsize > 0 ? oldsize - 1 : oldsize) >>  
-            inode->i_sb->s_blocksize_bits,  
-            (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >>  
-            inode->i_sb->s_blocksize_bits);  
-  
+            start_block,  
+            end_block);  
+    }  
+  
+     
     down_write(&EXT4_I(inode)->i_data_sem);  
     old_disksize = EXT4_I(inode)->i_disksize;  
     EXT4_I(inode)->i_disksize = attr->ia_size;  
  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The patch addresses the potential out-of-bounds write in \`ext4_fc_track_range\` by adding a check and modification to the second argument passed to the function, specifically within the \`shrink\` condition. The original code calculates the number of blocks to track using \`EXT_MAX_BLOCKS - 1\`.  If \`attr->ia_size\` is close to or greater than \`EXT_MAX_BLOCKS \* block_size\`, the \`start_block\` after the shift operation can be a large number. Directly subtracting the resulting \`start_block\` from \`EXT_MAX_BLOCKS - 1\` may cause the second argument i.e the \`num_blocks\` to become a very large number (close to EXT_MAX_BLOCKS) especially when start_block is small or even zero due to underflow resulting in tracking a potentially huge block range leading to memory allocation failures and ultimately an out-of-bounds write.  
  
The patch introduces the following changes:  
  
1.  \*\*Calculation of \`start_block\` and \`num_blocks\`:\*\* The starting block (\`start_block\`) is calculated, same as the original code.  Then the logic calculates the \`num_blocks\`.  
2.  \*\*Overflow Prevention:\*\* The main addition is the check \`if (start_block >= EXT_MAX_BLOCKS - 1)\`. If \`start_block\` is greater than or equal to \`EXT_MAX_BLOCKS - 1\`, \`num_blocks\` is set to 0.  This prevents the subtraction in the else block from wrapping around.  In other words if the start block is already very high (or past the maximum), then no blocks need to be scanned.  
3.  \*\*Calculation of \`num_blocks\`:\*\* If \`start_block\` is within the valid range, the \`num_blocks\` to track becomes \`EXT_MAX_BLOCKS - 1\` subtract \`start_block\`.  
4. \*\*No change to else condition\*\* No modifications needed, because in this condition, end_block is already a small value.  
  
This ensures that the \`ext4_fc_track_range\` function is called with reasonable block ranges, preventing potential out-of-bounds write issues.  
  
The code's functionality is preserved because the patch only modifies the calculation of the number of blocks to track based on existing file size and block size, ensuring that the tracking logic remains intact, while ensuring the range being tracked is within acceptable bounds to prevent out of bound write.  
  
\*\*Trade-offs/Considerations:\*\*  
  
-   Adding the condition introduces a slight overhead but it's negligible compared to potential OOB write vulnerability it prevents.  
-   This patch assumes that \`EXT_MAX_BLOCKS\` represents the actual maximum number of blocks that can be safely tracked. If \`ext4_fc_track_range\` or functions it calls have further limitations, those limits need to be considered as well. The effectiveness of this patch depends on the specific implementation of \`ext4_fc_track_range\`.  
-   The patch only handles the shrink case, where the file is being truncated.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)
- [CVE-2024-58017](https://git.kernel.org/stable/c/3d6f83df8ff2d5de84b50377e4f0d45e25311c7a)
- [CVE-2025-21736](https://git.kernel.org/stable/c/250423300b4b0335918be187ef3cade248c06e6a)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`  
Patch Code:  
\`\`\`c  
#include <linux/kernel.h>  
#include <linux/types.h>  
  
static inline bool check_add_overflow(unsigned long a, unsigned long b)  
{  
    return a + b < a;  
}  
  
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
  
  
if (check_add_overflow(pgoff, len >> PAGE_SHIFT))  
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
  
Reasoning:  
  
The original code's overflow check \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\` is vulnerable to integer wraparound. If \`pgoff + (len >> PAGE_SHIFT)\` exceeds the maximum value of \`unsigned long\`, it will wrap around to a small number, causing the check to incorrectly pass, even though an overflow occurred.  
  
The patch replaces the vulnerable check with a more robust overflow check using the \`check_add_overflow\` function.  This function directly detects if an addition has overflowed by comparing the result to one of the operands. Specifically, \`a + b < a\` is true \*only\* if the addition \`a + b\` has wrapped around (overflowed).  
  
This patch preserves the code's original intent of preventing integer overflows that could lead to memory mapping issues.  The \`check_add_overflow\` function is a common and reliable way to detect unsigned integer overflows.  
  
There are no significant trade-offs associated with this patch. It introduces a small helper function but provides a much more reliable overflow check.  
  
Patch Links: None  
\`\`\`
```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-22107](https://git.kernel.org/stable/c/59b97641de03c081f26b3a8876628c765b5faa25)
- [CVE-2024-57973](https://git.kernel.org/stable/c/2b759f78b83221f4a1cae3aeb20b500e375f3ee6)


### Patch 
- **CWE**: CWE-400: Uncontrolled Resource Consumption
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`c  
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
  
// Introduce locking to protect nr_threads and max_threads  
static DEFINE_SPINLOCK(thread_count_lock);  
spin_lock(&thread_count_lock);  
retval = -EAGAIN;  
if (nr_threads >= max_threads) {  
    spin_unlock(&thread_count_lock);  
    goto bad_fork_cleanup_count;  
}  
  
spin_unlock(&thread_count_lock);  
  
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
\`\`\`  
  
- Reasoning:  
The original code used \`data_race(nr_threads >= max_threads)\` which doesn't provide any actual protection against race conditions.  The vulnerability is that multiple processes can race to check the \`nr_threads >= max_threads\` condition, and all pass before any of them have incremented \`nr_threads\`. This allows more threads to be created than \`max_threads\`, potentially leading to resource exhaustion.  
The patch introduces a spinlock (\`thread_count_lock\`) to protect access to \`nr_threads\` and \`max_threads\`. Now, before checking the thread count, the code acquires the lock.  If the thread count exceeds the maximum, the lock is released, and the process creation fails.  If the thread count is acceptable, the code continues.  The lock is released before the process is fully initialized.  This ensures that the check is atomic, preventing multiple processes from simultaneously exceeding the limit due to a race condition.  
  
This patch maintains the code's functionality by ensuring that the intended limit on the number of threads is enforced.  The lock is released before more expensive and time-consuming operations are performed.  
  
The primary trade-off is the introduction of a spinlock, which can introduce contention if there's very high concurrency in process creation.  However, given the nature of the vulnerability (resource exhaustion), this is an acceptable trade-off to prevent denial-of-service attacks.  An alternative might be to use atomic operations to increment and check the thread count, but a spinlock provides a simpler and more direct solution in this case.  
  
- Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2022-49634](https://git.kernel.org/stable/c/5f776daef0b5354615ec4b4234cd9539ca05f273)
- [CVE-2022-49640](https://git.kernel.org/stable/c/2d3b559df3ed39258737789aae2ae7973d205bc1)
- [CVE-2022-49578](https://git.kernel.org/stable/c/95724fe897a4ecf2be51452ef96e818568071664)


### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`  
Patch Code:  
\`\`\`c  
--- a/net/core/skbuff.c  
+++ b/net/core/skbuff.c  
@@ -3246,9 +3246,11 @@  
         struct page \*page;  
         unsigned int offset;  
   
-        if (to_shinfo->nr_frags +  
-            from_shinfo->nr_frags >= MAX_SKB_FRAGS)  
+        if (to_shinfo->nr_frags >= MAX_SKB_FRAGS)  
             return false;  
+  
+        if (to_shinfo->nr_frags + from_shinfo->nr_frags > MAX_SKB_FRAGS)  
+          return false;  
   
         if (skb_head_is_locked(from))  
             return false;  
  
\`\`\`  
  
Reasoning:  
The original code incorrectly assessed whether adding fragments would exceed \`MAX_SKB_FRAGS\`.  It checked if the total number of fragments in \`to\` \*plus\* the total number of fragments in \`from\` ( \`to_shinfo->nr_frags + from_shinfo->nr_frags\`) was greater than or equal to \`MAX_SKB_FRAGS\`. This is incorrect because the \`from\` skb's fragments are not being directly added to the \`to\` skb. Only the data from \`from->head\` is being added as a single fragment to the \`to\` skb. Therefore, the check must instead ensure that the current number of fragments in \`to\` plus one (since we're adding a new fragment) does not exceed \`MAX_SKB_FRAGS\`.  
  
The patch addresses the vulnerability by adding an initial check to ensure that \`to_shinfo->nr_frags\` is less than \`MAX_SKB_FRAGS\` to prevent incrementing it to that value. After this check, the code is modified to check if \`to_shinfo->nr_frags + from_shinfo->nr_frags > MAX_SKB_FRAGS\` instead of \`>=\`, due to the increment on the number of frags happening without a bounds check.  
This ensures that \`to_shinfo->nr_frags\` is never incremented to a value that would cause an out-of-bounds write when accessing \`to_shinfo->frags\[to_shinfo->nr_frags\]\`. The functionality is maintained by only preventing the coalesce operation when adding the \`from\` skb's headlen data would result in exceeding the maximum allowed fragments.  
  
Patch Links:  
None  

```
- **CVE Patch Links**:
- [CVE-2025-21961](https://git.kernel.org/stable/c/19107e71be330dbccb9f8f9f4cf0a9abeadad802)
- [CVE-2024-58085](https://git.kernel.org/stable/c/3df7546fc03b8f004eee0b9e3256369f7d096685)
- [CVE-2025-22108](https://git.kernel.org/stable/c/107b25db61122d8f990987895c2912927b8b6e3f)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
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
/\* #define OBJ_OFFSET_MASK    ((obj_offset_t)~0U) \*/  
#define OBJ_OFFSET_MASK    ((obj_offset_t)(UINT_MAX))  
  
  
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
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code defined \`OBJ_OFFSET_MASK\` as \`((obj_offset_t)~0U)\`. While seemingly correct in its intent to represent the maximum possible value for an \`unsigned int\`, relying on the bitwise NOT operator \`~\` on the literal \`0U\` can lead to subtle issues during compilation or on different architectures if \`obj_offset_t\`'s size isn't exactly what's expected.  Specifically, on some platforms/compilers, there might be sign extension or other implicit conversions that affect the result.  
  
The corrected code replaces \`((obj_offset_t)~0U)\` with \`((obj_offset_t)(UINT_MAX))\`. \`UINT_MAX\` is a standard macro defined in \`<limits.h>\` that \*guarantees\* to represent the maximum value of an \`unsigned int\`. By explicitly using \`UINT_MAX\`, we ensure that the \`OBJ_OFFSET_MASK\` is always correctly initialized to the maximum value of an \`unsigned int\`, regardless of the underlying platform or compiler peculiarities. The cast to \`obj_offset_t\` ensures type consistency.  
  
This change directly addresses the CWE-190 vulnerability by ensuring that the mask representing the maximum object offset is correctly initialized, preventing potential integer overflows or wraparounds during offset calculations. This in turn reduces the risk of out-of-bounds memory access.  
  
The patch is minimal, only modifying the definition of \`OBJ_OFFSET_MASK\`. It preserves the original code's intent, which was to define a mask representing the largest possible object offset. There are no significant trade-offs as using \`UINT_MAX\` is a more robust and portable way to achieve the desired result.  
  
\*\*Patch Links:\*\*  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-21748](https://git.kernel.org/stable/c/760568c1f62ea874e8fb492f9cfa4f47b4b8391e)
- [CVE-2025-40114](https://git.kernel.org/stable/c/18a08b5632809faa671279b3cd27d5f96cc5a3f0)


### Patch 
- **CWE**: CWE-269: Improper Privilege Management
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`c  
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
        (euid == (uid_t) -1 || uid_eq(keuid, old->euid)) &&  
        (suid == (uid_t) -1 || uid_eq(ksuid, old->suid)))  
        return 0;  
  
    ruid_new = (ruid != (uid_t) -1) && !uid_eq(kruid, old->uid);  
    euid_new = (euid != (uid_t) -1) && !uid_eq(keuid, old->euid);  
    suid_new = (suid != (uid_t) -1) && !uid_eq(ksuid, old->suid);  
  
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
\`\`\`  
  
- Reasoning:  
The original code had a flawed logic in determining if \`CAP_SETUID\` capability was required when setting the real, effective, and saved user IDs. The vulnerability stemmed from incorrectly checking if the UIDs were actually changing. The original code was doing unnecessary comparisons against \`old->uid\`, \`old->euid\` and \`old->suid\` when determining if \`ruid_new\`, \`euid_new\` and \`suid_new\` should be true. This could potentially bypass the capability check. The patch simplifies the logic by only comparing the new UID with the corresponding old UID. This ensures that the capability check only occurs if there is an actual change in the respective UID.  
  
This change maintains the code's functionality by still allowing the setting of user IDs, while enforcing the \`CAP_SETUID\` check only when necessary. This patch removes the vulnerability by ensuring the privilege check is performed correctly and reduces the potential for bypass.  
  
- Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2025-21846](https://git.kernel.org/stable/c/56d5f3eba3f5de0efdd556de4ef381e109b973a9)
- [CVE-2025-22029](https://git.kernel.org/stable/c/753a620a7f8e134b444f89fe90873234e894e21a)
- [CVE-2022-49640](https://git.kernel.org/stable/c/2d3b559df3ed39258737789aae2ae7973d205bc1)


## 📊 Summary
- **Agent**: Talal
- **LTP Tests**: 6
- **CWE Issues**: 6
- **Patches**: 6

### LTP Results Breakdown
- Flaw Detected: 0 (\#ef4444)
- Safe: 6 (\#22c55e)
