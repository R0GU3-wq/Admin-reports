
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

#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: In the provided code snippet, specifically within the \`ext4_fc_track_range\` calls, the expression \`(attr->ia_size > 0 ? attr->ia_size - 1 : 0) >> inode->i_sb->s_blocksize_bits\` and \`(oldsize > 0 ? oldsize - 1 : oldsize) >> inode->i_sb->s_blocksize_bits\` are used to calculate block numbers based on file sizes.  If \`attr->ia_size\` or \`oldsize\` is zero, the expression evaluates to \`0\`. However, if \`attr->ia_size\` or \`oldsize\` is equal to the minimum integer value (e.g., \`INT_MIN\`), subtracting 1 can cause an integer wraparound, leading to a very large positive number. This large number is then right-shifted, still potentially resulting in a large value which may be out of bounds for the \`ext4_fc_track_range\` function's block range parameters. This could lead to out-of-bounds memory access when the function uses the block range, potentially causing a denial-of-service or, in more severe cases, arbitrary code execution if the memory region being accessed is carefully controlled by an attacker.
- **Location**: Lines within the \`ext4_fc_track_range\` calls (e.g., Line numbers depending on the full context). Specifically, the calculation \`(attr->ia_size > 0 ? attr->ia_size - 1 : 0) >> inode->i_sb->s_blocksize_bits\` and \`(oldsize > 0 ? oldsize - 1 : oldsize) >> inode->i_sb->s_blocksize_bits\` within the arguments of those calls.
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
before it is utilised." (Similarity: 60)
- CVE-2023-52933: "In the Linux kernel, the following vulnerability has been resolved:  
  
Squashfs: fix handling and sanity checking of xattr_ids count  
  
A Sysbot \[1\] corrupted filesystem exposes two flaws in the handling and  
sanity checking of the xattr_ids count in the filesystem.  Both of these  
flaws cause computation overflow due to incorrect typing.  
  
In the corrupted filesystem the xattr_ids value is 4294967071, which  
stored in a signed variable becomes the negative number -225.  
  
Flaw 1 (64-bit systems only):  
  
The signed integer xattr_ids variable causes sign extension.  
  
This causes variable overflow in the SQUASHFS_XATTR_\*(A) macros.  The  
variable is first multiplied by sizeof(struct squashfs_xattr_id) where the  
type of the sizeof operator is "unsigned long".  
  
On a 64-bit system this is 64-bits in size, and causes the negative number  
to be sign extended and widened to 64-bits and then become unsigned.  This  
produces the very large number 18446744073709548016 or 2^64 - 3600.  This  
number when rounded up by SQUASHFS_METADATA_SIZE - 1 (8191 bytes) and  
divided by SQUASHFS_METADATA_SIZE overflows and produces a length of 0  
(stored in len).  
  
Flaw 2 (32-bit systems only):  
  
On a 32-bit system the integer variable is not widened by the unsigned  
long type of the sizeof operator (32-bits), and the signedness of the  
variable has no effect due it always being treated as unsigned.  
  
The above corrupted xattr_ids value of 4294967071, when multiplied  
overflows and produces the number 4294963696 or 2^32 - 3400.  This number  
when rounded up by SQUASHFS_METADATA_SIZE - 1 (8191 bytes) and divided by  
SQUASHFS_METADATA_SIZE overflows again and produces a length of 0.  
  
The effect of the 0 length computation:  
  
In conjunction with the corrupted xattr_ids field, the filesystem also has  
a corrupted xattr_table_start value, where it matches the end of  
filesystem value of 850.  
  
This causes the following sanity check code to fail because the  
incorrectly computed len of 0 matches the incorrect size of the table  
reported by the superblock (0 bytes).  
  
    len = SQUASHFS_XATTR_BLOCK_BYTES(\*xattr_ids);  
    indexes = SQUASHFS_XATTR_BLOCKS(\*xattr_ids);  
  
    /\*  
     \* The computed size of the index table (len bytes) should exactly  
     \* match the table start and end points  
    \*/  
    start = table_start + sizeof(\*id_table);  
    end = msblk->bytes_used;  
  
    if (len != (end - start))  
            return ERR_PTR(-EINVAL);  
  
Changing the xattr_ids variable to be "usigned int" fixes the flaw on a  
64-bit system.  This relies on the fact the computation is widened by the  
unsigned long type of the sizeof operator.  
  
Casting the variable to u64 in the above macro fixes this flaw on a 32-bit  
system.  
  
It also means 64-bit systems do not implicitly rely on the type of the  
sizeof operator to widen the computation.  
  
\[1\] https://lore.kernel.org/lkml/000000000000cd44f005f1a0f17f@google.com/" (Similarity: 57)
- CVE-2024-58017: "In the Linux kernel, the following vulnerability has been resolved:  
  
printk: Fix signed integer overflow when defining LOG_BUF_LEN_MAX  
  
Shifting 1 << 31 on a 32-bit int causes signed integer overflow, which  
leads to undefined behavior. To prevent this, cast 1 to u32 before  
performing the shift, ensuring well-defined behavior.  
  
This change explicitly avoids any potential overflow by ensuring that  
the shift occurs on an unsigned 32-bit integer." (Similarity: 55)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: The code performs a check \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\` to prevent integer overflows when calculating the size of the mapping. However, this check is insufficient. If \`len\` is sufficiently large, then \`len >> PAGE_SHIFT\` can wrap around to a small positive value. Adding this small positive value to \`pgoff\` can still be less than \`pgoff\` due to the integer overflow. This would bypass the check and lead to allocation of less memory than intended, which could cause memory corruption vulnerabilities when the program attempts to access memory beyond allocated size.
- **Location**: Line 594
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
 </TASK>" (Similarity: 52)
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
element is part of an unmapped page." (Similarity: 47)
- CVE-2024-57973: "In the Linux kernel, the following vulnerability has been resolved:  
  
rdma/cxgb4: Prevent potential integer overflow on 32bit  
  
The "gl->tot_len" variable is controlled by the user.  It comes from  
process_responses().  On 32bit systems, the "gl->tot_len + sizeof(struct  
cpl_pass_accept_req) + sizeof(struct rss_header)" addition could have an  
integer wrapping bug.  Use size_add() to prevent this." (Similarity: 47)


#### CWE-787: Out-of-bounds Write (Exploitability: 8)
- **Description**: While the provided code snippet itself doesn't directly show an out-of-bounds write, the call to \`rcu_copy_process(p)\` (Line 3010) is a likely location where this vulnerability could manifest. \`rcu_copy_process\` is responsible for copying various process-related data structures to the newly created process. If any of the copy operations within \`rcu_copy_process\` (which is not visible in this snippet) fail to validate buffer sizes properly before copying data, an out-of-bounds write could occur. This would allow an attacker to overwrite kernel memory, leading to a denial of service, privilege escalation, or arbitrary code execution. The complexity is hidden within the details of \`rcu_copy_process\` implementation, but the vulnerability's impact would be catastrophic.
- **Location**: Line 3010: rcu_copy_process(p)
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
- CVE-2025-22003: "In the Linux kernel, the following vulnerability has been resolved:  
  
can: ucan: fix out of bound read in strscpy() source  
  
Commit 7fdaf8966aae ("can: ucan: use strscpy() to instead of strncpy()")  
unintentionally introduced a one byte out of bound read on strscpy()'s  
source argument (which is kind of ironic knowing that strscpy() is meant  
to be a more secure alternative :)).  
  
Let's consider below buffers:  
  
  dest\[len + 1\]; /\* will be NUL terminated \*/  
  src\[len\]; /\* may not be NUL terminated \*/  
  
When doing:  
  
  strncpy(dest, src, len);  
  dest\[len\] = '\0';  
  
strncpy() will read up to len bytes from src.  
  
On the other hand:  
  
  strscpy(dest, src, len + 1);  
  
will read up to len + 1 bytes from src, that is to say, an out of bound  
read of one byte will occur on src if it is not NUL terminated. Note  
that the src\[len\] byte is never copied, but strscpy() still needs to  
read it to check whether a truncation occurred or not.  
  
This exact pattern happened in ucan.  
  
The root cause is that the source is not NUL terminated. Instead of  
doing a copy in a local buffer, directly NUL terminate it as soon as  
usb_control_msg() returns. With this, the local firmware_str\[\] variable  
can be removed.  
  
On top of this do a couple refactors:  
  
  - ucan_ctl_payload->raw is only used for the firmware string, so  
    rename it to ucan_ctl_payload->fw_str and change its type from u8 to  
    char.  
  
  - ucan_device_request_in() is only used to retrieve the firmware  
    string, so rename it to ucan_get_fw_str() and refactor it to make it  
    directly handle all the string termination logic." (Similarity: 65)
- CVE-2024-58016: "In the Linux kernel, the following vulnerability has been resolved:  
  
safesetid: check size of policy writes  
  
syzbot attempts to write a buffer with a large size to a sysfs entry  
with writes handled by handle_policy_update(), triggering a warning  
in kmalloc.  
  
Check the size specified for write buffers before allocating.  
  
\[PM: subject tweak\]" (Similarity: 59)
- CVE-2025-21996: "In the Linux kernel, the following vulnerability has been resolved:  
  
drm/radeon: fix uninitialized size issue in radeon_vce_cs_parse()  
  
On the off chance that command stream passed from userspace via  
ioctl() call to radeon_vce_cs_parse() is weirdly crafted and  
first command to execute is to encode (case 0x03000001), the function  
in question will attempt to call radeon_vce_cs_reloc() with size  
argument that has not been properly initialized. Specifically, 'size'  
will point to 'tmp' variable before the latter had a chance to be  
assigned any value.  
  
Play it safe and init 'tmp' with 0, thus ensuring that  
radeon_vce_cs_reloc() will catch an early error in cases like these.  
  
Found by Linux Verification Center (linuxtesting.org) with static  
analysis tool SVACE.  
  
(cherry picked from commit 2d52de55f9ee7aaee0e09ac443f77855989c6b68)" (Similarity: 58)


#### CWE-787: Out-of-bounds Write (Exploitability: 7)
- **Description**: The code in \`skb_try_coalesce\` attempts to coalesce two \`sk_buff\` structures. When \`skb_headlen(from)\` is not 0, the code attempts to add the data from the head of the \`from\` sk_buff as a fragment to the \`to\` sk_buff. However, the code checks if \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\`. This check doesn't account for cases where \`from_shinfo->nr_frags\` might be large but less than \`MAX_SKB_FRAGS\`, yet adding one more fragment (from \`from->head\`) to \`to\` would still exceed \`MAX_SKB_FRAGS\` for the \`to\` sk_buff. The correct check should be  \`to_shinfo->nr_frags + 1 > MAX_SKB_FRAGS\`. If \`to_shinfo->nr_frags\` is already equal to \`MAX_SKB_FRAGS\`, adding another fragment results in an out-of-bounds write to \`to_shinfo->frags\[\]\`, leading to memory corruption. This can cause a denial of service or potentially lead to privilege escalation if attacker-controlled data overwrites kernel structures.
- **Location**: Line where \`skb_fill_page_desc\` is called within \`skb_try_coalesce\` function:  \`skb_fill_page_desc(to, to_shinfo->nr_frags, page, offset, skb_headlen(from));\` inside the \`if (skb_headlen(from) != 0)\` block. The vulnerable check before is: \`if (to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS)\`
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
There is no need to distinguish over-32KB and over-KMALLOC_MAX_SIZE." (Similarity: 51)
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
able to reproduce this issue." (Similarity: 51)
- CVE-2025-22087: "In the Linux kernel, the following vulnerability has been resolved:  
  
bpf: Fix array bounds error with may_goto  
  
may_goto uses an additional 8 bytes on the stack, which causes the  
interpreters\[\] array to go out of bounds when calculating index by  
stack_size.  
  
1. If a BPF program is rewritten, re-evaluate the stack size. For non-JIT  
cases, reject loading directly.  
  
2. For non-JIT cases, calculating interpreters\[idx\] may still cause  
out-of-bounds array access, and just warn about it.  
  
3. For jit_requested cases, the execution of bpf_func also needs to be  
warned. So move the definition of function __bpf_prog_ret0_warn out of  
the macro definition CONFIG_BPF_JIT_ALWAYS_ON." (Similarity: 50)


#### CWE-415: Double Free (Exploitability: 7)
- **Description**: A double-free condition occurs when the same memory region is freed multiple times. In the context of a slab allocator like SLUB, a double-free can corrupt the slab's metadata, potentially leading to arbitrary code execution or denial of service.  While not immediately evident in the provided snippet, it's crucial to understand that the kmem_cache structure manages slab objects, and improper handling of allocation/deallocation within functions not shown could lead to double-free. The \`track\` struct suggests a possible debugging mechanism to track allocations and frees, but an error in this mechanism, or a separate code path, could still result in a double free.
- **Location**: Potentially within functions responsible for slab allocation and deallocation which use the \`kmem_cache\` structure. Further analysis of functions that use \`kmem_cache\`, \`cpu_slab\`, and allocation/free operations is required to pinpoint the exact location. Specifically, if the allocation count of a slab object is not properly managed, it could lead to double free when the same memory region is freed multiple times.
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
leading to use-after-free." (Similarity: 67)
- CVE-2025-21981: "In the Linux kernel, the following vulnerability has been resolved:  
  
ice: fix memory leak in aRFS after reset  
  
Fix aRFS (accelerated Receive Flow Steering) structures memory leak by  
adding a checker to verify if aRFS memory is already allocated while  
configuring VSI. aRFS objects are allocated in two cases:  
- as part of VSI initialization (at probe), and  
- as part of reset handling  
  
However, VSI reconfiguration executed during reset involves memory  
allocation one more time, without prior releasing already allocated  
resources. This led to the memory leak with the following signature:  
  
\[root@os-delivery ~\]# cat /sys/kernel/debug/kmemleak  
unreferenced object 0xff3c1ca7252e6000 (size 8192):  
  comm "kworker/0:0", pid 8, jiffies 4296833052  
  hex dump (first 32 bytes):  
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
  backtrace (crc 0):  
    \[<ffffffff991ec485>\] __kmalloc_cache_noprof+0x275/0x340  
    \[<ffffffffc0a6e06a>\] ice_init_arfs+0x3a/0xe0 \[ice\]  
    \[<ffffffffc09f1027>\] ice_vsi_cfg_def+0x607/0x850 \[ice\]  
    \[<ffffffffc09f244b>\] ice_vsi_setup+0x5b/0x130 \[ice\]  
    \[<ffffffffc09c2131>\] ice_init+0x1c1/0x460 \[ice\]  
    \[<ffffffffc09c64af>\] ice_probe+0x2af/0x520 \[ice\]  
    \[<ffffffff994fbcd3>\] local_pci_probe+0x43/0xa0  
    \[<ffffffff98f07103>\] work_for_cpu_fn+0x13/0x20  
    \[<ffffffff98f0b6d9>\] process_one_work+0x179/0x390  
    \[<ffffffff98f0c1e9>\] worker_thread+0x239/0x340  
    \[<ffffffff98f14abc>\] kthread+0xcc/0x100  
    \[<ffffffff98e45a6d>\] ret_from_fork+0x2d/0x50  
    \[<ffffffff98e083ba>\] ret_from_fork_asm+0x1a/0x30  
    ..." (Similarity: 59)
- CVE-2025-22085: "In the Linux kernel, the following vulnerability has been resolved:  
  
RDMA/core: Fix use-after-free when rename device name  
  
Syzbot reported a slab-use-after-free with the following call trace:  
  
==================================================================  
BUG: KASAN: slab-use-after-free in nla_put+0xd3/0x150 lib/nlattr.c:1099  
Read of size 5 at addr ffff888140ea1c60 by task syz.0.988/10025  
  
CPU: 0 UID: 0 PID: 10025 Comm: syz.0.988  
Not tainted 6.14.0-rc4-syzkaller-00859-gf77f12010f67 #0  
Hardware name: Google Compute Engine, BIOS Google 02/12/2025  
Call Trace:  
 <TASK>  
 __dump_stack lib/dump_stack.c:94 \[inline\]  
 dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120  
 print_address_description mm/kasan/report.c:408 \[inline\]  
 print_report+0x16e/0x5b0 mm/kasan/report.c:521  
 kasan_report+0x143/0x180 mm/kasan/report.c:634  
 kasan_check_range+0x282/0x290 mm/kasan/generic.c:189  
 __asan_memcpy+0x29/0x70 mm/kasan/shadow.c:105  
 nla_put+0xd3/0x150 lib/nlattr.c:1099  
 nla_put_string include/net/netlink.h:1621 \[inline\]  
 fill_nldev_handle+0x16e/0x200 drivers/infiniband/core/nldev.c:265  
 rdma_nl_notify_event+0x561/0xef0 drivers/infiniband/core/nldev.c:2857  
 ib_device_notify_register+0x22/0x230 drivers/infiniband/core/device.c:1344  
 ib_register_device+0x1292/0x1460 drivers/infiniband/core/device.c:1460  
 rxe_register_device+0x233/0x350 drivers/infiniband/sw/rxe/rxe_verbs.c:1540  
 rxe_net_add+0x74/0xf0 drivers/infiniband/sw/rxe/rxe_net.c:550  
 rxe_newlink+0xde/0x1a0 drivers/infiniband/sw/rxe/rxe.c:212  
 nldev_newlink+0x5ea/0x680 drivers/infiniband/core/nldev.c:1795  
 rdma_nl_rcv_skb drivers/infiniband/core/netlink.c:239 \[inline\]  
 rdma_nl_rcv+0x6dd/0x9e0 drivers/infiniband/core/netlink.c:259  
 netlink_unicast_kernel net/netlink/af_netlink.c:1313 \[inline\]  
 netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1339  
 netlink_sendmsg+0x8de/0xcb0 net/netlink/af_netlink.c:1883  
 sock_sendmsg_nosec net/socket.c:709 \[inline\]  
 __sock_sendmsg+0x221/0x270 net/socket.c:724  
 ____sys_sendmsg+0x53a/0x860 net/socket.c:2564  
 ___sys_sendmsg net/socket.c:2618 \[inline\]  
 __sys_sendmsg+0x269/0x350 net/socket.c:2650  
 do_syscall_x64 arch/x86/entry/common.c:52 \[inline\]  
 do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83  
 entry_SYSCALL_64_after_hwframe+0x77/0x7f  
RIP: 0033:0x7f42d1b8d169  
Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 ...  
RSP: 002b:00007f42d2960038 EFLAGS: 00000246 ORIG_RAX: 000000000000002e  
RAX: ffffffffffffffda RBX: 00007f42d1da6320 RCX: 00007f42d1b8d169  
RDX: 0000000000000000 RSI: 00004000000002c0 RDI: 000000000000000c  
RBP: 00007f42d1c0e2a0 R08: 0000000000000000 R09: 0000000000000000  
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000  
R13: 0000000000000000 R14: 00007f42d1da6320 R15: 00007ffe399344a8  
 </TASK>  
  
Allocated by task 10025:  
 kasan_save_stack mm/kasan/common.c:47 \[inline\]  
 kasan_save_track+0x3f/0x80 mm/kasan/common.c:68  
 poison_kmalloc_redzone mm/kasan/common.c:377 \[inline\]  
 __kasan_kmalloc+0x98/0xb0 mm/kasan/common.c:394  
 kasan_kmalloc include/linux/kasan.h:260 \[inline\]  
 __do_kmalloc_node mm/slub.c:4294 \[inline\]  
 __kmalloc_node_track_caller_noprof+0x28b/0x4c0 mm/slub.c:4313  
 __kmemdup_nul mm/util.c:61 \[inline\]  
 kstrdup+0x42/0x100 mm/util.c:81  
 kobject_set_name_vargs+0x61/0x120 lib/kobject.c:274  
 dev_set_name+0xd5/0x120 drivers/base/core.c:3468  
 assign_name drivers/infiniband/core/device.c:1202 \[inline\]  
 ib_register_device+0x178/0x1460 drivers/infiniband/core/device.c:1384  
 rxe_register_device+0x233/0x350 drivers/infiniband/sw/rxe/rxe_verbs.c:1540  
 rxe_net_add+0x74/0xf0 drivers/infiniband/sw/rxe/rxe_net.c:550  
 rxe_newlink+0xde/0x1a0 drivers/infiniband/sw/rxe/rxe.c:212  
 nldev_newlink+0x5ea/0x680 drivers/infiniband/core/nldev.c:1795  
 rdma_nl_rcv_skb drivers/infiniband/core/netlink.c:239 \[inline\]  
 rdma_nl_rcv+0x6dd/0x9e0 drivers/infiniband/core/netlink.c:259  
 netlink_unicast_kernel net/netlink/af_netlink.c:1313 \[inline\]  
 netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1339  
 netlink_sendmsg+0x8de/0xcb0 net  
---truncated---" (Similarity: 58)


#### CWE-269: Improper Privilege Management (Exploitability: 7)
- **Description**: The \`__sys_setresuid\` function allows a process to change its real, effective, and saved user IDs. The vulnerability lies in how the function checks for the \`CAP_SETUID\` capability. Specifically, lines 1129-1134 check if \*any\* of the RUID, EUID, or SUID changes would result in a different ID than the current UID, EUID or SUID, and only then checks for \`CAP_SETUID\`. This allows a process to set its EUID to the same value as its current UID, EUID, or SUID without possessing \`CAP_SETUID\`. This can be problematic if the process is running as root, but another user also possesses a file with the setuid bit set for that process. After setting the effective uid, the process can execute the suid binary to obtain the privileges of the file owner. This constitutes privilege escalation from the current user to the suid file owner's privileges, because any unprivileged user can call setresuid to set their effective UID to the same as their real or saved UID, thus bypassing the usual privilege check when using a setuid binary.
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
  
This api should stop to exist though." (Similarity: 50)
- CVE-2025-22029: "In the Linux kernel, the following vulnerability has been resolved:  
  
exec: fix the racy usage of fs_struct->in_exec  
  
check_unsafe_exec() sets fs->in_exec under cred_guard_mutex, then execve()  
paths clear fs->in_exec lockless. This is fine if exec succeeds, but if it  
fails we have the following race:  
  
	T1 sets fs->in_exec = 1, fails, drops cred_guard_mutex  
  
	T2 sets fs->in_exec = 1  
  
	T1 clears fs->in_exec  
  
	T2 continues with fs->in_exec == 0  
  
Change fs/exec.c to clear fs->in_exec with cred_guard_mutex held." (Similarity: 48)
- CVE-2023-52987: "In the Linux kernel, the following vulnerability has been resolved:  
  
ASoC: SOF: ipc4-mtrace: prevent underflow in sof_ipc4_priority_mask_dfs_write()  
  
The "id" comes from the user.  Change the type to unsigned to prevent  
an array underflow." (Similarity: 46)


## 🛠️ Patch Reports

### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`c  
/\* Patch Code: \*/  
\`\`\`c  
    if (shrink)  
        ext4_fc_track_range(handle, inode,  
            (attr->ia_size > 0 && attr->ia_size != LLONG_MIN ? attr->ia_size - 1 : 0) >>  
            inode->i_sb->s_blocksize_bits,  
            EXT_MAX_BLOCKS - 1);  
    else  
        ext4_fc_track_range(  
            handle, inode,  
            (oldsize > 0 && oldsize != LLONG_MIN ? oldsize - 1 : oldsize) >>  
            inode->i_sb->s_blocksize_bits,  
            (attr->ia_size > 0 && attr->ia_size != LLONG_MIN ? attr->ia_size - 1 : 0) >>  
            inode->i_sb->s_blocksize_bits);  
\`\`\`  
  
\`\`\`  
/\* Reasoning: \*/  
The integer overflow vulnerability arises when \`attr->ia_size\` or \`oldsize\` is equal to \`LLONG_MIN\`. Subtracting 1 from \`LLONG_MIN\` results in integer wraparound, leading to a large positive value.  
  
The patch addresses this by adding a check to ensure that the value is not \`LLONG_MIN\` before performing the subtraction. Specifically, the condition \`attr->ia_size != LLONG_MIN\` and \`oldsize != LLONG_MIN\` is added to the existing ternary operator conditions. If \`attr->ia_size\` or \`oldsize\` is \`LLONG_MIN\`, the expression evaluates to 0, preventing the wraparound.  
  
This change maintains the original code's functionality because it only modifies the behavior when \`attr->ia_size\` or \`oldsize\` is equal to \`LLONG_MIN\`.  In all other cases, the code behaves identically to the original.  
  
There are no significant trade-offs, as the added check has minimal performance impact.  It is important to use \`LLONG_MIN\` instead of \`INT_MIN\` due to the potential usage of 64 bit file size.  
  
/\* Patch Links: \*/  
None  
\`\`\`
```
- **CVE Patch Links**:
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)
- [CVE-2023-52933](https://git.kernel.org/stable/c/1369322c1de52c7b9b988b95c9903110a4566778)
- [CVE-2024-58017](https://git.kernel.org/stable/c/3d6f83df8ff2d5de84b50377e4f0d45e25311c7a)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\`\`\`  
Patch Code:  
\`\`\`c  
+       /\*  
+        \* Use u64 for the calculation to check for overflow.  
+        \* 'len >> PAGE_SHIFT' could potentially wrap around if len is large enough.  
+        \*/  
+       if ((u64)pgoff + ((u64)len >> PAGE_SHIFT) > ULONG_MAX >> PAGE_SHIFT){  
+               return -EOVERFLOW;  
+       }  
+  
        if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)  
                return -EOVERFLOW;  
\`\`\`  
  
Reasoning:  
The original check \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\` aimed to prevent integer overflows. However, it was flawed because \`len >> PAGE_SHIFT\` could itself wrap around to a small positive number. This small positive number added to \`pgoff\` could still be less than \`pgoff\` due to overflow, bypassing the check.  
  
The patch addresses this vulnerability by first converting \`pgoff\` and \`len >> PAGE_SHIFT\` to \`u64\` before performing the addition. It then checks if the result exceeds \`ULONG_MAX >> PAGE_SHIFT\`. This ensures that even if \`len >> PAGE_SHIFT\` would wrap around, the check will detect it. The right shift is performed to allow for \`pgoff\` to occupy the \`PAGE_SHIFT\` lower bits of the \`u64\`. This also aligns with the existing check, which only accounts for number of pages. The original check is retained as it is still valid, and serves as an additional check to prevent a possible missed overflow in the new check. It also improves code readability since it contains the original logic.  
  
- Vulnerability Resolution: This patch completely prevents the integer overflow by using a wider type for the calculation and checking against a maximum value.  
- Functionality Preservation: The patch only affects the overflow check. It doesn't change any other part of the code's logic and should not affect functionality when valid inputs are provided.  
- Trade-offs: Using \`u64\` for the calculation introduces a slight performance overhead compared to the original integer addition. However, this overhead is negligible compared to the security benefit provided by preventing the integer overflow.  
  
Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-22107](https://git.kernel.org/stable/c/59b97641de03c081f26b3a8876628c765b5faa25)
- [CVE-2024-57973](https://git.kernel.org/stable/c/2b759f78b83221f4a1cae3aeb20b500e375f3ee6)


### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
+#include <linux/limits.h> // Include for NAME_MAX  
+  
 retval = copy_creds(p, clone_flags);  // Line 2993  
 if (retval < 0)  
     goto bad_fork_free;  
  
@@ -3006,6 +3007,22 @@  
 INIT_LIST_HEAD(&p->children);  
 INIT_LIST_HEAD(&p->sibling);  
 rcu_copy_process(p);  
+  
+#ifdef CONFIG_SECURITY  
+    /\*  
+     \* This is a preventative measure against potential overflows in the  
+     \* security subsystem related to process naming. While the security  
+     \* subsystem should enforce limits, adding this check ensures robustness.  
+     \* It checks the length of the process name before copying, preventing  
+     \* a potential out-of-bounds write during the copy operation within  
+     \* the security context.  This is a speculative fix, as the exact  
+     \* location of the potential vulnerability within rcu_copy_process is unknown.  
+     \*/  
+    if (strlen(p->comm) >= NAME_MAX) {  
+        p->comm\[NAME_MAX - 1\] = '\0'; // Truncate to avoid overflow  
+    }  
+#endif  
+  
 p->vfork_done = NULL;  
 spin_lock_init(&p->alloc_lock);  
  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The CWE analysis points to a potential out-of-bounds write within the \`rcu_copy_process(p)\` call. While the exact location of the vulnerability isn't specified, the analysis suggests a failure to validate buffer sizes during data copy operations within \`rcu_copy_process\`.  
  
Given that \`rcu_copy_process\` copies process-related data structures, including the process name (\`p->comm\`), the patch adds a preemptive check to ensure the length of the process name doesn't exceed \`NAME_MAX\` before \`rcu_copy_process\` is called.  If the name is too long, it's truncated. This helps prevent potential buffer overflows if \`rcu_copy_process\` or code it calls (e.g., in the security subsystem) copies \`p->comm\` without proper bounds checking.  
  
- \*\*Resolution of Vulnerability:\*\* The patch mitigates the risk of an out-of-bounds write by limiting the length of the process name, ensuring that any copy operations involving the process name will not write beyond the allocated buffer.  The fix uses \`NAME_MAX\`, which is defined in \`linux/limits.h\` and represents the maximum length for a process name. Truncating prevents the overflow.  
  
- \*\*Maintenance of Functionality:\*\* The patch preserves the original code's functionality by only adding a length check and truncation before the potentially vulnerable \`rcu_copy_process\` call. The process is still forked and initialized.  If the process name is too long, it's truncated, which might slightly alter the process name, but it avoids a crash or security vulnerability. The code is only enabled under \`CONFIG_SECURITY\` so that it is only compiled if the security subsystem is enabled.  
  
- \*\*Trade-offs and Considerations:\*\*  
    - Truncating the process name might result in a less informative process list or debugging information. However, this is a reasonable trade-off for preventing a potential kernel memory corruption vulnerability.  
    - The patch is speculative because the exact location of the vulnerability within \`rcu_copy_process\` is unknown. It addresses a likely cause based on the CWE analysis and understanding of typical data structures copied during process creation.  
    - A more robust solution would involve auditing and fixing the underlying code within \`rcu_copy_process\` that performs the copy operation.  However, without access to that internal code, this preventative measure is the best approach.  
    - This fix assumes that the \`comm\` field is a character array that can be safely truncated.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22003](https://git.kernel.org/stable/c/1d22a122ffb116c3cf78053e812b8b21f8852ee9)
- [CVE-2024-58016](https://git.kernel.org/stable/c/36b385d0f2b4c0bf41d491e19075ecd990d2bf94)
- [CVE-2025-21996](https://git.kernel.org/stable/c/0effb378ebce52b897f85cd7f828854b8c7cb636)


### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
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
  
        if (to_shinfo->nr_frags + 1 > MAX_SKB_FRAGS)  
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
  
Reasoning:  
  
The original code had a flawed check for the maximum number of fragments allowed in the \`to\` sk_buff. The condition \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\` doesn't prevent the \`to\` sk_buff from exceeding the \`MAX_SKB_FRAGS\` limit when adding the head data of \`from\` as a fragment. It is possible to have a scenario where \`to_shinfo->nr_frags\` is close to \`MAX_SKB_FRAGS\` and \`from_shinfo->nr_frags\` is small, but adding the head of \`from\` to \`to\` still causes an overflow.  
  
The corrected code changes the check to \`to_shinfo->nr_frags + 1 > MAX_SKB_FRAGS\`. This explicitly checks if adding \*one\* more fragment (the head of the \`from\` sk_buff) to the \`to\` sk_buff would exceed the maximum allowed fragments.  This directly addresses the out-of-bounds write vulnerability.  
  
The patch maintains the original code's functionality by ensuring that the coalescing of sk_buffs only occurs when it's safe to add the head of the \`from\` sk_buff as a fragment to the \`to\` sk_buff without exceeding the fragment limit. It only modifies the conditional check and doesn't alter any other logic within the function.  
  
There are no significant trade-offs. The corrected check might slightly reduce the cases where coalescing can occur, but this is a necessary consequence of preventing a potential memory corruption vulnerability.  
  
Patch Links:  
None  

```
- **CVE Patch Links**:
- [CVE-2024-58085](https://git.kernel.org/stable/c/3df7546fc03b8f004eee0b9e3256369f7d096685)
- [CVE-2025-21961](https://git.kernel.org/stable/c/19107e71be330dbccb9f8f9f4cf0a9abeadad802)
- [CVE-2025-22087](https://git.kernel.org/stable/c/19e6817f84000d0b06f09fd69ebd56217842c122)


### Patch 
- **CWE**: CWE-415: Double Free
- **Kernel Version**: 6.11.0-25-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
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
#ifdef CONFIG_SLUB_DEBUG  
    unsigned int refcnt; /\* Reference counter to detect double free \*/  
#endif  
};  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The primary concern, based on the CWE analysis, is a potential double-free vulnerability. Given the provided code context (slab allocator), a reference counter is a relatively common approach to detect double frees when CONFIG_SLUB_DEBUG is enabled. The added \`refcnt\` field within the \`kmem_cache\` structure allows for tracking the allocation count of each object managed by the slab cache.  
  
Here's how it resolves the vulnerability:  
  
-   \*\*Double-Free Detection:\*\* During allocation, \`refcnt\` should be incremented. Before freeing, \`refcnt\` should be decremented. If \`refcnt\` is zero before a free, it indicates a double-free condition, allowing the kernel to trigger an error or take other appropriate actions. Actual implementation of incrementing, decrementing, and checking this field requires modifications in allocation and deallocation functions of \`slub.c\` file, and they are not included here, since they're beyond the available code scope.  
  
Here's how it maintains functionality:  
  
-   \*\*Minimal Impact:\*\* The \`refcnt\` field is added under the \`CONFIG_SLUB_DEBUG\` configuration option. This ensures that the change only affects debugging builds and has no performance impact on production systems when debugging is disabled.  
-   \*\*Data Integrity:\*\*  The addition of \`refcnt\` itself does not alter the fundamental behavior of the slab allocator.  
  
Here are some trade-offs and considerations:  
  
-   \*\*Performance Overhead:\*\* Enabling \`CONFIG_SLUB_DEBUG\` introduces a performance overhead due to the reference counter management.  
-   \*\*Completeness:\*\*  Adding the \`refcnt\` is only one part of the solution. The actual allocation and deallocation routines need to be modified to use and check \`refcnt\`, which is beyond the scope of the initial structure definition. The provided code only includes a structure definition.  
-   \*\*Memory Usage:\*\* Each kmem_cache structure will consume a bit more memory with the added \`refcnt\` field, but this is negligible in most cases.  
-   \*\*Error handling:\*\* The logic of checking refcnt and handling errors when refcnt is zero is out of the scope, but should be carefully implemented.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2022-49700](https://git.kernel.org/stable/c/0515cc9b6b24877f59b222ade704bfaa42caa2a6)
- [CVE-2025-21981](https://git.kernel.org/stable/c/23d97f18901ef5e4e264e3b1777fe65c760186b5)
- [CVE-2025-22085](https://git.kernel.org/stable/c/0d6460b9d2a3ee380940bdf47680751ef91cb88e)


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
        (euid == (uid_t) -1 || (uid_eq(keuid, old->euid) &&  
                                uid_eq(keuid, old->fsuid))) &&  
        (suid == (uid_t) -1 || uid_eq(ksuid, old->suid)))  
        return 0;  
  
    ruid_new = ruid != (uid_t) -1 && !uid_eq(kruid, old->uid);  
    euid_new = euid != (uid_t) -1 && !uid_eq(keuid, old->euid);  
    suid_new = suid != (uid_t) -1 && !uid_eq(ksuid, old->suid);  
  
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
  
\*\*Reasoning:\*\*  
  
The original code's check for \`CAP_SETUID\` (lines 1129-1134) was flawed.  It allowed setting the EUID to the same value as the existing UID, EUID, or SUID without the capability. The vulnerability arises because the code determines if a capability check is required by verifying that a UID is new \*and\* different from \*all\* existing UIDs. This enables an unprivileged user to elevate privileges through a setuid binary if their current EUID, UID, or SUID is equal to the owner of that setuid binary.  
  
The fix modifies lines 1129-1134 to remove comparisons of the \*new\* UIDs against each other.  Specifically, the expressions \`!uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid)\` are removed for \`ruid_new\`, \`!uid_eq(keuid, old->uid) && !uid_eq(keuid, old->suid)\` for \`euid_new\`, and \`!uid_eq(ksuid, old->uid) && !uid_eq(ksuid, old->euid)\` for \`suid_new\`.  
  
This ensures that \`CAP_SETUID\` is always checked when the process attempts to change \*any\* of the UIDs to a value different from the current corresponding UID, thus requiring the capability for privilege elevation.  
  
\*   \*\*How it resolves the vulnerability:\*\* By enforcing the capability check when any of the UIDs are being changed to a different value, the attack vector where an unprivileged user could manipulate their EUID to match a setuid binary owner is eliminated.  
  
\*   \*\*How it maintains the code's functionality:\*\*  The fundamental functionality of \`setresuid\` remains the same - it allows a process to change its real, effective, and saved user IDs.  However, it now correctly enforces the \`CAP_SETUID\` capability check, preventing unauthorized privilege escalation.  
  
\*   \*\*Trade-offs or considerations:\*\*  There are no significant trade-offs. The change makes the privilege check more strict, which is the desired behavior for security.  The performance impact is minimal, as it only removes a few comparisons.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-21846](https://git.kernel.org/stable/c/56d5f3eba3f5de0efdd556de4ef381e109b973a9)
- [CVE-2025-22029](https://git.kernel.org/stable/c/753a620a7f8e134b444f89fe90873234e894e21a)
- [CVE-2023-52987](https://git.kernel.org/stable/c/d52f34784e4e2f6e77671a9f104d8a69a3b5d24c)


## 📊 Summary
- **Agent**: Talal
- **LTP Tests**: 6
- **CWE Issues**: 6
- **Patches**: 6

### LTP Results Breakdown
- Flaw Detected: 0 (\#ef4444)
- Safe: 6 (\#22c55e)
