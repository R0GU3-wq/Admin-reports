
# Talal Kernel Watch Report - 2025-05-05

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
- **Description**: The code calculates block ranges for tracking with \`ext4_fc_track_range\`. Specifically, it calculates the starting and ending blocks based on \`attr->ia_size\`, \`oldsize\` and \`inode->i_sb->s_blocksize_bits\`. The shift operation using \`>> inode->i_sb->s_blocksize_bits\` could potentially cause an integer overflow if \`inode->i_sb->s_blocksize_bits\` is sufficiently large, or if \`attr->ia_size - 1\` or \`oldsize - 1\` is large enough (close to the maximum value of its type) before the right shift, and the subsequent division by block size wrapped around. The \`EXT_MAX_BLOCKS - 1\` value is also hardcoded and could become problematic if future block size changes are introduced without modifying this code appropriately. If the resulting range is incorrect, metadata corruption may occur due to incorrect tracking, potentially leading to data loss or other filesystem inconsistencies.
- **Location**: Lines 5820, 5825
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
  
\[1\] https://lore.kernel.org/lkml/000000000000cd44f005f1a0f17f@google.com/" (Similarity: 53)
- CVE-2022-49414: "In the Linux kernel, the following vulnerability has been resolved:  
  
ext4: fix race condition between ext4_write and ext4_convert_inline_data  
  
Hulk Robot reported a BUG_ON:  
 ==================================================================  
 EXT4-fs error (device loop3): ext4_mb_generate_buddy:805: group 0,  
 block bitmap and bg descriptor inconsistent: 25 vs 31513 free clusters  
 kernel BUG at fs/ext4/ext4_jbd2.c:53!  
 invalid opcode: 0000 \[#1\] SMP KASAN PTI  
 CPU: 0 PID: 25371 Comm: syz-executor.3 Not tainted 5.10.0+ #1  
 RIP: 0010:ext4_put_nojournal fs/ext4/ext4_jbd2.c:53 \[inline\]  
 RIP: 0010:__ext4_journal_stop+0x10e/0x110 fs/ext4/ext4_jbd2.c:116  
 \[...\]  
 Call Trace:  
  ext4_write_inline_data_end+0x59a/0x730 fs/ext4/inline.c:795  
  generic_perform_write+0x279/0x3c0 mm/filemap.c:3344  
  ext4_buffered_write_iter+0x2e3/0x3d0 fs/ext4/file.c:270  
  ext4_file_write_iter+0x30a/0x11c0 fs/ext4/file.c:520  
  do_iter_readv_writev+0x339/0x3c0 fs/read_write.c:732  
  do_iter_write+0x107/0x430 fs/read_write.c:861  
  vfs_writev fs/read_write.c:934 \[inline\]  
  do_pwritev+0x1e5/0x380 fs/read_write.c:1031  
 \[...\]  
 ==================================================================  
  
Above issue may happen as follows:  
           cpu1                     cpu2  
__________________________|__________________________  
do_pwritev  
 vfs_writev  
  do_iter_write  
   ext4_file_write_iter  
    ext4_buffered_write_iter  
     generic_perform_write  
      ext4_da_write_begin  
                           vfs_fallocate  
                            ext4_fallocate  
                             ext4_convert_inline_data  
                              ext4_convert_inline_data_nolock  
                               ext4_destroy_inline_data_nolock  
                                clear EXT4_STATE_MAY_INLINE_DATA  
                               ext4_map_blocks  
                                ext4_ext_map_blocks  
                                 ext4_mb_new_blocks  
                                  ext4_mb_regular_allocator  
                                   ext4_mb_good_group_nolock  
                                    ext4_mb_init_group  
                                     ext4_mb_init_cache  
                                      ext4_mb_generate_buddy  --> error  
       ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA)  
                                ext4_restore_inline_data  
                                 set EXT4_STATE_MAY_INLINE_DATA  
       ext4_block_write_begin  
      ext4_da_write_end  
       ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA)  
       ext4_write_inline_data_end  
        handle=NULL  
        ext4_journal_stop(handle)  
         __ext4_journal_stop  
          ext4_put_nojournal(handle)  
           ref_cnt = (unsigned long)handle  
           BUG_ON(ref_cnt == 0)  ---> BUG_ON  
  
The lock held by ext4_convert_inline_data is xattr_sem, but the lock  
held by generic_perform_write is i_rwsem. Therefore, the two locks can  
be concurrent.  
  
To solve above issue, we add inode_lock() for ext4_convert_inline_data().  
At the same time, move ext4_convert_inline_data() in front of  
ext4_punch_hole(), remove similar handling from ext4_punch_hole()." (Similarity: 53)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 6)
- **Description**: The code calculates the number of pages required by shifting \`len\` right by \`PAGE_SHIFT\` ( \`len >> PAGE_SHIFT\`). This result is then added to \`pgoff\`. If \`pgoff + (len >> PAGE_SHIFT)\` exceeds the maximum value that \`pgoff\` can hold, an integer overflow occurs. Although the code checks for the overflow with \`if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)\`, an attacker can control \`len\` and \`pgoff\` to trigger this overflow. The consequence is returning \`-EOVERFLOW\` which prevents a potentially vulnerable mapping. However, manipulating \`len\` and \`pgoff\` to reliably trigger the return of \`-EOVERFLOW\` can act as a limited denial of service. Although the direct impact seems limited (only preventing a mapping), the integer overflow itself is the core problem. By carefully crafting inputs such as len and pgoff, it might be possible to cause the overflow to wrap to a small value, bypassing other size checks, and ultimately resulting in a smaller-than-expected memory allocation. The smaller allocation along with the intended larger usage can result in heap overflow and other memory corruption issues.
- **Location**: Line 596
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
 </TASK>" (Similarity: 55)
- CVE-2024-58017: "In the Linux kernel, the following vulnerability has been resolved:  
  
printk: Fix signed integer overflow when defining LOG_BUF_LEN_MAX  
  
Shifting 1 << 31 on a 32-bit int causes signed integer overflow, which  
leads to undefined behavior. To prevent this, cast 1 to u32 before  
performing the shift, ensuring well-defined behavior.  
  
This change explicitly avoids any potential overflow by ensuring that  
the shift occurs on an unsigned 32-bit integer." (Similarity: 53)
- CVE-2022-49748: "In the Linux kernel, the following vulnerability has been resolved:  
  
perf/x86/amd: fix potential integer overflow on shift of a int  
  
The left shift of int 32 bit integer constant 1 is evaluated using 32 bit  
arithmetic and then passed as a 64 bit function argument. In the case where  
i is 32 or more this can lead to an overflow.  Avoid this by shifting  
using the BIT_ULL macro instead." (Similarity: 53)


#### CWE-400: Uncontrolled Resource Consumption (Exploitability: 7)
- **Description**: The code contains a check for resource limits using \`is_rlimit_overlimit\` on \`RLIMIT_NPROC\` which represents the maximum number of processes a user can create.  However, the subsequent \`data_race(nr_threads >= max_threads)\` check suggests a different resource constraint - the overall number of threads or processes in the system. While the code attempts to prevent exceeding \`RLIMIT_NPROC\` it does not provide sufficient safeguards against uncontrolled consumption of overall system threads/processes. A malicious user (or a bug) could repeatedly fork processes (within their \`RLIMIT_NPROC\`) but still exhaust the system's overall ability to create new processes/threads (\`max_threads\`), leading to a denial-of-service condition for the entire system.  The \`data_race\` macro might have limited protection depending on the architecture and compiler, but it is likely not sufficient to avoid the race condition in all circumstances.
- **Location**: Lines checking \`is_rlimit_overlimit\` and \`data_race(nr_threads >= max_threads)\`
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
need to add annotations on the other subsystem's side." (Similarity: 59)
- CVE-2022-49640: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data races in proc_douintvec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_douintvec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_douintvec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 58)
- CVE-2022-49578: "In the Linux kernel, the following vulnerability has been resolved:  
  
ip: Fix data-races around sysctl_ip_prot_sock.  
  
sysctl_ip_prot_sock is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing." (Similarity: 57)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 8)
- **Description**: The code attempts to coalesce two sk_buff structures. The \`skb_fill_page_desc\` function adds a page fragment to the target \`sk_buff\` (\`to\`). The code checks \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\` to prevent exceeding the maximum number of fragments allowed. However, if \`to_shinfo->nr_frags\` and \`from_shinfo->nr_frags\` are close to \`MAX_SKB_FRAGS\`, their sum can wrap around to a small value, bypassing the check.  This can lead to \`to_shinfo->nr_frags\` becoming larger than \`MAX_SKB_FRAGS\` after the fragment is added via \`skb_fill_page_desc\`, resulting in an out-of-bounds write to the \`frags\` array within the \`skb_shared_info\` structure.  This can corrupt kernel memory and potentially lead to privilege escalation or denial of service.
- **Location**: Line 41: \`if (to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS)\`
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
able to reproduce this issue." (Similarity: 63)
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
 </TASK>" (Similarity: 61)
- CVE-2025-21774: "In the Linux kernel, the following vulnerability has been resolved:  
  
can: rockchip: rkcanfd_handle_rx_fifo_overflow_int(): bail out if skb cannot be allocated  
  
Fix NULL pointer check in rkcanfd_handle_rx_fifo_overflow_int() to  
bail out if skb cannot be allocated." (Similarity: 59)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 6)
- **Description**: The code defines \`obj_offset_t\` as an \`unsigned int\` and \`OBJ_OFFSET_MASK\` as \`((obj_offset_t)~0U)\`.  While seemingly benign, if the \`obj_offset\` field within the \`kmem_cache\` structure is used in calculations related to memory access, especially when combined with other size parameters like \`size\` or \`object_size\`, there is a risk of integer overflow. For example, multiplying \`obj_offset\` with another variable and using it as an offset into a slab can cause a wraparound, leading to out-of-bounds access. Given that \`obj_offset\` represents an offset \*within\* a slab, an overflow here means the allocator could potentially read or write to memory locations outside of the intended allocation. This can corrupt kernel data structures, leading to denial of service, privilege escalation, or arbitrary code execution.
- **Location**: struct kmem_cache definition, obj_offset field.  Any function using kmem_cache->obj_offset for address calculations.
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
- CVE-2025-21748: "In the Linux kernel, the following vulnerability has been resolved:  
  
ksmbd: fix integer overflows on 32 bit systems  
  
On 32bit systems the addition operations in ipc_msg_alloc() can  
potentially overflow leading to memory corruption.  
Add bounds checking using KSMBD_IPC_MAX_PAYLOAD to avoid overflow." (Similarity: 60)
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
 </TASK>" (Similarity: 60)
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
maximum offset allowed considering the structure size." (Similarity: 59)


#### CWE-269: Improper Privilege Management (Exploitability: 7)
- **Description**: The \`__sys_setresuid\` function in the Linux kernel is intended to set the real, effective, and saved user IDs. The vulnerability lies in the insufficient capability check performed before allowing a user to change their credentials. Specifically, while the code checks for \`CAP_SETUID\` (in the user namespace) using \`ns_capable_setid\`, it only does so if \*any\* of the RUID, EUID, or SUID are being changed to a \*new\* value (lines 1131-1135). However, if all three IDs are being set to the \*same\* value as \*one\* of the existing IDs (e.g., all to the current effective UID), this capability check is bypassed. This allows an unprivileged user to set all three IDs to their effective UID without proper authorization, potentially bypassing intended security restrictions or LSM (Linux Security Module) hooks that would normally apply when changing credentials. The impact is that it can lead to privilege escalation or bypassing security policies if the effective UID has broader capabilities than the current UID or SUID.
- **Location**: Lines 1131-1135 in \`__sys_setresuid\`
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
- CVE-2025-22038: "In the Linux kernel, the following vulnerability has been resolved:  
  
ksmbd: validate zero num_subauth before sub_auth is accessed  
  
Access psid->sub_auth\[psid->num_subauth - 1\] without checking  
if num_subauth is non-zero leads to an out-of-bounds read.  
This patch adds a validation step to ensure num_subauth != 0  
before sub_auth is accessed." (Similarity: 51)
- CVE-2022-49405: "In the Linux kernel, the following vulnerability has been resolved:  
  
staging: r8188eu: prevent ->Ssid overflow in rtw_wx_set_scan()  
  
This code has a check to prevent read overflow but it needs another  
check to prevent writing beyond the end of the ->Ssid\[\] array." (Similarity: 51)
- CVE-2023-52987: "In the Linux kernel, the following vulnerability has been resolved:  
  
ASoC: SOF: ipc4-mtrace: prevent underflow in sof_ipc4_priority_mask_dfs_write()  
  
The "id" comes from the user.  Change the type to unsigned to prevent  
an array underflow." (Similarity: 49)


## 🛠️ Patch Reports

### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
#include <linux/math.h>  
  
if (attr->ia_size != inode->i_size) {  
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
  
    u64 start_block, end_block;  
  
    if (shrink) {  
        start_block = (attr->ia_size > 0 ? attr->ia_size - 1 : 0);  
        end_block = EXT_MAX_BLOCKS - 1;  
    } else {  
        start_block = (oldsize > 0 ? oldsize - 1 : oldsize);  
        end_block = (attr->ia_size > 0 ? attr->ia_size - 1 : 0);  
    }  
  
    if (inode->i_sb->s_blocksize_bits < 64) {  
        start_block = div_u64(start_block, (1ULL << inode->i_sb->s_blocksize_bits));  
        end_block = div_u64(end_block, (1ULL << inode->i_sb->s_blocksize_bits));  
    } else {  
        /\* Blocksize is larger than 2^64, which should be impossible. \*/  
        start_block = 0;  
        end_block = 0;  
    }  
  
    ext4_fc_track_range(handle, inode, start_block, end_block);  
  
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
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code had potential integer overflow issues when calculating the block numbers by right-shifting \`attr->ia_size - 1\` or \`oldsize - 1\` by \`inode->i_sb->s_blocksize_bits\`.  To mitigate this, the patch performs the following steps:  
  
1. \*\*Use \`div_u64\`:\*\* The code now uses the \`div_u64\` function to divide the size by the block size. \`div_u64\` is a safe division function for unsigned 64-bit integers in the Linux kernel, preventing potential overflows.  
2. \*\*Explicit Type Conversion:\*\* Cast the left operand in shift expression to unsigned 64 bit integer to avoid integer overflow.  
3. \*\*Pre-calculate intermediate variables:\*\* The code now pre-calculates the \`start_block\` and \`end_block\` variables for better readability and to prepare for the safe division operation.  
4. \*\*Handle impossible block size values:\*\* If \`inode->i_sb->s_blocksize_bits\` is equal to or greater than 64 (implying a block size greater than or equal to 2^64), which is highly improbable, the code sets both \`start_block\` and \`end_block\` to 0. This provides a safe fallback in such an edge case, preventing undefined behavior, and may effectively disable the range tracking without causing a crash or filesystem corruption.  
  
This approach resolves the integer overflow vulnerability because it performs the division using a safe 64-bit division function and handles extreme (and highly unlikely) block sizes gracefully. The original code's functionality is maintained because the patch correctly calculates the block range based on the inode size and block size. It only addresses the potential for integer overflows during the block number calculation.  The intent of the original code, which is to track a range of blocks, is preserved.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)
- [CVE-2023-52933](https://git.kernel.org/stable/c/1369322c1de52c7b9b988b95c9903110a4566778)
- [CVE-2022-49414](https://git.kernel.org/stable/c/14602353b350950b551eccc6b46411aa3b12ffe2)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
#include <linux/types.h> // Needed for u64  
  
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
  
// Use u64 to avoid overflow during addition, then compare with ULONG_MAX  
if ((u64)pgoff + (len >> PAGE_SHIFT) > ULONG_MAX)  
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
  
\*\*Reasoning:\*\*  
  
The original code checks for integer overflow using \`if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)\`. This relies on the wrapping behavior of integers, which is well-defined in C for unsigned types but can have unpredictable behavior for signed types depending on compiler flags. Even when wrapping behavior is well defined, an attacker can still potentially cause the overflow and get \`-EOVERFLOW\` which is a limited denial of service. Additionally, it is also possible to overflow in such a way to wrap around to a smaller value and bypass size checks, leading to memory corruption vulnerabilities downstream.  
  
The patch addresses the integer overflow vulnerability by:  
  
1.  \*\*Casting to \`u64\`:\*\* The values \`pgoff\` and \`(len >> PAGE_SHIFT)\` are cast to \`u64\` before the addition. This promotes the calculation to a 64-bit unsigned integer, preventing the overflow that could occur with a smaller integer type (likely \`unsigned long\` on 32/64 bit systems).  
2.  \*\*Comparing with \`ULONG_MAX\`:\*\* The result of the addition is then compared with \`ULONG_MAX\`.  \`ULONG_MAX\` is the maximum value that an \`unsigned long\` can hold. Since \`pgoff\` is an \`unsigned long\`, if the 64-bit sum exceeds \`ULONG_MAX\`, it means that the result would have overflowed if it were stored in an \`unsigned long\` variable.  
  
This approach ensures that the code correctly detects potential overflows without relying on the wrapping behavior. It maintains the code's functionality by still returning \`-EOVERFLOW\` if the calculation results in a value that would exceed the maximum value for \`pgoff\`.  
  
\*\*Trade-offs and Considerations:\*\*  
  
\*   \*\*Performance:\*\* The patch introduces a slight performance overhead due to the 64-bit arithmetic. However, this overhead is likely negligible in most cases.  
\*   \*\*\`ULONG_MAX\`:\*\* Using \`ULONG_MAX\` implicitly assumes \`pgoff\` is of type \`unsigned long\`. While this is generally true in Linux kernel, it's something to keep in mind.  If \`pgoff\` could be of a wider type, a different comparison would be necessary.  
\*   \*\*Portability:\*\*  The inclusion of \`<linux/types.h>\` ensures that \`u64\` is defined correctly across different architectures.  
\* \*\*Security\*\*: This patch protects against integer overflow.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2024-58017](https://git.kernel.org/stable/c/3d6f83df8ff2d5de84b50377e4f0d45e25311c7a)
- [CVE-2022-49748](https://git.kernel.org/stable/c/08245672cdc6505550d1a5020603b0a8d4a6dcc7)


### Patch 
- **CWE**: CWE-400: Uncontrolled Resource Consumption
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
retval = copy_creds(p, clone_flags);  
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
if (data_race(nr_threads >= max_threads) || nr_threads >= sysctl_threads_max)  
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
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The vulnerability lies in the potential for a user to exhaust system resources by creating a large number of processes/threads, even if they stay within their individual \`RLIMIT_NPROC\` limit. The original code checks for the per-user limit, and also attempts to check if the \`nr_threads\` is greater than or equal to the \`max_threads\`.  However, it only uses a \`data_race\` macro which is not sufficient to avoid the race condition in all circumstances.  
  
The patch addresses this by adding an explicit check against \`sysctl_threads_max\`. \`sysctl_threads_max\` represents the system-wide maximum number of threads or processes allowed. Adding \`|| nr_threads >= sysctl_threads_max\` to the existing \`if\` condition ensures that a new process or thread will not be created if the system-wide limit is reached, regardless of the \`data_race\` result. This prevents a denial-of-service attack by resource exhaustion.  
  
The patch maintains the code's functionality by still respecting the per-user process limit (\`RLIMIT_NPROC\`) and only adding an additional constraint. The \`data_race\` check is preserved, since it may offer some limited protection.  
The trade-off is that this limits the total number of processes or threads that can be created on the system, which could impact legitimate use cases if \`sysctl_threads_max\` is set too low.  However, a reasonable value for \`sysctl_threads_max\` is crucial for system stability.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2022-49634](https://git.kernel.org/stable/c/5f776daef0b5354615ec4b4234cd9539ca05f273)
- [CVE-2022-49640](https://git.kernel.org/stable/c/2d3b559df3ed39258737789aae2ae7973d205bc1)
- [CVE-2022-49578](https://git.kernel.org/stable/c/95724fe897a4ecf2be51452ef96e818568071664)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
Patch Code:  
\`\`\`c  
diff --git a/net/core/skbuff.c b/net/core/skbuff.c  
index 7e34b5d..a12b3c4 100644  
--- a/net/core/skbuff.c  
+++ b/net/core/skbuff.c  
@@ -38,6 +38,7 @@  
 #include <linux/highmem.h>  
 #include <linux/atomic.h>  
 #include <net/checksum.h>  
+#include <linux/math64.h>  
  
 /\*  
  \* Coalesce two sk_buffs:  
@@ -69,8 +70,10 @@  
         return false;  
     if (skb_zcopy(to) || skb_zcopy(from))  
         return false;  
+    if (from_shinfo->nr_frags > MAX_SKB_FRAGS - to_shinfo->nr_frags)  
+        return false;  
  
-    if (skb_headlen(from) != 0) {  
+   if (skb_headlen(from) != 0) {  
         struct page \*page;  
         unsigned int offset;  
  
Patch Links: None  
  
Reasoning:  
The original code checks for potential integer overflows using \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\`. This check is vulnerable to integer wraparound. If both \`to_shinfo->nr_frags\` and \`from_shinfo->nr_frags\` are sufficiently large, their sum can wrap around to a small value, bypassing the check and allowing the code to proceed with adding fragments beyond the limit \`MAX_SKB_FRAGS\`.  
  
The corrected code replaces the vulnerable addition and comparison with a subtraction, avoiding the integer overflow issue: \`from_shinfo->nr_frags > MAX_SKB_FRAGS - to_shinfo->nr_frags\`. This revised check verifies that adding the number of fragments from \`from\` to \`to\` will not exceed \`MAX_SKB_FRAGS\`. The subtraction will correctly catch the overflow cases that the original code misses.  
  
This patch preserves the original code's functionality by maintaining the intended constraint on the maximum number of fragments. It addresses the integer overflow issue directly. There are no significant trade-offs associated with this change; it improves the robustness of the code without impacting its performance noticeably.  
  
Patch Links: None  
  

```
- **CVE Patch Links**:
- [CVE-2025-21961](https://git.kernel.org/stable/c/19107e71be330dbccb9f8f9f4cf0a9abeadad802)
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-21774](https://git.kernel.org/stable/c/118fb35681bd2c0d2afa22f7be0ef94bb4d06849)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
--- a/mm/slub.c  
+++ b/mm/slub.c  
@@ -41,7 +41,7 @@  
   
 /\* Bitfield for obj offset within a slab \*/  
 typedef unsigned int __bitwise obj_offset_t;  
-#define OBJ_OFFSET_MASK    ((obj_offset_t)~0U)  
+#define OBJ_OFFSET_MASK    ((obj_offset_t)(PAGE_SIZE - 1))  
   
 /\*  
  \* Slab cache structure  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The vulnerability lies in the potential for \`obj_offset\` to be used in calculations that can result in out-of-bounds memory access within a slab. The original \`OBJ_OFFSET_MASK\` allows \`obj_offset\` to represent any value up to the maximum value of an unsigned integer, meaning an object can have an extremely large offset. While theoretically the size of the slab would be restricted, there's no explicit code restricting the value of \`obj_offset\` to be within the slab. The danger is that if \`obj_offset\` is close to \`UINT_MAX\`, adding it to other offsets when calculating object addresses can easily lead to an integer overflow and incorrect memory accesses.  
  
The patch addresses this by limiting \`obj_offset\` to be less than \`PAGE_SIZE\`. A single slab will never be larger than a page, so limiting \`obj_offset\` to within \`PAGE_SIZE\` guarantees that any offset calculation using \`obj_offset\` will never result in an access outside the slab.  This effectively bounds the maximum value of the object offset to a safe range that is within the allocated slab.  
  
The code's functionality is maintained because a valid object offset will always be less than or equal to the page size, as a slab's size is limited by the page size.  Using \`PAGE_SIZE - 1\` ensures that the mask accounts for all possible offsets within a page.  
  
The main trade-off is that this patch limits the flexibility of the allocator to support slabs larger than a single page. However, modern Linux systems almost exclusively use single-page slabs in SLUB. Therefore, the trade-off is acceptable, and the increased security outweighs the minor limitation on slab size.  
  
\*\*Patch Links:\*\*  
None  

```
- **CVE Patch Links**:
- [CVE-2025-21748](https://git.kernel.org/stable/c/760568c1f62ea874e8fb492f9cfa4f47b4b8391e)
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2024-58000](https://git.kernel.org/stable/c/29b95ac917927ce9f95bf38797e16333ecb489b1)


### Patch 
- **CWE**: CWE-269: Improper Privilege Management
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)  // Line 1097  
{  
    struct user_namespace \*ns = current_user_ns();  
    const struct cred \*old;  
    struct cred \*new;  
    int retval;  
    kuid_t kruid, keuid, ksuid;  
  
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
  
-   ruid_new = ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&  
-              !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);  
-   euid_new = euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&  
-              !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid);  
-   suid_new = suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&  
-              !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid);  
-   if ((ruid_new || euid_new || suid_new) &&  
+   if (!ns_capable_setid(old->user_ns, CAP_SETUID))  // Line 1135  
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
  
The original code had a flawed capability check.  It only checked for \`CAP_SETUID\` if \*any\* of the RUID, EUID, or SUID were being set to a \*new\* value. This allowed a user to set all three IDs to their effective UID (or any other existing ID) without having \`CAP_SETUID\`, thus bypassing security restrictions.  
  
The patch removes the complex logic for determining if the IDs are "new" and simply checks for \`CAP_SETUID\` unconditionally before proceeding with the setresuid operation (unless it's a no-op). This enforces that any call to \`setresuid\` that actually changes any of the IDs requires the caller to have \`CAP_SETUID\`.  
  
- \*\*Resolution of Vulnerability:\*\* By unconditionally requiring \`CAP_SETUID\`, the patch prevents unprivileged users from setting their RUID, EUID, and SUID to any arbitrary value, including their current EUID, without proper authorization.  
- \*\*Maintenance of Functionality:\*\* The patch preserves the functionality of \`setresuid\` for privileged users (those with \`CAP_SETUID\`) and for cases where the system call is a no-op.  
- \*\*Trade-offs/Considerations:\*\* The only potential trade-off is that a previously working, but incorrect, behavior (setting all IDs to the EUID without capability check) is now disallowed.  This is intentional, as the original behavior was the vulnerability. The change is minimal, targeting only the capability check and not impacting other parts of the functionality.  
- Removing the \`ruid_new\`, \`euid_new\` and \`suid_new\` declarations, also simplifies the code and removes unused variables, while keeping the code readable.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22038](https://git.kernel.org/stable/c/0e36a3e080d6d8bd7a34e089345d043da4ac8283)
- [CVE-2022-49405](https://git.kernel.org/stable/c/476bfda0be0f9669add92bff604ca78226cf53d1)
- [CVE-2023-52987](https://git.kernel.org/stable/c/d52f34784e4e2f6e77671a9f104d8a69a3b5d24c)


## 📊 Summary
- **Agent**: Talal
- **LTP Tests**: 6
- **CWE Issues**: 6
- **Patches**: 6

### LTP Results Breakdown
- Flaw Detected: 1 (\#ef4444)
- Safe: 5 (\#22c55e)
