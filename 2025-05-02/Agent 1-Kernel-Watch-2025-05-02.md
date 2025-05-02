
# Agent 1 Kernel Watch Report - 2025-05-02

## 🔍 Detection Results

### LTP Test Results

| Test | Result |
|------|--------|
| Filesystem Tests | No Issues Found |
| Memory Management | No Issues Found |
| Process Management | Flaw Detected |
| Networking Tests | No Issues Found |
| Device Drivers | No Issues Found |
| System Calls | Flaw Detected |


### CWE Analysis

#### CWE-787: Out-of-bounds Write (Exploitability: 7)
- **Description**: The code modifies the inode's \`i_disksize\` (EXT4_I(inode)->i_disksize) to the new size \`attr->ia_size\` without proper validation or checks after acquiring the i_data_sem semaphore using down_write(&EXT4_I(inode)->i_data_sem). Although the code attempts to restore the old \`i_disksize\` if an error occurs later, there's a window between modifying \`i_disksize\` and the potential error check/rollback where a concurrent process could read the inode. If \`attr->ia_size\` is maliciously crafted or has unintended values that, while valid within the broader context of the filesystem, are outside the expected or allowable range for \`i_disksize\` based on the underlying storage device capabilities or filesystem limits, this could lead to an out-of-bounds write or other unexpected behavior during subsequent operations that rely on this value (e.g., during block allocation or inode updates). This is exacerbated by the fact the oldsize isn't used in ext4_fc_track_range when shrinking. If the shrink size is large, a large value is put into fc_track_range which can cause integer overflows when converted to extents.
- **Location**: Line 5828: EXT4_I(inode)->i_disksize = attr->ia_size;
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
- CVE-2022-49547: "In the Linux kernel, the following vulnerability has been resolved:  
  
btrfs: fix deadlock between concurrent dio writes when low on free data space  
  
When reserving data space for a direct IO write we can end up deadlocking  
if we have multiple tasks attempting a write to the same file range, there  
are multiple extents covered by that file range, we are low on available  
space for data and the writes don't expand the inode's i_size.  
  
The deadlock can happen like this:  
  
1) We have a file with an i_size of 1M, at offset 0 it has an extent with  
   a size of 128K and at offset 128K it has another extent also with a  
   size of 128K;  
  
2) Task A does a direct IO write against file range \[0, 256K), and because  
   the write is within the i_size boundary, it takes the inode's lock (VFS  
   level) in shared mode;  
  
3) Task A locks the file range \[0, 256K) at btrfs_dio_iomap_begin(), and  
   then gets the extent map for the extent covering the range \[0, 128K).  
   At btrfs_get_blocks_direct_write(), it creates an ordered extent for  
   that file range (\[0, 128K));  
  
4) Before returning from btrfs_dio_iomap_begin(), it unlocks the file  
   range \[0, 256K);  
  
5) Task A executes btrfs_dio_iomap_begin() again, this time for the file  
   range \[128K, 256K), and locks the file range \[128K, 256K);  
  
6) Task B starts a direct IO write against file range \[0, 256K) as well.  
   It also locks the inode in shared mode, as it's within the i_size limit,  
   and then tries to lock file range \[0, 256K). It is able to lock the  
   subrange \[0, 128K) but then blocks waiting for the range \[128K, 256K),  
   as it is currently locked by task A;  
  
7) Task A enters btrfs_get_blocks_direct_write() and tries to reserve data  
   space. Because we are low on available free space, it triggers the  
   async data reclaim task, and waits for it to reserve data space;  
  
8) The async reclaim task decides to wait for all existing ordered extents  
   to complete (through btrfs_wait_ordered_roots()).  
   It finds the ordered extent previously created by task A for the file  
   range \[0, 128K) and waits for it to complete;  
  
9) The ordered extent for the file range \[0, 128K) can not complete  
   because it blocks at btrfs_finish_ordered_io() when trying to lock the  
   file range \[0, 128K).  
  
   This results in a deadlock, because:  
  
   - task B is holding the file range \[0, 128K) locked, waiting for the  
     range \[128K, 256K) to be unlocked by task A;  
  
   - task A is holding the file range \[128K, 256K) locked and it's waiting  
     for the async data reclaim task to satisfy its space reservation  
     request;  
  
   - the async data reclaim task is waiting for ordered extent \[0, 128K)  
     to complete, but the ordered extent can not complete because the  
     file range \[0, 128K) is currently locked by task B, which is waiting  
     on task A to unlock file range \[128K, 256K) and task A waiting  
     on the async data reclaim task.  
  
   This results in a deadlock between 4 task: task A, task B, the async  
   data reclaim task and the task doing ordered extent completion (a work  
   queue task).  
  
This type of deadlock can sporadically be triggered by the test case  
generic/300 from fstests, and results in a stack trace like the following:  
  
\[12084.033689\] INFO: task kworker/u16:7:123749 blocked for more than 241 seconds.  
\[12084.034877\]       Not tainted 5.18.0-rc2-btrfs-next-115 #1  
\[12084.035562\] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.  
\[12084.036548\] task:kworker/u16:7   state:D stack:    0 pid:123749 ppid:     2 flags:0x00004000  
\[12084.036554\] Workqueue: btrfs-flush_delalloc btrfs_work_helper \[btrfs\]  
\[12084.036599\] Call Trace:  
\[12084.036601\]  <TASK>  
\[12084.036606\]  __schedule+0x3cb/0xed0  
\[12084.036616\]  schedule+0x4e/0xb0  
\[12084.036620\]  btrfs_start_ordered_extent+0x109/0x1c0 \[btrfs\]  
\[12084.036651\]  ? prepare_to_wait_exclusive+0xc0/0xc0  
\[12084.036659\]  btrfs_run_ordered_extent_work+0x1a/0x30 \[btrfs\]  
\[12084.036688\]  btrfs_work_helper+0xf8/0x400 \[btrfs\]  
\[12084.0367  
---truncated---" (Similarity: 57)


#### CWE-787: Out-of-bounds Write (Exploitability: 7)
- **Description**: The code modifies the inode's \`i_disksize\` (EXT4_I(inode)->i_disksize) to the new size \`attr->ia_size\` without proper validation or checks after acquiring the i_data_sem semaphore using down_write(&EXT4_I(inode)->i_data_sem). Although the code attempts to restore the old \`i_disksize\` if an error occurs later, there's a window between modifying \`i_disksize\` and the potential error check/rollback where a concurrent process could read the inode. If \`attr->ia_size\` is maliciously crafted or has unintended values that, while valid within the broader context of the filesystem, are outside the expected or allowable range for \`i_disksize\` based on the underlying storage device capabilities or filesystem limits, this could lead to an out-of-bounds write or other unexpected behavior during subsequent operations that rely on this value (e.g., during block allocation or inode updates). This is exacerbated by the fact the oldsize isn't used in ext4_fc_track_range when shrinking. If the shrink size is large, a large value is put into fc_track_range which can cause integer overflows when converted to extents.
- **Location**: Line 5828: EXT4_I(inode)->i_disksize = attr->ia_size;
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
- CVE-2022-49547: "In the Linux kernel, the following vulnerability has been resolved:  
  
btrfs: fix deadlock between concurrent dio writes when low on free data space  
  
When reserving data space for a direct IO write we can end up deadlocking  
if we have multiple tasks attempting a write to the same file range, there  
are multiple extents covered by that file range, we are low on available  
space for data and the writes don't expand the inode's i_size.  
  
The deadlock can happen like this:  
  
1) We have a file with an i_size of 1M, at offset 0 it has an extent with  
   a size of 128K and at offset 128K it has another extent also with a  
   size of 128K;  
  
2) Task A does a direct IO write against file range \[0, 256K), and because  
   the write is within the i_size boundary, it takes the inode's lock (VFS  
   level) in shared mode;  
  
3) Task A locks the file range \[0, 256K) at btrfs_dio_iomap_begin(), and  
   then gets the extent map for the extent covering the range \[0, 128K).  
   At btrfs_get_blocks_direct_write(), it creates an ordered extent for  
   that file range (\[0, 128K));  
  
4) Before returning from btrfs_dio_iomap_begin(), it unlocks the file  
   range \[0, 256K);  
  
5) Task A executes btrfs_dio_iomap_begin() again, this time for the file  
   range \[128K, 256K), and locks the file range \[128K, 256K);  
  
6) Task B starts a direct IO write against file range \[0, 256K) as well.  
   It also locks the inode in shared mode, as it's within the i_size limit,  
   and then tries to lock file range \[0, 256K). It is able to lock the  
   subrange \[0, 128K) but then blocks waiting for the range \[128K, 256K),  
   as it is currently locked by task A;  
  
7) Task A enters btrfs_get_blocks_direct_write() and tries to reserve data  
   space. Because we are low on available free space, it triggers the  
   async data reclaim task, and waits for it to reserve data space;  
  
8) The async reclaim task decides to wait for all existing ordered extents  
   to complete (through btrfs_wait_ordered_roots()).  
   It finds the ordered extent previously created by task A for the file  
   range \[0, 128K) and waits for it to complete;  
  
9) The ordered extent for the file range \[0, 128K) can not complete  
   because it blocks at btrfs_finish_ordered_io() when trying to lock the  
   file range \[0, 128K).  
  
   This results in a deadlock, because:  
  
   - task B is holding the file range \[0, 128K) locked, waiting for the  
     range \[128K, 256K) to be unlocked by task A;  
  
   - task A is holding the file range \[128K, 256K) locked and it's waiting  
     for the async data reclaim task to satisfy its space reservation  
     request;  
  
   - the async data reclaim task is waiting for ordered extent \[0, 128K)  
     to complete, but the ordered extent can not complete because the  
     file range \[0, 128K) is currently locked by task B, which is waiting  
     on task A to unlock file range \[128K, 256K) and task A waiting  
     on the async data reclaim task.  
  
   This results in a deadlock between 4 task: task A, task B, the async  
   data reclaim task and the task doing ordered extent completion (a work  
   queue task).  
  
This type of deadlock can sporadically be triggered by the test case  
generic/300 from fstests, and results in a stack trace like the following:  
  
\[12084.033689\] INFO: task kworker/u16:7:123749 blocked for more than 241 seconds.  
\[12084.034877\]       Not tainted 5.18.0-rc2-btrfs-next-115 #1  
\[12084.035562\] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.  
\[12084.036548\] task:kworker/u16:7   state:D stack:    0 pid:123749 ppid:     2 flags:0x00004000  
\[12084.036554\] Workqueue: btrfs-flush_delalloc btrfs_work_helper \[btrfs\]  
\[12084.036599\] Call Trace:  
\[12084.036601\]  <TASK>  
\[12084.036606\]  __schedule+0x3cb/0xed0  
\[12084.036616\]  schedule+0x4e/0xb0  
\[12084.036620\]  btrfs_start_ordered_extent+0x109/0x1c0 \[btrfs\]  
\[12084.036651\]  ? prepare_to_wait_exclusive+0xc0/0xc0  
\[12084.036659\]  btrfs_run_ordered_extent_work+0x1a/0x30 \[btrfs\]  
\[12084.036688\]  btrfs_work_helper+0xf8/0x400 \[btrfs\]  
\[12084.0367  
---truncated---" (Similarity: 57)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 7)
- **Description**: The code checks for integer overflows when calculating the size of the mapping using \`pgoff + (len >> PAGE_SHIFT) < pgoff\`. While this check is present, it's only performed \*after\* \`len\` has already been right-shifted by \`PAGE_SHIFT\`. If \`len\` is sufficiently large (close to the maximum value of its data type) but less than \`pgoff << PAGE_SHIFT\`, then the right shift can wrap around to a small value, potentially passing the overflow check.  However, the actual calculation \`pgoff + (len >> PAGE_SHIFT)\` could still result in a value larger than allowed, leading to unexpected behavior. If this result is used as the number of pages, an integer overflow could allow allocating far fewer pages than the application expects, which may result in out-of-bounds memory access when the application tries to write to the supposedly reserved range, potentially leading to a crash or more severe issues like privilege escalation if the mapped memory region overlaps critical kernel data structures.
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
- CVE-2025-21724: "In the Linux kernel, the following vulnerability has been resolved:  
  
iommufd/iova_bitmap: Fix shift-out-of-bounds in iova_bitmap_offset_to_index()  
  
Resolve a UBSAN shift-out-of-bounds issue in iova_bitmap_offset_to_index()  
where shifting the constant "1" (of type int) by bitmap->mapped.pgshift  
(an unsigned long value) could result in undefined behavior.  
  
The constant "1" defaults to a 32-bit "int", and when "pgshift" exceeds  
31 (e.g., pgshift = 63) the shift operation overflows, as the result  
cannot be represented in a 32-bit type.  
  
To resolve this, the constant is updated to "1UL", promoting it to an  
unsigned long type to match the operand's type." (Similarity: 50)
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
element is part of an unmapped page." (Similarity: 49)


#### CWE-400: Uncontrolled Resource Consumption (Exploitability: 7)
- **Description**: The code checks for resource limits (RLIMIT_NPROC) and thread limits (nr_threads >= max_threads) before creating a new process. However, the check for \`nr_threads >= max_threads\` uses \`data_race\`, which indicates that the \`nr_threads\` variable might be accessed concurrently without proper synchronization.  If \`nr_threads\` increments between the check and the actual process creation, the \`nr_threads\` can exceed the \`max_threads\` limit, potentially leading to a denial-of-service by exhausting system resources. The code uses \`data_race\` which detects if the variable has been accessed using inconsistent locking, making the \`nr_threads >= max_threads\` check unreliable. A malicious actor can potentially bypass this check by exploiting the race condition, leading to more processes being created than the intended limit.
- **Location**: Line containing \`data_race(nr_threads >= max_threads)\`
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
- CVE-2022-49578: "In the Linux kernel, the following vulnerability has been resolved:  
  
ip: Fix data-races around sysctl_ip_prot_sock.  
  
sysctl_ip_prot_sock is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing." (Similarity: 55)
- CVE-2022-49634: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data-races in proc_dou8vec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_dou8vec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_dou8vec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 54)
- CVE-2022-49640: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data races in proc_douintvec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_douintvec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_douintvec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 53)


#### CWE-787: Out-of-bounds Write (Exploitability: 8)
- **Description**: The code in \`skb_try_coalesce\` attempts to coalesce two \`sk_buff\` structures. When the \`from\` sk_buff's head data is non-zero, it's added as a fragment to the \`to\` sk_buff. However, a check is performed to ensure the number of fragments in the \`to\` sk_buff plus the number of fragments in the \`from\` sk_buff does not exceed \`MAX_SKB_FRAGS\`. The crucial part is that \`from_shinfo->nr_frags\` is used, but later, the code copies only the head portion of 'from' as a fragment, independent of any other fragments 'from' may have had. This means that \`from_shinfo->nr_frags\` might be greater than zero, but the head of 'from' is still copied to 'to', possibly exceeding \`MAX_SKB_FRAGS\` fragments on \`to\`. This can lead to an out-of-bounds write when the \`skb_fill_page_desc\` function writes beyond the allocated space for fragments in the \`to\` sk_buff's shared info structure (\`skb_shared_info\`).
- **Location**: Line containing \`skb_fill_page_desc\` within \`skb_try_coalesce\`
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
able to reproduce this issue." (Similarity: 55)
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
There is no need to distinguish over-32KB and over-KMALLOC_MAX_SIZE." (Similarity: 52)
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
the macro definition CONFIG_BPF_JIT_ALWAYS_ON." (Similarity: 51)


#### CWE-NVD: No Known Vulnerabilities (Exploitability: 1)
- **Description**: The provided code snippet defines data structures related to slab allocation. Without any actual allocation, deallocation, or data manipulation routines, no exploitable vulnerability can be identified.
- **Location**: N/A
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
- CVE-2025-21804: "In the Linux kernel, the following vulnerability has been resolved:  
  
PCI: rcar-ep: Fix incorrect variable used when calling devm_request_mem_region()  
  
The rcar_pcie_parse_outbound_ranges() uses the devm_request_mem_region()  
macro to request a needed resource. A string variable that lives on the  
stack is then used to store a dynamically computed resource name, which  
is then passed on as one of the macro arguments. This can lead to  
undefined behavior.  
  
Depending on the current contents of the memory, the manifestations of  
errors may vary. One possible output may be as follows:  
  
  $ cat /proc/iomem  
  30000000-37ffffff :  
  38000000-3fffffff :  
  
Sometimes, garbage may appear after the colon.  
  
In very rare cases, if no NULL-terminator is found in memory, the system  
might crash because the string iterator will overrun which can lead to  
access of unmapped memory above the stack.  
  
Thus, fix this by replacing outbound_name with the name of the previously  
requested resource. With the changes applied, the output will be as  
follows:  
  
  $ cat /proc/iomem  
  30000000-37ffffff : memory2  
  38000000-3fffffff : memory3  
  
\[kwilczynski: commit log\]" (Similarity: 58)
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
    directly handle all the string termination logic." (Similarity: 55)
- CVE-2025-22055: "In the Linux kernel, the following vulnerability has been resolved:  
  
net: fix geneve_opt length integer overflow  
  
struct geneve_opt uses 5 bit length for each single option, which  
means every vary size option should be smaller than 128 bytes.  
  
However, all current related Netlink policies cannot promise this  
length condition and the attacker can exploit a exact 128-byte size  
option to \*fake\* a zero length option and confuse the parsing logic,  
further achieve heap out-of-bounds read.  
  
One example crash log is like below:  
  
\[    3.905425\] ==================================================================  
\[    3.905925\] BUG: KASAN: slab-out-of-bounds in nla_put+0xa9/0xe0  
\[    3.906255\] Read of size 124 at addr ffff888005f291cc by task poc/177  
\[    3.906646\]  
\[    3.906775\] CPU: 0 PID: 177 Comm: poc-oob-read Not tainted 6.1.132 #1  
\[    3.907131\] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014  
\[    3.907784\] Call Trace:  
\[    3.907925\]  <TASK>  
\[    3.908048\]  dump_stack_lvl+0x44/0x5c  
\[    3.908258\]  print_report+0x184/0x4be  
\[    3.909151\]  kasan_report+0xc5/0x100  
\[    3.909539\]  kasan_check_range+0xf3/0x1a0  
\[    3.909794\]  memcpy+0x1f/0x60  
\[    3.909968\]  nla_put+0xa9/0xe0  
\[    3.910147\]  tunnel_key_dump+0x945/0xba0  
\[    3.911536\]  tcf_action_dump_1+0x1c1/0x340  
\[    3.912436\]  tcf_action_dump+0x101/0x180  
\[    3.912689\]  tcf_exts_dump+0x164/0x1e0  
\[    3.912905\]  fw_dump+0x18b/0x2d0  
\[    3.913483\]  tcf_fill_node+0x2ee/0x460  
\[    3.914778\]  tfilter_notify+0xf4/0x180  
\[    3.915208\]  tc_new_tfilter+0xd51/0x10d0  
\[    3.918615\]  rtnetlink_rcv_msg+0x4a2/0x560  
\[    3.919118\]  netlink_rcv_skb+0xcd/0x200  
\[    3.919787\]  netlink_unicast+0x395/0x530  
\[    3.921032\]  netlink_sendmsg+0x3d0/0x6d0  
\[    3.921987\]  __sock_sendmsg+0x99/0xa0  
\[    3.922220\]  __sys_sendto+0x1b7/0x240  
\[    3.922682\]  __x64_sys_sendto+0x72/0x90  
\[    3.922906\]  do_syscall_64+0x5e/0x90  
\[    3.923814\]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8  
\[    3.924122\] RIP: 0033:0x7e83eab84407  
\[    3.924331\] Code: 48 89 fa 4c 89 df e8 38 aa 00 00 8b 93 08 03 00 00 59 5e 48 83 f8 fc 74 1a 5b c3 0f 1f 84 00 00 00 00 00 48 8b 44 24 10 0f 05 <5b> c3 0f 1f 80 00 00 00 00 83 e2 39 83 faf  
\[    3.925330\] RSP: 002b:00007ffff505e370 EFLAGS: 00000202 ORIG_RAX: 000000000000002c  
\[    3.925752\] RAX: ffffffffffffffda RBX: 00007e83eaafa740 RCX: 00007e83eab84407  
\[    3.926173\] RDX: 00000000000001a8 RSI: 00007ffff505e3c0 RDI: 0000000000000003  
\[    3.926587\] RBP: 00007ffff505f460 R08: 00007e83eace1000 R09: 000000000000000c  
\[    3.926977\] R10: 0000000000000000 R11: 0000000000000202 R12: 00007ffff505f3c0  
\[    3.927367\] R13: 00007ffff505f5c8 R14: 00007e83ead1b000 R15: 00005d4fbbe6dcb8  
  
Fix these issues by enforing correct length condition in related  
policies." (Similarity: 54)


#### CWE-269: Improper Privilege Management (Exploitability: 7)
- **Description**: The \`__sys_setresuid\` function allows a process to set its real, effective, and saved user IDs. The vulnerability lies in the conditional check at line 1135: \`if ((ruid_new || euid_new || suid_new) && !ns_capable_setid(old->user_ns, CAP_SETUID))\`. This check verifies if the process has the \`CAP_SETUID\` capability within its user namespace if \*any\* of the RUID, EUID, or SUID are being changed to a value different from the current effective IDs.  However, it does \*not\* properly validate if the user is setting the IDs to \*another\* value it already possesses (e.g., setting RUID to current EUID, EUID to current SUID, etc.). An unprivileged user within a user namespace might be able to manipulate its RUID, EUID, and SUID to values it already possesses if it currently has at least one of them. This is because the individual checks prior to this block merely check for valid user IDs and avoid no-ops but do not prevent this specific manipulation, which could lead to bypassing privilege checks later on. For example, a process could potentially gain more permissions than it should have within the user namespace. The impact is privilege escalation within the user namespace.
- **Location**: Line 1135
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
  
This api should stop to exist though." (Similarity: 51)
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
- CVE-2023-52987: "In the Linux kernel, the following vulnerability has been resolved:  
  
ASoC: SOF: ipc4-mtrace: prevent underflow in sof_ipc4_priority_mask_dfs_write()  
  
The "id" comes from the user.  Change the type to unsigned to prevent  
an array underflow." (Similarity: 46)


## 🛠️ Patch Reports

### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
- **Kernel Version**: N/A
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
--- a/fs/ext4/inode.c  
+++ b/fs/ext4/inode.c  
@@ -5824,6 +5824,12 @@  
             (oldsize > 0 ? oldsize - 1 : oldsize) >>  
             inode->i_sb->s_blocksize_bits,  
             (attr->ia_size > 0 ? attr->ia_size - 1 : 0) >>  
+            inode->i_sb->s_blocksize_bits);  
+  
+    if (attr->ia_size > EXT4_MAX_I_SIZE) {  
+        error = -EFBIG;  
+        goto out_journal_stop;  
+    }  
   
     down_write(&EXT4_I(inode)->i_data_sem);  
     old_disksize = EXT4_I(inode)->i_disksize;  
@@ -5842,6 +5848,10 @@  
     if (error)  
         goto out_mmap_sem;  
     if (!shrink) {  
+out_journal_stop:  
+        up_write(&EXT4_I(inode)->i_data_sem);  
+        ext4_journal_stop(handle);  
+        EXT4_I(inode)->i_disksize = old_disksize;  
         pagecache_isize_extended(inode, oldsize,  
                                  inode->i_size);  
     } else if (ext4_should_journal_data(inode)) {  
  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code modifies \`EXT4_I(inode)->i_disksize\` to \`attr->ia_size\` without validating \`attr->ia_size\` against a maximum allowable size before acquiring the i_data_sem semaphore. A large \`attr->ia_size\` can cause an out-of-bounds write or other unpredictable behavior later during block allocation or inode updates.  
  
The patch adds a check to ensure that \`attr->ia_size\` is not greater than \`EXT4_MAX_I_SIZE\` before assigning it to \`EXT4_I(inode)->i_disksize\`.  \`EXT4_MAX_I_SIZE\` (or a similar appropriate maximum size) is a constant representing the maximum allowable size for an inode in the ext4 filesystem. If \`attr->ia_size\` exceeds this limit, the patch sets \`error\` to \`-EFBIG\` (File too big) and jumps to \`out_journal_stop\` to revert the journal start and unlock i_data_sem.  
  
This patch resolves the vulnerability by preventing the assignment of excessively large sizes to \`i_disksize\`, guarding against potential out-of-bounds writes or integer overflows.  
  
The patch maintains the code's functionality by allowing the size change only if it is within the acceptable bounds. If the size is too large, it returns an error, indicating that the requested size change is not possible and reverts any started journal.  
  
A trade-off is that the patch introduces a size limitation, but this limitation is necessary to ensure the integrity and stability of the filesystem.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)
- [CVE-2024-58085](https://git.kernel.org/stable/c/3df7546fc03b8f004eee0b9e3256369f7d096685)
- [CVE-2022-49547](https://git.kernel.org/stable/c/cfae6f765b3c40882ee90dae8fbf9325c8de9c35)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: N/A
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
\`\`\`c  
+#include <linux/kernel.h>  // Include for max macro  
  
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
  
+ // Check for potential overflow before the shift.  This is important  
+ // because len >> PAGE_SHIFT could wrap around and become smaller  
+ // than expected, bypassing the original overflow check.  
+ if (len > div_u64(ULLONG_MAX - pgoff, PAGE_SIZE))  
+   return -EOVERFLOW;  
  
if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)  
    return -EOVERFLOW;  
  
  
if (mm->map_count > sysctl_max_map_count)  
    return -ENOMEM;  
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code checks for integer overflow \*after\* right-shifting \`len\` by \`PAGE_SHIFT\`. As described in the CWE analysis, this check can be bypassed if \`len\` is a large value close to its maximum, causing the right shift to wrap around to a small value.  
  
The patch introduces a check \*before\* the right shift to prevent this. The \`div_u64\` function divides \`ULLONG_MAX - pgoff\` by \`PAGE_SIZE\`.  If \`len\` is greater than the result of this division, then \`pgoff + (len >> PAGE_SHIFT)\` would result in an overflow (or wrap around if unsigned), leading to incorrect calculations and a potential security vulnerability. Thus, this condition is rejected.  
  
This approach resolves the vulnerability by performing the overflow check with \`len\` before it's modified by the right shift. It maintains the code's functionality by only adding a pre-check, ensuring the intended behavior of the original overflow check is preserved while preventing the exploitable wrap-around scenario.  
  
The inclusion of \`<linux/kernel.h>\` is important to define \`ULLONG_MAX\`, ensuring that the calculations work correctly across different architectures and compiler settings. We use \`div_u64\` to safely divide a 64 bit number by a value of type \`unsigned long\`.  
  
\*\*Trade-offs and Considerations:\*\*  
  
\*   The added check introduces a slight performance overhead. However, it is generally acceptable given the security implications of the original vulnerability.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-21724](https://git.kernel.org/stable/c/38ac76fc06bc6826a3e4b12a98efbe98432380a9)
- [CVE-2025-22107](https://git.kernel.org/stable/c/59b97641de03c081f26b3a8876628c765b5faa25)


### Patch 
- **CWE**: CWE-400: Uncontrolled Resource Consumption
- **Kernel Version**: N/A
- **Patch Details**:
```diff
\`\`\`c  
/\*  
 \* Atomically increment the thread count and check if it exceeds the limit.  
 \*/  
static inline bool threads_exceeded(struct task_struct \*p)  
{  
    struct user_struct \*user = p->real_cred->user;  
    unsigned int max_threads = user->max_threads;  
    unsigned int nr_threads;  
  
    /\*  
     \* Atomically increment the thread count. If it exceeds the limit,  
     \* decrement it and return true. Otherwise, return false.  
     \*/  
    nr_threads = atomic_inc_return(&user->processes);  
    if (unlikely(nr_threads > max_threads)) {  
        atomic_dec(&user->processes);  
        return true;  
    }  
    return false;  
}  
  
  
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
if (threads_exceeded(p))  
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
  
The original code used \`data_race(nr_threads >= max_threads)\` to check the thread limit, which is susceptible to race conditions because \`nr_threads\` can be incremented concurrently by other threads.  The fix replaces the \`data_race\` with an atomic increment operation using \`atomic_inc_return\` on \`user->processes\`, which is then checked against \`max_threads\`.  
  
1.  \*\*Resolves the vulnerability:\*\* The \`threads_exceeded\` function atomically increments the \`user->processes\` counter and checks if the new value exceeds \`max_threads\`. If it does, the counter is decremented, and the function returns \`true\`, indicating that the limit has been exceeded and preventing process creation. This eliminates the race condition where \`nr_threads\` could be incremented after the check, leading to a bypass of the thread limit.  \`user->processes\` should be atomically accessed when checking or changing the value.  
  
2.  \*\*Maintains code functionality:\*\* The patch ensures that the thread limit is still enforced. It introduces a utility function, \`threads_exceeded\` for better code readability. This function performs an atomic increment and checks if the limit has been exceeded, returning an appropriate boolean. This replaces the racy read of \`nr_threads\` with an atomic increment and comparison.  
  
3.  \*\*Trade-offs and considerations:\*\* The patch introduces an atomic operation, which can be slightly more expensive than a regular read. However, the performance impact is minimal compared to the security benefits of preventing a denial-of-service attack. It assumes \`user->processes\` is an atomic variable. If it isn't, that also needs to be fixed. Also, error handling must involve decrementing the process count, to account for failed process creation.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2022-49578](https://git.kernel.org/stable/c/95724fe897a4ecf2be51452ef96e818568071664)
- [CVE-2022-49634](https://git.kernel.org/stable/c/5f776daef0b5354615ec4b4234cd9539ca05f273)
- [CVE-2022-49640](https://git.kernel.org/stable/c/2d3b559df3ed39258737789aae2ae7973d205bc1)


### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
- **Kernel Version**: N/A
- **Patch Details**:
```diff
\`\`\`  
- Patch Code:  
\`\`\`c  
--- a/net/core/skbuff.c  
+++ b/net/core/skbuff.c  
@@ -4572,8 +4572,7 @@  
         struct page \*page;  
         unsigned int offset;  
   
-        if (to_shinfo->nr_frags +  
-            from_shinfo->nr_frags >= MAX_SKB_FRAGS)  
+        if (to_shinfo->nr_frags >= MAX_SKB_FRAGS)  
             return false;  
   
         if (skb_head_is_locked(from))  
\`\`\`  
  
- Reasoning:  
The original code checks if \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\` before adding a fragment from 'from' to 'to'. However, only the head portion of 'from' is being added as a fragment to 'to' in this code block. The number of fragments in 'from' should not influence this condition because we are only adding one fragment to 'to' (the head of 'from'). The check should only consider if adding one more fragment to 'to' exceeds the \`MAX_SKB_FRAGS\` limit. Therefore, the condition is changed to \`to_shinfo->nr_frags >= MAX_SKB_FRAGS\`. This prevents an out-of-bounds write by ensuring that the number of fragments in 'to' never exceeds \`MAX_SKB_FRAGS\` when adding the head of 'from' as a fragment. This patch correctly restricts the fragment addition operation to not exceed the maximum number of allowed fragments. The functionality is maintained by ensuring coalescence is still attempted if the target skb has enough space for a new fragment. There are no noticeable trade-offs.  
  
- Patch Links:  
None  

```
- **CVE Patch Links**:
- [CVE-2025-21961](https://git.kernel.org/stable/c/19107e71be330dbccb9f8f9f4cf0a9abeadad802)
- [CVE-2024-58085](https://git.kernel.org/stable/c/3df7546fc03b8f004eee0b9e3256369f7d096685)
- [CVE-2025-22087](https://git.kernel.org/stable/c/19e6817f84000d0b06f09fd69ebd56217842c122)


### Patch 
- **CWE**: CWE-NVD: No Known Vulnerabilities
- **Kernel Version**: N/A
- **Patch Details**:
```diff
Based on the CWE analysis indicating no immediately exploitable vulnerability in the provided code, I cannot provide a patch. The code only defines data structures, and without usage context (allocation, deallocation, data manipulation), it's impossible to identify a specific flaw.  
  
- Patch Code:  
\`\`\`c  
// No patch applicable.  The provided code snippet doesn't contain a vulnerability.  
\`\`\`  
- Reasoning: The analysis identifies no vulnerabilities in the presented code. There are no operations that can lead to buffer overflows, use-after-free, or other exploitable conditions. It's just a definition of data structures.  
- Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2025-21804](https://git.kernel.org/stable/c/24576899c49509c0d533bcf569139f691d8f7af7)
- [CVE-2025-22003](https://git.kernel.org/stable/c/1d22a122ffb116c3cf78053e812b8b21f8852ee9)
- [CVE-2025-22055](https://git.kernel.org/stable/c/21748669c5825761cbbf47cbeeb01387ddccc8cb)


### Patch 
- **CWE**: CWE-269: Improper Privilege Management
- **Kernel Version**: N/A
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
    euid_new = euid != (uid_t) -1 && !(uid_eq(keuid, old->euid) && uid_eq(keuid, old->fsuid));  
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
  
The original code's vulnerability lies in how \`ruid_new\`, \`euid_new\`, and \`suid_new\` were calculated. The original calculation checked if the new UID was different from \*all\* existing UIDs (uid, euid, and suid) before requiring \`CAP_SETUID\`. This allowed an unprivileged user to set these IDs to each other, effectively rotating existing IDs without needing \`CAP_SETUID\`.  
  
The patch modifies the calculation of \`ruid_new\`, \`euid_new\`, and \`suid_new\` to more accurately reflect whether a \*new\* ID is being set. Specifically:  
  
\*   \`ruid_new\` is now simply checking if the passed ruid is different from the current uid.  
\*   \`euid_new\` now only checks if the passed euid is different from the current euid and fsuid. The fsuid is also important to check, as it is often equivalent to euid.  
\*   \`suid_new\` is now simply checking if the passed suid is different from the current suid.  
  
This ensures that if any of the IDs are being \*changed\* to a value they don't already possess (either uid, euid, or suid), the check for \`CAP_SETUID\` will correctly trigger, preventing the privilege escalation.  
  
Functionality is maintained by ensuring that valid UID changes still function correctly when the process possesses \`CAP_SETUID\`. The check for \`(ruid == (uid_t) -1 || uid_eq(kruid, old->uid)) && ...\` at the beginning still prevents no-op calls. The fundamental operation of setting user IDs remains the same, with the patch only correcting the privilege check.  
  
There are no significant trade-offs introduced by this patch. It tightens the security around \`setresuid\` calls within user namespaces to align with the intended privilege model.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-21846](https://git.kernel.org/stable/c/56d5f3eba3f5de0efdd556de4ef381e109b973a9)
- [CVE-2025-22029](https://git.kernel.org/stable/c/753a620a7f8e134b444f89fe90873234e894e21a)
- [CVE-2023-52987](https://git.kernel.org/stable/c/d52f34784e4e2f6e77671a9f104d8a69a3b5d24c)


## 📊 Summary
- **Agent**: Agent 1
- **LTP Tests**: 6
- **CWE Issues**: 7
- **Patches**: 6

### LTP Results Breakdown
- Flaw Detected: 2 (\#ef4444)
- Safe: 4 (\#22c55e)
