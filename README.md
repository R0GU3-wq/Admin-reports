# Admin-reports


# CWE Report for Test 1

**Kernel Version:** 6.15

## Original Code
```c
if (attr->ia_size != inode->i_size) {  // Line 5800
    /* attach jbd2 jinode for EOF folio tail zeroing */
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

## CWE Analysis
- **CWE**: CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- **Description**: The code modifies the inode size (i_size and i_disksize) under certain conditions related to file truncation or extension. The `ext4_fc_track_range` function is called to track the range of blocks being modified. If the `attr->ia_size` or `oldsize` are significantly large, or if there are a huge number of changes to file size, the `ext4_fc_track_range` function could consume excessive memory or CPU resources. Although not immediately apparent from the code snippet alone, the function `ext4_fc_track_range` may contribute to resource exhaustion by triggering excessive metadata updates or by allocating a huge number of bitmaps which eventually leads to denial of service. An attacker could repeatedly trigger operations leading to this code path, such as frequent and significant changes to the size of files (especially through truncate operations), to exhaust system resources.
- **Location**: Line 5818 and 5823. `ext4_fc_track_range`
- **Exploitability**: 6/10

## Matched CVEs
- **CVE-2025-37785** (Similarity: 54%)
  - Description: In the Linux kernel, the following vulnerability has been resolved:

ext4: fix OOB read when checking dotdot dir

Mounting a corrupted filesystem with directory which contains '.' dir
entry with rec_len == block size results in out-of-bounds read (later
on, when the corrupted directory is removed).

ext4_empty_dir() assumes every ext4 directory contains at least '.'
and '..' as directory entries in the first data block. It first loads
the '.' dir entry, performs sanity checks by calling ext4_check_dir_entry()
and then uses its rec_len member to compute the location of '..' dir
entry (in ext4_next_entry). It assumes the '..' dir entry fits into the
same data block.

If the rec_len of '.' is precisely one block (4KB), it slips through the
sanity checks (it is considered the last directory entry in the data
block) and leaves "struct ext4_dir_entry_2 *de" point exactly past the
memory slot allocated to the data block. The following call to
ext4_check_dir_entry() on new value of de then dereferences this pointer
which results in out-of-bounds mem access.

Fix this by extending __ext4_check_dir_entry() to check for '.' dir
entries that reach the end of data block. Make sure to ignore the phony
dir entries for checksum (by checking name_len for non-zero).

Note: This is reported by KASAN as use-after-free in case another
structure was recently freed from the slot past the bound, but it is
really an OOB read.

This issue was found by syzkaller tool.

Call Trace:
[   38.594108] BUG: KASAN: slab-use-after-free in __ext4_check_dir_entry+0x67e/0x710
[   38.594649] Read of size 2 at addr ffff88802b41a004 by task syz-executor/5375
[   38.595158]
[   38.595288] CPU: 0 UID: 0 PID: 5375 Comm: syz-executor Not tainted 6.14.0-rc7 #1
[   38.595298] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
[   38.595304] Call Trace:
[   38.595308]  <TASK>
[   38.595311]  dump_stack_lvl+0xa7/0xd0
[   38.595325]  print_address_description.constprop.0+0x2c/0x3f0
[   38.595339]  ? __ext4_check_dir_entry+0x67e/0x710
[   38.595349]  print_report+0xaa/0x250
[   38.595359]  ? __ext4_check_dir_entry+0x67e/0x710
[   38.595368]  ? kasan_addr_to_slab+0x9/0x90
[   38.595378]  kasan_report+0xab/0xe0
[   38.595389]  ? __ext4_check_dir_entry+0x67e/0x710
[   38.595400]  __ext4_check_dir_entry+0x67e/0x710
[   38.595410]  ext4_empty_dir+0x465/0x990
[   38.595421]  ? __pfx_ext4_empty_dir+0x10/0x10
[   38.595432]  ext4_rmdir.part.0+0x29a/0xd10
[   38.595441]  ? __dquot_initialize+0x2a7/0xbf0
[   38.595455]  ? __pfx_ext4_rmdir.part.0+0x10/0x10
[   38.595464]  ? __pfx___dquot_initialize+0x10/0x10
[   38.595478]  ? down_write+0xdb/0x140
[   38.595487]  ? __pfx_down_write+0x10/0x10
[   38.595497]  ext4_rmdir+0xee/0x140
[   38.595506]  vfs_rmdir+0x209/0x670
[   38.595517]  ? lookup_one_qstr_excl+0x3b/0x190
[   38.595529]  do_rmdir+0x363/0x3c0
[   38.595537]  ? __pfx_do_rmdir+0x10/0x10
[   38.595544]  ? strncpy_from_user+0x1ff/0x2e0
[   38.595561]  __x64_sys_unlinkat+0xf0/0x130
[   38.595570]  do_syscall_64+0x5b/0x180
[   38.595583]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
- **CVE-2025-39735** (Similarity: 54%)
  - Description: In the Linux kernel, the following vulnerability has been resolved:

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
			ch = ptr[j];
		...
	}

To fix this we should validate "EALIST_SIZE(ea_buf->xattr)"
before it is utilised.
- **CVE-2022-49409** (Similarity: 53%)
  - Description: In the Linux kernel, the following vulnerability has been resolved:

ext4: fix bug_on in __es_tree_search

Hulk Robot reported a BUG_ON:
==================================================================
kernel BUG at fs/ext4/extents_status.c:199!
[...]
RIP: 0010:ext4_es_end fs/ext4/extents_status.c:199 [inline]
RIP: 0010:__es_tree_search+0x1e0/0x260 fs/ext4/extents_status.c:217
[...]
Call Trace:
 ext4_es_cache_extent+0x109/0x340 fs/ext4/extents_status.c:766
 ext4_cache_extents+0x239/0x2e0 fs/ext4/extents.c:561
 ext4_find_extent+0x6b7/0xa20 fs/ext4/extents.c:964
 ext4_ext_map_blocks+0x16b/0x4b70 fs/ext4/extents.c:4384
 ext4_map_blocks+0xe26/0x19f0 fs/ext4/inode.c:567
 ext4_getblk+0x320/0x4c0 fs/ext4/inode.c:980
 ext4_bread+0x2d/0x170 fs/ext4/inode.c:1031
 ext4_quota_read+0x248/0x320 fs/ext4/super.c:6257
 v2_read_header+0x78/0x110 fs/quota/quota_v2.c:63
 v2_check_quota_file+0x76/0x230 fs/quota/quota_v2.c:82
 vfs_load_quota_inode+0x5d1/0x1530 fs/quota/dquot.c:2368
 dquot_enable+0x28a/0x330 fs/quota/dquot.c:2490
 ext4_quota_enable fs/ext4/super.c:6137 [inline]
 ext4_enable_quotas+0x5d7/0x960 fs/ext4/super.c:6163
 ext4_fill_super+0xa7c9/0xdc00 fs/ext4/super.c:4754
 mount_bdev+0x2e9/0x3b0 fs/super.c:1158
 mount_fs+0x4b/0x1e4 fs/super.c:1261
[...]
==================================================================

Above issue may happen as follows:
-------------------------------------
ext4_fill_super
 ext4_enable_quotas
  ext4_quota_enable
   ext4_iget
    __ext4_iget
     ext4_ext_check_inode
      ext4_ext_check
       __ext4_ext_check
        ext4_valid_extent_entries
         Check for overlapping extents does't take effect
   dquot_enable
    vfs_load_quota_inode
     v2_check_quota_file
      v2_read_header
       ext4_quota_read
        ext4_bread
         ext4_getblk
          ext4_map_blocks
           ext4_ext_map_blocks
            ext4_find_extent
             ext4_cache_extents
              ext4_es_cache_extent
               ext4_es_cache_extent
                __es_tree_search
                 ext4_es_end
                  BUG_ON(es->es_lblk + es->es_len < es->es_lblk)

The error ext4 extents is as follows:
0af3 0300 0400 0000 00000000    extent_header
00000000 0100 0000 12000000     extent1
00000000 0100 0000 18000000     extent2
02000000 0400 0000 14000000     extent3

In the ext4_valid_extent_entries function,
if prev is 0, no error is returned even if lblock<=prev.
This was intended to skip the check on the first extent, but
in the error image above, prev=0+1-1=0 when checking the second extent,
so even though lblock<=prev, the function does not return an error.
As a result, bug_ON occurs in __es_tree_search and the system panics.

To solve this problem, we only need to check that:
1. The lblock of the first extent is not less than 0.
2. The lblock of the next extent  is not less than
   the next block of the previous extent.
The same applies to extent_idx.

