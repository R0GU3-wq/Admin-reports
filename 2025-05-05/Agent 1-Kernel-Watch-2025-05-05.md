
# Agent 1 Kernel Watch Report - 2025-05-05

## 🔍 Detection Results

### LTP Test Results

| Test | Result |
|------|--------|
| Filesystem Tests | Flaw Detected |
| Memory Management | Flaw Detected |
| Process Management | No Issues Found |
| Networking Tests | Flaw Detected |
| Device Drivers | No Issues Found |
| System Calls | No Issues Found |


### CWE Analysis

#### CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion') (Exploitability: 7)
- **Description**: The code modifies the file size using \`i_size_write(inode, attr->ia_size)\` (around line 5830). Although journaled, repeatedly shrinking and extending the file size (via \`attr->ia_size\`) can lead to excessive journal activity, metadata updates, and potentially trigger inode table expansion. If an attacker can control \`attr->ia_size\` they can repeatedly resize a file triggering excessive IO and CPU operations due to the journal writes. This could lead to a denial of service.
- **Location**: Line 5800 - 5834, especially calls involving \`attr->ia_size\`
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
- CVE-2024-58016: "In the Linux kernel, the following vulnerability has been resolved:  
  
safesetid: check size of policy writes  
  
syzbot attempts to write a buffer with a large size to a sysfs entry  
with writes handled by handle_policy_update(), triggering a warning  
in kmalloc.  
  
Check the size specified for write buffers before allocating.  
  
\[PM: subject tweak\]" (Similarity: 53)
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
before it is utilised." (Similarity: 52)
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
There is no need to distinguish over-32KB and over-KMALLOC_MAX_SIZE." (Similarity: 50)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 8)
- **Description**: The code checks for integer overflow in the calculation \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\`. While this check exists, it is insufficient. The \`len >> PAGE_SHIFT\` expression can still overflow if \`len\` is sufficiently large (close to the maximum value of the type). If this overflow occurs, the value of \`len >> PAGE_SHIFT\` will wrap around to a small number. Subsequently, the addition \`pgoff + (len >> PAGE_SHIFT)\` will result in a value that \*might\* be greater than or equal to \`pgoff\`, thus bypassing the intended overflow check. However, the small, wrapped value of \`len >> PAGE_SHIFT\` is then used later in memory allocation, potentially leading to allocating a much smaller memory region than intended. This can then cause buffer overflows if the code later attempts to write to the region as if it were of size \`len\`.
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
 </TASK>" (Similarity: 54)
- CVE-2024-58018: "In the Linux kernel, the following vulnerability has been resolved:  
  
nvkm: correctly calculate the available space of the GSP cmdq buffer  
  
r535_gsp_cmdq_push() waits for the available page in the GSP cmdq  
buffer when handling a large RPC request. When it sees at least one  
available page in the cmdq, it quits the waiting with the amount of  
free buffer pages in the queue.  
  
Unfortunately, it always takes the \[write pointer, buf_size) as  
available buffer pages before rolling back and wrongly calculates the  
size of the data should be copied. Thus, it can overwrite the RPC  
request that GSP is currently reading, which causes GSP hang due  
to corrupted RPC request:  
  
\[  549.209389\] ------------\[ cut here \]------------  
\[  549.214010\] WARNING: CPU: 8 PID: 6314 at drivers/gpu/drm/nouveau/nvkm/subdev/gsp/r535.c:116 r535_gsp_msgq_wait+0xd0/0x190 \[nvkm\]  
\[  549.225678\] Modules linked in: nvkm(E+) gsp_log(E) snd_seq_dummy(E) snd_hrtimer(E) snd_seq(E) snd_timer(E) snd_seq_device(E) snd(E) soundcore(E) rfkill(E) qrtr(E) vfat(E) fat(E) ipmi_ssif(E) amd_atl(E) intel_rapl_msr(E) intel_rapl_common(E) mlx5_ib(E) amd64_edac(E) edac_mce_amd(E) kvm_amd(E) ib_uverbs(E) kvm(E) ib_core(E) acpi_ipmi(E) ipmi_si(E) mxm_wmi(E) ipmi_devintf(E) rapl(E) i2c_piix4(E) wmi_bmof(E) joydev(E) ptdma(E) acpi_cpufreq(E) k10temp(E) pcspkr(E) ipmi_msghandler(E) xfs(E) libcrc32c(E) ast(E) i2c_algo_bit(E) crct10dif_pclmul(E) drm_shmem_helper(E) nvme_tcp(E) crc32_pclmul(E) ahci(E) drm_kms_helper(E) libahci(E) nvme_fabrics(E) crc32c_intel(E) nvme(E) cdc_ether(E) mlx5_core(E) nvme_core(E) usbnet(E) drm(E) libata(E) ccp(E) ghash_clmulni_intel(E) mii(E) t10_pi(E) mlxfw(E) sp5100_tco(E) psample(E) pci_hyperv_intf(E) wmi(E) dm_multipath(E) sunrpc(E) dm_mirror(E) dm_region_hash(E) dm_log(E) dm_mod(E) be2iscsi(E) bnx2i(E) cnic(E) uio(E) cxgb4i(E) cxgb4(E) tls(E) libcxgbi(E) libcxgb(E) qla4xxx(E)  
\[  549.225752\]  iscsi_boot_sysfs(E) iscsi_tcp(E) libiscsi_tcp(E) libiscsi(E) scsi_transport_iscsi(E) fuse(E) \[last unloaded: gsp_log(E)\]  
\[  549.326293\] CPU: 8 PID: 6314 Comm: insmod Tainted: G            E      6.9.0-rc6+ #1  
\[  549.334039\] Hardware name: ASRockRack 1U1G-MILAN/N/ROMED8-NL, BIOS L3.12E 09/06/2022  
\[  549.341781\] RIP: 0010:r535_gsp_msgq_wait+0xd0/0x190 \[nvkm\]  
\[  549.347343\] Code: 08 00 00 89 da c1 e2 0c 48 8d ac 11 00 10 00 00 48 8b 0c 24 48 85 c9 74 1f c1 e0 0c 4c 8d 6d 30 83 e8 30 89 01 e9 68 ff ff ff <0f> 0b 49 c7 c5 92 ff ff ff e9 5a ff ff ff ba ff ff ff ff be c0 0c  
\[  549.366090\] RSP: 0018:ffffacbccaaeb7d0 EFLAGS: 00010246  
\[  549.371315\] RAX: 0000000000000000 RBX: 0000000000000012 RCX: 0000000000923e28  
\[  549.378451\] RDX: 0000000000000000 RSI: 0000000055555554 RDI: ffffacbccaaeb730  
\[  549.385590\] RBP: 0000000000000001 R08: ffff8bd14d235f70 R09: ffff8bd14d235f70  
\[  549.392721\] R10: 0000000000000002 R11: ffff8bd14d233864 R12: 0000000000000020  
\[  549.399854\] R13: ffffacbccaaeb818 R14: 0000000000000020 R15: ffff8bb298c67000  
\[  549.406988\] FS:  00007f5179244740(0000) GS:ffff8bd14d200000(0000) knlGS:0000000000000000  
\[  549.415076\] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033  
\[  549.420829\] CR2: 00007fa844000010 CR3: 00000001567dc005 CR4: 0000000000770ef0  
\[  549.427963\] PKRU: 55555554  
\[  549.430672\] Call Trace:  
\[  549.433126\]  <TASK>  
\[  549.435233\]  ? __warn+0x7f/0x130  
\[  549.438473\]  ? r535_gsp_msgq_wait+0xd0/0x190 \[nvkm\]  
\[  549.443426\]  ? report_bug+0x18a/0x1a0  
\[  549.447098\]  ? handle_bug+0x3c/0x70  
\[  549.450589\]  ? exc_invalid_op+0x14/0x70  
\[  549.454430\]  ? asm_exc_invalid_op+0x16/0x20  
\[  549.458619\]  ? r535_gsp_msgq_wait+0xd0/0x190 \[nvkm\]  
\[  549.463565\]  r535_gsp_msg_recv+0x46/0x230 \[nvkm\]  
\[  549.468257\]  r535_gsp_rpc_push+0x106/0x160 \[nvkm\]  
\[  549.473033\]  r535_gsp_rpc_rm_ctrl_push+0x40/0x130 \[nvkm\]  
\[  549.478422\]  nvidia_grid_init_vgpu_types+0xbc/0xe0 \[nvkm\]  
\[  549.483899\]  nvidia_grid_init+0xb1/0xd0 \[nvkm\]  
\[  549.488420\]  ? srso_alias_return_thunk+0x5/0xfbef5  
\[  549.493213\]  nvkm_device_pci_probe+0x305/0x420 \[nvkm\]  
\[  549.498338\]  local_pci_probe+0x46/  
---truncated---" (Similarity: 53)
- CVE-2024-58019: "In the Linux kernel, the following vulnerability has been resolved:  
  
nvkm/gsp: correctly advance the read pointer of GSP message queue  
  
A GSP event message consists three parts: message header, RPC header,  
message body. GSP calculates the number of pages to write from the  
total size of a GSP message. This behavior can be observed from the  
movement of the write pointer.  
  
However, nvkm takes only the size of RPC header and message body as  
the message size when advancing the read pointer. When handling a  
two-page GSP message in the non rollback case, It wrongly takes the  
message body of the previous message as the message header of the next  
message. As the "message length" tends to be zero, in the calculation of  
size needs to be copied (0 - size of (message header)), the size needs to  
be copied will be "0xffffffxx". It also triggers a kernel panic due to a  
NULL pointer error.  
  
\[  547.614102\] msg: 00000f90: ff ff ff ff ff ff ff ff 40 d7 18 fb 8b 00 00 00  ........@.......  
\[  547.622533\] msg: 00000fa0: 00 00 00 00 ff ff ff ff ff ff ff ff 00 00 00 00  ................  
\[  547.630965\] msg: 00000fb0: ff ff ff ff ff ff ff ff 00 00 00 00 ff ff ff ff  ................  
\[  547.639397\] msg: 00000fc0: ff ff ff ff 00 00 00 00 ff ff ff ff ff ff ff ff  ................  
\[  547.647832\] nvkm 0000:c1:00.0: gsp: peek msg rpc fn:0 len:0x0/0xffffffffffffffe0  
\[  547.655225\] nvkm 0000:c1:00.0: gsp: get msg rpc fn:0 len:0x0/0xffffffffffffffe0  
\[  547.662532\] BUG: kernel NULL pointer dereference, address: 0000000000000020  
\[  547.669485\] #PF: supervisor read access in kernel mode  
\[  547.674624\] #PF: error_code(0x0000) - not-present page  
\[  547.679755\] PGD 0 P4D 0  
\[  547.682294\] Oops: 0000 \[#1\] PREEMPT SMP NOPTI  
\[  547.686643\] CPU: 22 PID: 322 Comm: kworker/22:1 Tainted: G            E      6.9.0-rc6+ #1  
\[  547.694893\] Hardware name: ASRockRack 1U1G-MILAN/N/ROMED8-NL, BIOS L3.12E 09/06/2022  
\[  547.702626\] Workqueue: events r535_gsp_msgq_work \[nvkm\]  
\[  547.707921\] RIP: 0010:r535_gsp_msg_recv+0x87/0x230 \[nvkm\]  
\[  547.713375\] Code: 00 8b 70 08 48 89 e1 31 d2 4c 89 f7 e8 12 f5 ff ff 48 89 c5 48 85 c0 0f 84 cf 00 00 00 48 81 fd 00 f0 ff ff 0f 87 c4 00 00 00 <8b> 55 10 41 8b 46 30 85 d2 0f 85 f6 00 00 00 83 f8 04 76 10 ba 05  
\[  547.732119\] RSP: 0018:ffffabe440f87e10 EFLAGS: 00010203  
\[  547.737335\] RAX: 0000000000000010 RBX: 0000000000000008 RCX: 000000000000003f  
\[  547.744461\] RDX: 0000000000000000 RSI: ffffabe4480a8030 RDI: 0000000000000010  
\[  547.751585\] RBP: 0000000000000010 R08: 0000000000000000 R09: ffffabe440f87bb0  
\[  547.758707\] R10: ffffabe440f87dc8 R11: 0000000000000010 R12: 0000000000000000  
\[  547.765834\] R13: 0000000000000000 R14: ffff9351df1e5000 R15: 0000000000000000  
\[  547.772958\] FS:  0000000000000000(0000) GS:ffff93708eb00000(0000) knlGS:0000000000000000  
\[  547.781035\] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033  
\[  547.786771\] CR2: 0000000000000020 CR3: 00000003cc220002 CR4: 0000000000770ef0  
\[  547.793896\] PKRU: 55555554  
\[  547.796600\] Call Trace:  
\[  547.799046\]  <TASK>  
\[  547.801152\]  ? __die+0x20/0x70  
\[  547.804211\]  ? page_fault_oops+0x75/0x170  
\[  547.808221\]  ? print_hex_dump+0x100/0x160  
\[  547.812226\]  ? exc_page_fault+0x64/0x150  
\[  547.816152\]  ? asm_exc_page_fault+0x22/0x30  
\[  547.820341\]  ? r535_gsp_msg_recv+0x87/0x230 \[nvkm\]  
\[  547.825184\]  r535_gsp_msgq_work+0x42/0x50 \[nvkm\]  
\[  547.829845\]  process_one_work+0x196/0x3d0  
\[  547.833861\]  worker_thread+0x2fc/0x410  
\[  547.837613\]  ? __pfx_worker_thread+0x10/0x10  
\[  547.841885\]  kthread+0xdf/0x110  
\[  547.845031\]  ? __pfx_kthread+0x10/0x10  
\[  547.848775\]  ret_from_fork+0x30/0x50  
\[  547.852354\]  ? __pfx_kthread+0x10/0x10  
\[  547.856097\]  ret_from_fork_asm+0x1a/0x30  
\[  547.860019\]  </TASK>  
\[  547.862208\] Modules linked in: nvkm(E) gsp_log(E) snd_seq_dummy(E) snd_hrtimer(E) snd_seq(E) snd_timer(E) snd_seq_device(E) snd(E) soundcore(E) rfkill(E) qrtr(E) vfat(E) fat(E) ipmi_ssif(E) amd_atl(E) intel_rapl_msr(E) intel_rapl_common(E) amd64_edac(E) mlx5_ib(E) edac_mce_amd(E) kvm_amd  
---truncated---" (Similarity: 51)


#### CWE-400: Uncontrolled Resource Consumption (Exploitability: 6)
- **Description**: The code snippet checks resource limits (RLIMIT_NPROC) and the number of threads (nr_threads, max_threads). While it checks \`is_rlimit_overlimit\` and \`data_race(nr_threads >= max_threads)\`, the checks might not be sufficient to prevent resource exhaustion. Specifically, if \`max_threads\` is set to a very high value, or if the \`RLIMIT_NPROC\` is very large and near the system limit, a process could fork a large number of threads or processes before the limit is reached.  This could lead to denial of service by exhausting system resources (memory, process IDs, etc.), making the system unresponsive or crashing it. The \`data_race\` check is likely intended to prevent a race condition when comparing the number of threads, but it does not solve the fundamental problem of unbounded resource consumption if the limits themselves are too high or are bypassed due to timing windows.
- **Location**: Line 2993 onwards, particularly the resource limit and thread count checks.
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
need to add annotations on the other subsystem's side." (Similarity: 53)
- CVE-2022-49578: "In the Linux kernel, the following vulnerability has been resolved:  
  
ip: Fix data-races around sysctl_ip_prot_sock.  
  
sysctl_ip_prot_sock is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing." (Similarity: 52)
- CVE-2022-49640: "In the Linux kernel, the following vulnerability has been resolved:  
  
sysctl: Fix data races in proc_douintvec_minmax().  
  
A sysctl variable is accessed concurrently, and there is always a chance  
of data-race.  So, all readers and writers need some basic protection to  
avoid load/store-tearing.  
  
This patch changes proc_douintvec_minmax() to use READ_ONCE() and  
WRITE_ONCE() internally to fix data-races on the sysctl side.  For now,  
proc_douintvec_minmax() itself is tolerant to a data-race, but we still  
need to add annotations on the other subsystem's side." (Similarity: 52)


#### CWE-787: Out-of-bounds Write (Exploitability: 8)
- **Description**: The code within \`skb_try_coalesce\` attempts to coalesce two \`sk_buff\` structures, \`to\` and \`from\`. Specifically, if \`skb_headlen(from)\` is not zero, it attempts to add a new fragment to the \`to\` sk_buff's fragment array. The vulnerability lies in the check \`to_shinfo->nr_frags + from_shinfo->nr_frags >= MAX_SKB_FRAGS\`. While this check prevents the addition of too many fragments in total considering both sk_buffs, it does not prevent \`to_shinfo->nr_frags\` from being equal to \`MAX_SKB_FRAGS\` \*before\* the function is even called. If \`to_shinfo->nr_frags\` is already equal to \`MAX_SKB_FRAGS - 1\`, and \`from_shinfo->nr_frags\` is greater than 0 (or skb_headlen(from) is not 0, as in the vulnerable code path), the check still passes, and then \`skb_fill_page_desc\` is called, incrementing \`to_shinfo->nr_frags\` past the limit defined by \`MAX_SKB_FRAGS\`, leading to an out-of-bounds write to the \`frags\` array within the \`skb_shared_info\` structure. This can overwrite adjacent kernel memory, potentially leading to arbitrary code execution or a denial of service. If \`to_shinfo->nr_frags\` is already \`MAX_SKB_FRAGS\`, the check will still pass since it's a \`greater than or equal\` comparison, and the subsequent write will be out of bounds.
- **Location**: Line where \`skb_fill_page_desc\` is called, within the \`if (skb_headlen(from) != 0)\` block.
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
- CVE-2025-21774: "In the Linux kernel, the following vulnerability has been resolved:  
  
can: rockchip: rkcanfd_handle_rx_fifo_overflow_int(): bail out if skb cannot be allocated  
  
Fix NULL pointer check in rkcanfd_handle_rx_fifo_overflow_int() to  
bail out if skb cannot be allocated." (Similarity: 56)
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
the macro definition CONFIG_BPF_JIT_ALWAYS_ON." (Similarity: 54)


#### CWE-190: Integer Overflow or Wraparound (Exploitability: 6)
- **Description**: The code defines \`obj_offset_t\` as an \`unsigned int\` and uses \`OBJ_OFFSET_MASK\` which is initialized to \`((obj_offset_t)~0U)\`.  While this appears safe at first glance, the surrounding code uses \`obj_offset_t\` to represent the offset of an object within a slab. If the \`object_size\` is sufficiently large (close to the maximum value of \`unsigned int\`), and if the slab allocator allows for objects to be allocated such that \`obj_offset\` could potentially reach a value that, when combined with other calculations (not shown in the extract but assumed based on usage pattern), results in an integer overflow. Although this snippet doesn't directly perform the vulnerable operation, the type definition and mask suggest that object offsets are manipulated, increasing the risk of an overflow within other slab allocation functions that use \`obj_offset_t\`. An integer overflow can lead to incorrect memory calculations, potentially resulting in out-of-bounds memory access, heap overflows, or other memory corruption vulnerabilities.
- **Location**: Definition of \`obj_offset_t\` and \`OBJ_OFFSET_MASK\`
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
before it is utilised." (Similarity: 59)
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
but not necessary to backport." (Similarity: 58)


#### CWE-269: Improper Privilege Management (Exploitability: 8)
- **Description**: The \`__sys_setresuid\` function allows a process to change its real, effective, and saved set user IDs. While there's a capability check (\`ns_capable_setid(old->user_ns, CAP_SETUID)\`), the logic determining when this check is performed is flawed. Specifically, the variables \`ruid_new\`, \`euid_new\`, and \`suid_new\` are calculated based on whether the new UIDs are different from \*all\* of \`old->uid\`, \`old->euid\`, and \`old->suid\`. This means that if a process already has one of its UIDs set to the desired value, the \`CAP_SETUID\` check might be bypassed even when changing another UID to a value it shouldn't be able to set. For example, if a process has \`uid == desired_uid\`, it could potentially set \`euid\` and \`suid\` to arbitrary values without the \`CAP_SETUID\` check being triggered, leading to privilege escalation.  The condition \`(ruid_new || euid_new || suid_new)\` controls if capabilities are checked before allowing the setuid operation. By satisfying a condition where at least one of these is false, the capability check is bypassed, and arbitrary setuid operations are possible.
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
- CVE-2025-22080: "In the Linux kernel, the following vulnerability has been resolved:  
  
fs/ntfs3: Prevent integer overflow in hdr_first_de()  
  
The "de_off" and "used" variables come from the disk so they both need to  
check.  The problem is that on 32bit systems if they're both greater than  
UINT_MAX - 16 then the check does work as intended because of an integer  
overflow." (Similarity: 42)


## 🛠️ Patch Reports

### Patch 
- **CWE**: CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\`\`\`c  
/\* Patch Code \*/  
static long resize_limit = 1024 \* 1024; /\* 1MB limit \*/  
  
if (attr->ia_size != inode->i_size) {  
    long size_diff = llabs((long long)attr->ia_size - (long long)inode->i_size);  
  
    if (size_diff > resize_limit) {  
        error = -EFBIG;  
        goto out_mmap_sem;  
    }  
  
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
\`\`\`  
  
Reasoning:  
  
The patch introduces a size difference check before allowing the file size to be modified. It calculates the absolute difference (\`size_diff\`) between the requested new size (\`attr->ia_size\`) and the current size (\`inode->i_size\`). If this difference exceeds a predefined limit (\`resize_limit\`, set to 1MB), the operation is rejected with an \`EFBIG\` error (File too big).  
  
This mitigates the resource exhaustion vulnerability by preventing excessively large or rapidly repeated resizing operations.  The 1MB limit is an example; a production system might tune this limit based on available resources and acceptable performance characteristics.  
  
The \`llabs\` function is used to get the absolute difference between the sizes, handling potential integer overflow issues when subtracting a large size from a smaller one, which could occur if \`attr->ia_size\` and \`inode->i_size\` are large unsigned values. Casting to \`long long\` ensures that the difference calculation has sufficient range to avoid truncation before \`llabs\` is applied.  
  
Functionality is maintained for legitimate resizing operations within the specified size difference threshold.  
  
Trade-offs:  
  
-   A hard limit on the size difference introduces a restriction that may affect legitimate use cases that require large file size adjustments.  The \`resize_limit\` should be configurable if this becomes an issue.  
-   The check adds a small overhead to the resizing operation, but this is likely negligible compared to the cost of excessive journaling.  
-   Setting \`resize_limit\` too low might prevent legitimate file operations, while setting it too high might not adequately address the vulnerability.  
  
Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2024-58016](https://git.kernel.org/stable/c/36b385d0f2b4c0bf41d491e19075ecd990d2bf94)
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)
- [CVE-2024-58085](https://git.kernel.org/stable/c/3df7546fc03b8f004eee0b9e3256369f7d096685)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
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
  
// Check for potential overflow before the shift operation  
if (len > ULONG_MAX >> PAGE_SHIFT)  
    return -EOVERFLOW;  
  
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
\`\`\`  
  
\*\*Reasoning:\*\*  
  
The original code's overflow check \`(pgoff + (len >> PAGE_SHIFT)) < pgoff\` is vulnerable to integer overflow because the expression \`len >> PAGE_SHIFT\` can wrap around. The patch adds a check \`if (len > ULONG_MAX >> PAGE_SHIFT)\` \*before\* the shift operation.  
  
1.  \*\*Resolution:\*\* This pre-shift check prevents \`len >> PAGE_SHIFT\` from overflowing.  \`ULONG_MAX >> PAGE_SHIFT\` calculates the maximum permissible value for \`len\` that, when right-shifted by \`PAGE_SHIFT\`, will not cause a wraparound. If \`len\` exceeds this value, the function returns \`-EOVERFLOW\`, preventing the vulnerable code from executing.  
  
2.  \*\*Functionality:\*\* The patch maintains the code's original functionality by performing the same error checks as before but prevents the integer overflow from occurring. The added check only prevents execution when \`len\` is large enough to potentially cause an overflow during the shift operation.  
  
3.  \*\*Trade-offs/Considerations:\*\* The patch introduces a new check, which adds a small performance overhead. However, this overhead is negligible compared to the security risk of allowing the integer overflow to occur.  The patch relies on \`ULONG_MAX\` being the maximum value for the \`len\` variable type, which is generally the case. Using \`SIZE_MAX\` could be another alternative, depending on how the len variable is declared. However, it's most likely to be \`unsigned long\` as the shift operation is unsigned. The macro \`PAGE_SHIFT\` is assumed to be defined and provide the number of bits to shift for page alignment, which is standard in the Linux kernel.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2024-58018](https://git.kernel.org/stable/c/01ed662bdd6fce4f59c1804b334610d710d79fa0)
- [CVE-2024-58019](https://git.kernel.org/stable/c/5185e63b45ea39339ed83f269e2ddfafb07e70d9)


### Patch 
- **CWE**: CWE-400: Uncontrolled Resource Consumption
- **Kernel Version**: 6.11.0-24-generic
- **Patch Details**:
```diff
\*\*Patch Code:\*\*  
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
  
  
retval = -EAGAIN;  
if (data_race(nr_threads >= max_threads))  
    goto bad_fork_cleanup_count;  
  
/\* Add a check to ensure the current number of threads does not exceed a reasonable threshold. \*/  
#define MAX_REASONABLE_THREADS 4096 /\* A reasonable upper limit \*/  
retval = -EAGAIN;  
if (nr_threads > MAX_REASONABLE_THREADS)  
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
  
The patch addresses the CWE-400 vulnerability by introducing a hard limit on the number of threads that can be created.  While the existing code checks \`rlimit(RLIMIT_NPROC)\` and compares \`nr_threads\` with \`max_threads\`, it's possible for a process to exhaust system resources if these limits are set too high, or if a race condition allows the process to briefly exceed those limits.  
  
The added check \`if (nr_threads > MAX_REASONABLE_THREADS)\` introduces a ceiling on the number of threads any process can create. \`MAX_REASONABLE_THREADS\` is defined as 4096, a value that should be sufficient for most applications while still preventing runaway thread creation. This limit provides a safeguard even if \`RLIMIT_NPROC\` is set to a high value, preventing a single process from consuming all available system resources.  
  
This patch directly addresses the resource consumption vulnerability by limiting the number of threads a process can create, regardless of the user's RLIMIT settings (as long as that limit allows more than \`MAX_REASONABLE_THREADS\` threads). It maintains the code's functionality by only adding a check and returning -EAGAIN if the new limit is exceeded, similar to the existing limit checks.  
  
Trade-offs:  A hard-coded limit might be too restrictive for some specific applications that legitimately require a large number of threads.  The \`MAX_REASONABLE_THREADS\` value should be chosen carefully considering the target system and typical workloads.  A more sophisticated approach would involve dynamically adjusting this limit based on available system resources (e.g., available memory). Another trade-off is that legitimate processes may be blocked if they require more than MAX_REASONABLE_THREADS threads. However, such processes are rare, and the added security outweighs the slight inconvenience.  
  
\*\*Patch Links:\*\* None  

```
- **CVE Patch Links**:
- [CVE-2022-49634](https://git.kernel.org/stable/c/5f776daef0b5354615ec4b4234cd9539ca05f273)
- [CVE-2022-49578](https://git.kernel.org/stable/c/95724fe897a4ecf2be51452ef96e818568071664)
- [CVE-2022-49640](https://git.kernel.org/stable/c/2d3b559df3ed39258737789aae2ae7973d205bc1)


### Patch 
- **CWE**: CWE-787: Out-of-bounds Write
- **Kernel Version**: 6.11.0-24-generic
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
  
        if (to_shinfo->nr_frags >= MAX_SKB_FRAGS)  
            return false;  
  
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
}  
\`\`\`  
  
- Reasoning:  
The patch adds a check \`if (to_shinfo->nr_frags >= MAX_SKB_FRAGS)\` before the original fragment count check. This ensures that \`skb_fill_page_desc\` is only called if there is space available in the \`to\` sk_buff's fragment array.  The original check only considered the \*combined\* number of fragments, not whether \`to\` already had a full fragment array.  This prevents the out-of-bounds write that occurs when \`to_shinfo->nr_frags\` is already equal to \`MAX_SKB_FRAGS\` or \`MAX_SKB_FRAGS -1\` and an attempt is made to increment it further in \`skb_fill_page_desc\`.  
  
The corrected code maintains the original code's functionality by only adding a preventative check. It does not alter the intended behavior of coalescing the sk_buffs if space is available.  
  
There are no significant trade-offs. The added check introduces minimal overhead and effectively prevents the vulnerability.  
  
- Patch Links: None  

```
- **CVE Patch Links**:
- [CVE-2025-21961](https://git.kernel.org/stable/c/19107e71be330dbccb9f8f9f4cf0a9abeadad802)
- [CVE-2025-21774](https://git.kernel.org/stable/c/118fb35681bd2c0d2afa22f7be0ef94bb4d06849)
- [CVE-2025-22087](https://git.kernel.org/stable/c/19e6817f84000d0b06f09fd69ebd56217842c122)


### Patch 
- **CWE**: CWE-190: Integer Overflow or Wraparound
- **Kernel Version**: 6.11.0-24-generic
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
typedef size_t __bitwise obj_offset_t;  
#define OBJ_OFFSET_MASK    ((obj_offset_t)~0UL)  
  
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
  
The vulnerability lies in the potential for \`obj_offset_t\` (currently defined as \`unsigned int\`) to overflow when combined with \`object_size\` or other calculations within the slab allocator. To mitigate this, we increase the size of \`obj_offset_t\` to \`size_t\`. This ensures that \`obj_offset_t\` can represent larger object offsets, reducing the likelihood of an integer overflow, especially when \`object_size\` approaches the maximum value of \`unsigned int\`. Correspondingly, \`OBJ_OFFSET_MASK\` is also updated to \`((obj_offset_t)~0UL)\` to correctly mask the \`size_t\` value.  
  
- \*\*Resolution:\*\*  Changing the type of \`obj_offset_t\` to \`size_t\` increases its range, thus preventing potential integer overflows that could occur when calculating object offsets.  
- \*\*Functionality:\*\* Using \`size_t\` is appropriate since object offsets are fundamentally memory addresses and sizes which \`size_t\` is designed to hold. The code's functionality is maintained because the variable represents the offset of the object within a slab, and \`size_t\` can hold sufficiently large offsets.  
- \*\*Trade-offs:\*\* The trade-off is a potential increase in memory consumption, as \`size_t\` might be larger than \`unsigned int\` (especially on 32-bit architectures where \`size_t\` is often 4 bytes and changes to 8 bytes on 64-bit architectures). However, this increased memory usage is generally acceptable given the improved safety and reduced risk of memory corruption. It's preferable to have larger offset that is safer, than a smaller one that could lead to vulnerabilities. This change is particularly important for systems with larger memory spaces and object sizes.  
- \*\*Edge Cases:\*\*  By using \`size_t\`, we are now relying on the kernel's memory management to handle the significantly larger address space.  While this is generally safe, it's important to consider the implications for very large slabs and object sizes. The mask is updated to be an unsigned long so that all the bits are set for a \`size_t\` type.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-39735](https://git.kernel.org/stable/c/0beddc2a3f9b9cf7d8887973041e36c2d0fa3652)
- [CVE-2025-22091](https://git.kernel.org/stable/c/01fd737776ca0f17a96d83cd7f0840ce130b9a02)
- [CVE-2025-40114](https://git.kernel.org/stable/c/18a08b5632809faa671279b3cd27d5f96cc5a3f0)


### Patch 
- **CWE**: CWE-269: Improper Privilege Management
- **Kernel Version**: 6.11.0-24-generic
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
  
\*\*Reasoning:\*\*  
  
The original code incorrectly determined whether a capability check was required before setting the UIDs. It checked if the new UIDs were different from \*all\* of the old UIDs (\`old->uid\`, \`old->euid\`, and \`old->suid\`).  This allowed bypassing the \`CAP_SETUID\` check if even one of the old UIDs matched the new UID being set.  
  
The patch modifies the \`ruid_new\`, \`euid_new\`, and \`suid_new\` calculations to only compare the new UID against the corresponding old UID. Specifically:  
  
- \`ruid_new\` is now \`(ruid != (uid_t) -1) && !uid_eq(kruid, old->uid)\`; It only checks if ruid is being changed.  
- \`euid_new\` is now \`(euid != (uid_t) -1) && !uid_eq(keuid, old->euid)\`; It only checks if euid is being changed.  
- \`suid_new\` is now \`(suid != (uid_t) -1) && !uid_eq(ksuid, old->suid)\`; It only checks if suid is being changed.  
  
This ensures that the \`CAP_SETUID\` check is performed whenever any of the UIDs are being changed to a value different from their current value, regardless of the values of other UIDs.  This prevents the privilege escalation vulnerability.  
  
This patch maintains the code's original functionality by still allowing legitimate UID changes when the process has the \`CAP_SETUID\` capability. The no-op check is also preserved. The patch is minimal, only changing the logic of the boolean variable assignments.  
  
\*\*Patch Links:\*\*  
  
None  

```
- **CVE Patch Links**:
- [CVE-2025-22029](https://git.kernel.org/stable/c/753a620a7f8e134b444f89fe90873234e894e21a)
- [CVE-2025-21846](https://git.kernel.org/stable/c/56d5f3eba3f5de0efdd556de4ef381e109b973a9)
- [CVE-2025-22080](https://git.kernel.org/stable/c/201a2bdda13b619c4927700ffe47d387a30ced50)


## 📊 Summary
- **Agent**: Agent 1
- **LTP Tests**: 6
- **CWE Issues**: 6
- **Patches**: 6

### LTP Results Breakdown
- Flaw Detected: 3 (\#ef4444)
- Safe: 3 (\#22c55e)
