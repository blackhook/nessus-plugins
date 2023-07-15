#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-666.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100711);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7487", "CVE-2017-7645", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9150");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-666)");
  script_summary(english:"Check for the openSUSE-2017-666 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.70 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-9076: The dccp_v6_request_recv_sock function in
    net/dccp/ipv6.c in the Linux kernel mishandled
    inheritance, which allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    crafted system calls, a related issue to CVE-2017-8890
    (bnc#1039885).

  - CVE-2017-9077: The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel mishandled
    inheritance, which allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    crafted system calls, a related issue to CVE-2017-8890
    (bnc#1040069).

  - CVE-2017-9075: The sctp_v6_create_accept_sk function in
    net/sctp/ipv6.c in the Linux kernel mishandled
    inheritance, which allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    crafted system calls, a related issue to CVE-2017-8890
    (bnc#1039883).

  - CVE-2017-9074: The IPv6 fragmentation implementation in
    the Linux kernel did not consider that the nexthdr field
    may be associated with an invalid option, which allowed
    local users to cause a denial of service (out-of-bounds
    read and BUG) or possibly have unspecified other impact
    via crafted socket and send system calls (bnc#1039882).

  - CVE-2017-7487: The ipxitf_ioctl function in
    net/ipx/af_ipx.c in the Linux kernel mishandled
    reference counts, which allowed local users to cause a
    denial of service (use-after-free) or possibly have
    unspecified other impact via a failed SIOCGIFADDR ioctl
    call for an IPX interface (bnc#1038879).

  - CVE-2017-8890: The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    allowed attackers to cause a denial of service (double
    free) or possibly have unspecified other impact by
    leveraging use of the accept system call (bnc#1038544).

  - CVE-2017-9150: The do_check function in
    kernel/bpf/verifier.c in the Linux kernel did not make
    the allow_ptr_leaks value available for restricting the
    output of the print_bpf_insn function, which allowed
    local users to obtain sensitive address information via
    crafted bpf system calls (bnc#1040279).

  - CVE-2017-7645: The NFSv2/NFSv3 server in the nfsd
    subsystem in the Linux kernel allowed remote attackers
    to cause a denial of service (system crash) via a long
    RPC reply, related to net/sunrpc/svc.c,
    fs/nfsd/nfs3xdr.c, and fs/nfsd/nfsxdr.c. (bsc#1034670)

The following non-security bugs were fixed :

  - 9p: fix a potential acl leak (4.4.68 stable queue).

  - acpi / APEI: Add missing synchronize_rcu() on NOTIFY_SCI
    removal (bsc#1031717).

  - acpi / scan: Drop support for force_remove
    (bnc#1029607).

  - ahci: disable correct irq for dummy ports (bsc#1040125).

  - alsa: hda - Fix deadlock of controller device lock at
    unbinding (4.4.68 stable queue).

  - arm: 8452/3: PJ4: make coprocessor access sequences
    buildable in Thumb2 mode (4.4.68 stable queue).

  - arm: OMAP5 / DRA7: Fix HYP mode boot for thumb2 build
    (4.4.68 stable queue).

  - asoc: rt5640: use msleep() for long delays
    (bsc#1031717).

  - asoc: sti: Fix error handling if of_clk_get() fails
    (bsc#1031717).

  - blacklist 61e8a0d5a027 powerpc/pci: Fix endian bug in
    fixed PHB numbering (bsc#989311)

  - block: get rid of blk_integrity_revalidate() (4.4.68
    stable queue).

  - bna: avoid writing uninitialized data into hw registers
    (bsc#966321 FATE#320156).

  - bnxt_en: allocate enough space for ->ntp_fltr_bmap
    (bsc#1020412 FATE#321671).

  - bpf, arm64: fix jit branch offset related to ldimm64
    (4.4.68 stable queue).

  - brcmfmac: Ensure pointer correctly set if skb data
    location changes (4.4.68 stable queue).

  - brcmfmac: Make skb header writable before use (4.4.68
    stable queue).

  - brcmfmac: restore stopping netdev queue when bus clogs
    up (bsc#1031717).

  - btrfs: add a flags field to btrfs_fs_info (bsc#1012452).

  - btrfs: add ASSERT for block group's memory leak
    (bsc#1012452).

  - btrfs: add btrfs_trans_handle->fs_info pointer
    (bsc#1012452).

  - btrfs: add bytes_readonly to the spaceinfo at once
    (bsc#1012452).

  - btrfs: add check to sysfs handler of label
    (bsc#1012452).

  - btrfs: add dynamic debug support (bsc#1012452).

  - btrfs: add error handling for extent buffer in print
    tree (bsc#1012452).

  - btrfs: add missing bytes_readonly attribute file in
    sysfs (bsc#1012452).

  - btrfs: add missing check for writeback errors on fsync
    (bsc#1012452).

  - btrfs: add more validation checks for superblock
    (bsc#1012452).

  - btrfs: Add ratelimit to btrfs printing (bsc#1012452).

  - btrfs: add read-only check to sysfs handler of features
    (bsc#1012452).

  - btrfs: add semaphore to synchronize direct IO writes
    with fsync (bsc#1012452).

  - btrfs: add tracepoint for adding block groups
    (bsc#1012452).

  - btrfs: add tracepoints for flush events (bsc#1012452).

  - btrfs: add validadtion checks for chunk loading
    (bsc#1012452).

  - btrfs: add write protection to SET_FEATURES ioctl
    (bsc#1012452).

  - btrfs: allow balancing to dup with multi-device
    (bsc#1012452).

  - btrfs: always reserve metadata for delalloc extents
    (bsc#1012452).

  - btrfs: always use trans->block_rsv for orphans
    (bsc#1012452).

  - btrfs: avoid blocking open_ctree from cleaner_kthread
    (bsc#1012452).

  - btrfs: avoid deadlocks during reservations in
    btrfs_truncate_block (bsc#1012452).

  - btrfs: avoid overflowing f_bfree (bsc#1012452).

  - btrfs: btrfs_abort_transaction, drop root parameter
    (bsc#1012452).

  - btrfs: __btrfs_buffered_write: Pass valid file offset
    when releasing delalloc space (bsc#1012452).

  - btrfs: btrfs_check_super_valid: Allow 4096 as stripesize
    (bsc#1012452).

  - btrfs: btrfs_debug should consume fs_info when DEBUG is
    not defined (bsc#1012452).

  - btrfs: btrfs_relocate_chunk pass extent_root to
    btrfs_end_transaction (bsc#1012452).

  - btrfs: build fixup for qgroup_account_snapshot
    (bsc#1012452).

  - btrfs: change BUG_ON()'s to ASSERT()'s in
    backref_cache_cleanup() (bsc#1012452).

  - btrfs: change delayed reservation fallback behavior
    (bsc#1012452).

  - btrfs: change how we calculate the global block rsv
    (bsc#1012452).

  - btrfs: check btree node's nritems (bsc#1012452).

  - btrfs: check if extent buffer is aligned to sectorsize
    (bsc#1012452).

  - btrfs: check inconsistence between chunk and block group
    (bsc#1012452).

  - btrfs: clarify do_chunk_alloc()'s return value
    (bsc#1012452).

  - btrfs: clean the old superblocks before freeing the
    device (bsc#1012452).

  - btrfs: clean up and optimize __check_raid_min_device()
    (bsc#1012452).

  - btrfs: cleanup assigning next active device with a check
    (bsc#1012452).

  - btrfs: cleanup BUG_ON in merge_bio (bsc#1012452).

  - btrfs: Cleanup compress_file_range() (bsc#1012452).

  - btrfs: cleanup error handling in
    extent_write_cached_pages (bsc#1012452).

  - btrfs: clear uptodate flags of pages in sys_array eb
    (bsc#1012452).

  - btrfs: clone: use vmalloc only as fallback for nodesize
    bufer (bsc#1012452).

  - btrfs: convert nodesize macros to static inlines
    (bsc#1012452).

  - btrfs: convert printk(KERN_* to use pr_* calls
    (bsc#1012452).

  - btrfs: convert pr_* to btrfs_* where possible
    (bsc#1012452).

  - btrfs: convert send's verbose_printk to btrfs_debug
    (bsc#1012452).

  - btrfs: copy_to_sk drop unused root parameter
    (bsc#1012452).

  - btrfs: create a helper function to read the disk super
    (bsc#1012452).

  - btrfs: create example debugfs file only in debugging
    build (bsc#1012452).

  - btrfs: create helper btrfs_find_device_by_user_input()
    (bsc#1012452).

  - btrfs: create helper function __check_raid_min_devices()
    (bsc#1012452).

  - btrfs: detect corruption when non-root leaf has zero
    item (bsc#1012452).

  - btrfs: divide btrfs_update_reserved_bytes() into two
    functions (bsc#1012452).

  - btrfs: do not background blkdev_put() (bsc#1012452).

  - btrfs: do not bother kicking async if there's nothing to
    reclaim (bsc#1012452).

  - btrfs: do not BUG_ON() in btrfs_orphan_add
    (bsc#1012452).

  - btrfs: do not create empty block group if we have
    allocated data (bsc#1012452).

  - btrfs: do not decrease bytes_may_use when replaying
    extents (bsc#1012452).

  - btrfs: do not do nocow check unless we have to
    (bsc#1012452).

  - btrfs: do not do unnecessary delalloc flushes when
    relocating (bsc#1012452).

  - btrfs: do not force mounts to wait for cleaner_kthread
    to delete one or more subvolumes (bsc#1012452).

  - btrfs: do not wait for unrelated IO to finish before
    relocation (bsc#1012452).

  - btrfs: do not WARN() in btrfs_transaction_abort() for IO
    errors (bsc#1035866).

  - btrfs: end transaction if we abort when creating uuid
    root (bsc#1012452).

  - btrfs: enhance btrfs_find_device_by_user_input() to
    check device path (bsc#1012452).

  - btrfs: error out if generic_bin_search get invalid
    arguments (bsc#1012452).

  - btrfs: expand cow_file_range() to support in-band dedup
    and subpage-blocksize (bsc#1012452).

  - btrfs: extend btrfs_set_extent_delalloc and its friends
    to support in-band dedupe and subpage size patchset
    (bsc#1012452).

  - btrfs: fill relocation block rsv after allocation
    (bsc#1012452).

  - btrfs: fix an integer overflow check (bsc#1012452).

  - btrfs: fix a possible umount deadlock (bsc#1012452).

  - btrfs: fix btrfs_no_printk stub helper (bsc#1012452).

  - btrfs: Fix BUG_ON condition in
    scrub_setup_recheck_block() (bsc#1012452).

  - btrfs: fix BUG_ON in btrfs_mark_buffer_dirty
    (bsc#1012452).

  - btrfs: fix BUG_ON in btrfs_submit_compressed_write
    (bsc#1012452).

  - btrfs: fix callers of btrfs_block_rsv_migrate
    (bsc#1012452).

  - btrfs: fix check_direct_IO() for non-iovec iterators
    (bsc#1012452).

  - btrfs: fix check_shared for fiemap ioctl (bsc#1037177).

  - btrfs: fix crash when tracepoint arguments are freed by
    wq callbacks (bsc#1012452).

  - btrfs: fix data loss after truncate when using the
    no-holes feature (bsc#1036214).

  - btrfs: fix deadlock in delayed_ref_async_start
    (bsc#1012452).

  - btrfs: fix delalloc reservation amount tracepoint
    (bsc#1012452).

  - btrfs: fix disk_i_size update bug when fallocate() fails
    (bsc#1012452).

  - btrfs: fix divide error upon chunk's stripe_len
    (bsc#1012452).

  - btrfs: fix double free of fs root (bsc#1012452).

  - btrfs: fix eb memory leak due to readpage failure
    (bsc#1012452).

  - btrfs: fix em leak in find_first_block_group
    (bsc#1012452).

  - btrfs: fix emptiness check for dirtied extent buffers at
    check_leaf() (bsc#1012452).

  - btrfs: fix error handling in map_private_extent_buffer
    (bsc#1012452).

  - btrfs: fix error return code in btrfs_init_test_fs()
    (bsc#1012452).

  - btrfs: fix free space calculation in dump_space_info()
    (bsc#1012452).

  - btrfs: fix fsfreeze hang caused by delayed iputs deal
    (bsc#1012452).

  - btrfs: fix fspath error deallocation (bsc#1012452).

  - btrfs: fix int32 overflow in shrink_delalloc()
    (bsc#1012452).

  - btrfs: Fix integer overflow when calculating
    bytes_per_bitmap (bsc#1012452).

  - btrfs: fix invalid dereference in btrfs_retry_endio
    (bsc#1040395).

  - btrfs: fix lock dep warning, move scratch dev out of
    device_list_mutex and uuid_mutex (bsc#1012452).

  - btrfs: fix lock dep warning move scratch super outside
    of chunk_mutex (bsc#1012452).

  - btrfs: fix __MAX_CSUM_ITEMS (bsc#1012452).

  - btrfs: fix memory leak during RAID 5/6 device
    replacement (bsc#1012452).

  - btrfs: fix memory leak of block group cache
    (bsc#1012452).

  - btrfs: fix memory leak of reloc_root (bsc#1012452).

  - btrfs: fix mixed block count of available space
    (bsc#1012452).

  - btrfs: fix one bug that process may endlessly wait for
    ticket in wait_reserve_ticket() (bsc#1012452).

  - btrfs: fix panic in balance due to EIO (bsc#1012452).

  - btrfs: fix race between block group relocation and nocow
    writes (bsc#1012452).

  - btrfs: fix race between device replace and block group
    removal (bsc#1012452).

  - btrfs: fix race between device replace and chunk
    allocation (bsc#1012452).

  - btrfs: fix race between device replace and discard
    (bsc#1012452).

  - btrfs: fix race between device replace and read repair
    (bsc#1012452).

  - btrfs: fix race between fsync and direct IO writes for
    prealloc extents (bsc#1012452).

  - btrfs: fix race between readahead and device
    replace/removal (bsc#1012452).

  - btrfs: fix race setting block group back to RW mode
    during device replace (bsc#1012452).

  - btrfs: fix race setting block group readonly during
    device replace (bsc#1012452).

  - btrfs: fix read_node_slot to return errors
    (bsc#1012452).

  - btrfs: fix release reserved extents trace points
    (bsc#1012452).

  - btrfs: fix segmentation fault when doing dio read
    (bsc#1040425).

  - btrfs: Fix slab accounting flags (bsc#1012452).

  - btrfs: fix unexpected return value of fiemap
    (bsc#1012452).

  - btrfs: fix unprotected assignment of the left cursor for
    device replace (bsc#1012452).

  - btrfs: fix WARNING in btrfs_select_ref_head()
    (bsc#1012452).

  - btrfs: flush_space: treat return value of do_chunk_alloc
    properly (bsc#1012452).

  - btrfs: Force stripesize to the value of sectorsize
    (bsc#1012452).

  - btrfs: free sys_array eb as soon as possible
    (bsc#1012452).

  - btrfs: GFP_NOFS does not GFP_HIGHMEM (bsc#1012452).

  - btrfs: Handle uninitialised inode eviction
    (bsc#1012452).

  - btrfs: hide test-only member under ifdef (bsc#1012452).

  - btrfs: improve check_node to avoid reading corrupted
    nodes (bsc#1012452).

  - btrfs: introduce BTRFS_MAX_ITEM_SIZE (bsc#1012452).

  - btrfs: introduce device delete by devid (bsc#1012452).

  - btrfs: introduce raid-type to error-code table, for
    minimum device constraint (bsc#1012452).

  - btrfs: introduce ticketed enospc infrastructure
    (bsc#1012452).

  - btrfs: introduce tickets_id to determine whether
    asynchronous metadata reclaim work makes progress
    (bsc#1012452).

  - btrfs: ioctl: reorder exclusive op check in RM_DEV
    (bsc#1012452).

  - btrfs: kill BUG_ON in do_relocation (bsc#1012452).

  - btrfs: kill BUG_ON in run_delayed_tree_ref
    (bsc#1012452).

  - btrfs: kill BUG_ON()'s in btrfs_mark_extent_written
    (bsc#1012452).

  - btrfs: kill invalid ASSERT() in process_all_refs()
    (bsc#1012452).

  - btrfs: kill the start argument to
    read_extent_buffer_pages (bsc#1012452).

  - btrfs: kill unused writepage_io_hook callback
    (bsc#1012452).

  - btrfs: make find_workspace always succeed (bsc#1012452).

  - btrfs: make find_workspace warn if there are no
    workspaces (bsc#1012452).

  - btrfs: make mapping->writeback_index point to the last
    written page (bsc#1012452).

  - btrfs: make state preallocation more speculative in
    __set_extent_bit (bsc#1012452).

  - btrfs: make sure device is synced before return
    (bsc#1012452).

  - btrfs: make use of btrfs_find_device_by_user_input()
    (bsc#1012452).

  - btrfs: make use of btrfs_scratch_superblocks() in
    btrfs_rm_device() (bsc#1012452).

  - btrfs: memset to avoid stale content in btree leaf
    (bsc#1012452).

  - btrfs: memset to avoid stale content in btree node block
    (bsc#1012452).

  - btrfs: move error handling code together in ctree.h
    (bsc#1012452).

  - btrfs: optimize check for stale device (bsc#1012452).

  - btrfs: parent_start initialization cleanup
    (bsc#1012452).

  - btrfs: pass correct args to
    btrfs_async_run_delayed_refs() (bsc#1012452).

  - btrfs: pass number of devices to
    btrfs_check_raid_min_devices (bsc#1012452).

  - btrfs: pass the right error code to the btrfs_std_error
    (bsc#1012452).

  - btrfs: preallocate compression workspaces (bsc#1012452).

  - btrfs: Ratelimit 'no csum found' info message
    (bsc#1012452).

  - btrfs: refactor btrfs_dev_replace_start for reuse
    (bsc#1012452).

  - btrfs: Refactor btrfs_lock_cluster() to kill compiler
    warning (bsc#1012452).

  - btrfs: remove BUG() in raid56 (bsc#1012452).

  - btrfs: remove BUG_ON in start_transaction (bsc#1012452).

  - btrfs: remove BUG_ON()'s in btrfs_map_block
    (bsc#1012452).

  - btrfs: remove build fixup for qgroup_account_snapshot
    (bsc#1012452).

  - btrfs: remove save_error_info() (bsc#1012452).

  - btrfs: remove unnecessary btrfs_mark_buffer_dirty in
    split_leaf (bsc#1012452).

  - btrfs: remove unused function btrfs_assert()
    (bsc#1012452).

  - btrfs: rename and document compression workspace members
    (bsc#1012452).

  - btrfs: rename btrfs_find_device_by_user_input
    (bsc#1012452).

  - btrfs: rename btrfs_std_error to btrfs_handle_fs_error
    (bsc#1012452).

  - btrfs: rename __check_raid_min_devices (bsc#1012452).

  - btrfs: rename flags for vol args v2 (bsc#1012452).

  - btrfs: reorg btrfs_close_one_device() (bsc#1012452).

  - btrfs: Replace -ENOENT by -ERANGE in btrfs_get_acl()
    (bsc#1012452).

  - btrfs: reuse existing variable in scrub_stripe, reduce
    stack usage (bsc#1012452).

  - btrfs: s_bdev is not null after missing replace
    (bsc#1012452).

  - btrfs: scrub: Set bbio to NULL before calling
    btrfs_map_block (bsc#1012452).

  - btrfs: send: silence an integer overflow warning
    (bsc#1012452).

  - btrfs: send: use temporary variable to store allocation
    size (bsc#1012452).

  - btrfs: send: use vmalloc only as fallback for
    clone_roots (bsc#1012452).

  - btrfs: send: use vmalloc only as fallback for
    clone_sources_tmp (bsc#1012452).

  - btrfs: send: use vmalloc only as fallback for read_buf
    (bsc#1012452).

  - btrfs: send: use vmalloc only as fallback for send_buf
    (bsc#1012452).

  - btrfs: Simplify conditions about compress while mapping
    btrfs flags to inode flags (bsc#1012452).

  - btrfs: sink gfp parameter to clear_extent_bits
    (bsc#1012452).

  - btrfs: sink gfp parameter to clear_extent_dirty
    (bsc#1012452).

  - btrfs: sink gfp parameter to clear_record_extent_bits
    (bsc#1012452).

  - btrfs: sink gfp parameter to convert_extent_bit
    (bsc#1012452).

  - btrfs: sink gfp parameter to set_extent_bits
    (bsc#1012452).

  - btrfs: sink gfp parameter to set_extent_defrag
    (bsc#1012452).

  - btrfs: sink gfp parameter to set_extent_delalloc
    (bsc#1012452).

  - btrfs: sink gfp parameter to set_extent_new
    (bsc#1012452).

  - btrfs: sink gfp parameter to set_record_extent_bits
    (bsc#1012452).

  - btrfs: skip commit transaction if we do not have enough
    pinned bytes (bsc#1037186).

  - btrfs: subpage-blocksize: Rate limit scrub error message
    (bsc#1012452).

  - btrfs: switch to common message helpers in open_ctree,
    adjust messages (bsc#1012452).

  - btrfs: sysfs: protect reading label by lock
    (bsc#1012452).

  - btrfs: trace pinned extents (bsc#1012452).

  - btrfs: track transid for delayed ref flushing
    (bsc#1012452).

  - btrfs: uapi/linux/btrfs.h migration, document subvol
    flags (bsc#1012452).

  - btrfs: uapi/linux/btrfs.h migration, move balance flags
    (bsc#1012452).

  - btrfs: uapi/linux/btrfs.h migration, move
    BTRFS_LABEL_SIZE (bsc#1012452).

  - btrfs: uapi/linux/btrfs.h migration, move feature flags
    (bsc#1012452).

  - btrfs: uapi/linux/btrfs.h migration, move struct
    btrfs_ioctl_defrag_range_args (bsc#1012452).

  - btrfs: uapi/linux/btrfs.h migration, qgroup limit flags
    (bsc#1012452).

  - btrfs: uapi/linux/btrfs_tree.h migration, item types and
    defines (bsc#1012452).

  - btrfs: uapi/linux/btrfs_tree.h, use __u8 and __u64
    (bsc#1012452).

  - btrfs: unsplit printed strings (bsc#1012452).

  - btrfs: untangle gotos a bit in __clear_extent_bit
    (bsc#1012452).

  - btrfs: untangle gotos a bit in convert_extent_bit
    (bsc#1012452).

  - btrfs: untangle gotos a bit in __set_extent_bit
    (bsc#1012452).

  - btrfs: update btrfs_space_info's bytes_may_use timely
    (bsc#1012452).

  - btrfs: Use correct format specifier (bsc#1012452).

  - btrfs: use correct offset for reloc_inode in
    prealloc_file_extent_cluster() (bsc#1012452).

  - btrfs: use dynamic allocation for root item in
    create_subvol (bsc#1012452).

  - btrfs: use existing device constraints table
    btrfs_raid_array (bsc#1012452).

  - btrfs: use FLUSH_LIMIT for relocation in
    reserve_metadata_bytes (bsc#1012452).

  - btrfs: use fs_info directly (bsc#1012452).

  - btrfs: use new error message helper in
    qgroup_account_snapshot (bsc#1012452).

  - btrfs: use root when checking need_async_flush
    (bsc#1012452).

  - btrfs: use the correct struct for BTRFS_IOC_LOGICAL_INO
    (bsc#1012452).

  - btrfs: Use __u64 in exported linux/btrfs.h
    (bsc#1012452).

  - btrfs: warn_on for unaccounted spaces (bsc#1012452).

  - ceph: check i_nlink while converting a file handle to
    dentry (bsc#1039864).

  - ceph: Check that the new inode size is within limits in
    ceph_fallocate() (bsc#1037969).

  - ceph: Correctly return NXIO errors from ceph_llseek
    (git-fixes).

  - ceph: fix file open flags on ppc64 (bsc#1022266).

  - ceph: fix memory leak in __ceph_setxattr()
    (bsc#1036763).

  - cifs: backport prepath matching fix (bsc#799133).

  - clk: Make x86/ conditional on CONFIG_COMMON_CLK (4.4.68
    stable queue).

  - cpupower: Fix turbo frequency reporting for pre-Sandy
    Bridge cores (4.4.68 stable queue).

  - crypto: algif_aead - Require setkey before accept(2)
    (bsc#1031717).

  - crypto: sha-mb - Fix load failure (bsc#1037384).

  - dell-laptop: Adds support for keyboard backlight timeout
    AC settings (bsc#1013561).

  - Disable CONFIG_POWER_SUPPLY_DEBUG in debug kernel
    (bsc#1031500).

  - dmaengine: dw: fix typo in Kconfig (bsc#1031717).

  - dm: fix dm_target_io leak if clone_bio() returns an
    error (bsc#1040125).

  - dm-mpath: fix race window in do_end_io() (bsc#1011044).

  - dm round robin: do not use this_cpu_ptr() without having
    preemption disabled (bsc#1040125).

  - dm verity fec: fix block calculation (bsc#1040125).

  - dm verity fec: fix bufio leaks (bsc#1040125).

  - dm verity fec: limit error correction recursion
    (bsc#1040125).

  - drivers: base: dma-mapping: Fix typo in
    dmam_alloc_non_coherent comments (bsc#1031717).

  - drivers/tty: 8250: only call fintek_8250_probe when
    doing port I/O (bsc#1031717).

  - drm/i915: Disable tv output on i9x5gm (bsc#1039700).

  - drm/i915: Do not touch NULL sg on
    i915_gem_object_get_pages_gtt() error (bsc#1031717).

  - drm/i915: Fix mismatched INIT power domain disabling
    during suspend (bsc#1031717).

  - drm/i915: Nuke debug messages from the pipe update
    critical section (bsc#1031717).

  - drm/i915: Program iboost settings for HDMI/DVI on SKL
    (bsc#1031717).

  - drm/i915: relax uncritical udelay_range() (bsc#1031717).

  - drm/i915: relax uncritical udelay_range() settings
    (bsc#1031717).

  - drm/i915: Use pagecache write to prepopulate shmemfs
    from pwrite-ioctl (bsc#1040463).

  - drm/ttm: fix use-after-free races in vm fault handling
    (4.4.68 stable queue).

  - e1000e: Do not return uninitialized stats (bug#1034635).

  - enic: set skb->hash type properly (bsc#922871
    fate#318754).

  - f2fs: fix bad prefetchw of NULL page (bsc#1012829).

  - f2fs: sanity check segment count (4.4.68 stable queue).

  - fnic: Return 'DID_IMM_RETRY' if rport is not ready
    (bsc#1035920).

  - fs/block_dev: always invalidate cleancache in
    invalidate_bdev() (git-fixes).

  - fs: fix data invalidation in the cleancache during
    direct IO (git-fixes).

  - fs/xattr.c: zero out memory copied to userspace in
    getxattr (git-fixes).

  - ftrace: Make ftrace_location_range() global
    (FATE#322421).

  - ibmvnic: Add set_link_state routine for setting adapter
    link state (fate#322021, bsc#1031512).

  - ibmvnic: Allocate zero-filled memory for sub crqs
    (fate#322021, bsc#1031512).

  - ibmvnic: Check for driver reset first in ibmvnic_xmit
    (fate#322021, bsc#1038297).

  - ibmvnic: Cleanup failure path in ibmvnic_open
    (fate#322021, bsc#1031512).

  - ibmvnic: Clean up tx pools when closing (fate#322021,
    bsc#1038297).

  - ibmvnic: Continue skb processing after skb completion
    error (fate#322021, bsc#1038297).

  - ibmvnic: Correct crq and resource releasing
    (fate#322021, bsc#1031512).

  - ibmvnic: Create init and release routines for the bounce
    buffer (fate#322021, bsc#1031512).

  - ibmvnic: Create init and release routines for the rx
    pool (fate#322021, bsc#1031512).

  - ibmvnic: Create init and release routines for the tx
    pool (fate#322021, bsc#1031512).

  - ibmvnic: Create init/release routines for stats token
    (fate#322021, bsc#1031512).

  - ibmvnic: Delete napi's when releasing driver resources
    (fate#322021, bsc#1038297).

  - ibmvnic: Disable irq prior to close (fate#322021,
    bsc#1031512).

  - ibmvnic: Do not disable IRQ after scheduling tasklet
    (fate#322021, bsc#1031512).

  - ibmvnic: Fix ibmvnic_change_mac_addr struct format
    (fate#322021, bsc#1031512).

  - ibmvnic: fix missing unlock on error in
    __ibmvnic_reset() (fate#322021, bsc#1038297, Fixes:
    ed651a10875f).

  - ibmvnic: Fixup atomic API usage (fate#322021,
    bsc#1031512).

  - ibmvnic: Free skb's in cases of failure in transmit
    (fate#322021, bsc#1031512).

  - ibmvnic: Insert header on VLAN tagged received frame
    (fate#322021, bsc#1031512).

  - ibmvnic: Merge the two release_sub_crq_queue routines
    (fate#322021, bsc#1031512).

  - ibmvnic: Move initialization of sub crqs to ibmvnic_init
    (fate#322021, bsc#1031512).

  - ibmvnic: Move initialization of the stats token to
    ibmvnic_open (fate#322021, bsc#1031512).

  - ibmvnic: Move queue restarting in ibmvnic_tx_complete
    (fate#322021, bsc#1038297).

  - ibmvnic: Move resource initialization to its own routine
    (fate#322021, bsc#1038297).

  - ibmvnic: Only retrieve error info if present
    (fate#322021, bsc#1031512).

  - ibmvnic: Record SKB RX queue during poll (fate#322021,
    bsc#1038297).

  - ibmvnic: Remove debugfs support (fate#322021,
    bsc#1031512).

  - ibmvnic: Remove inflight list (fate#322021,
    bsc#1031512).

  - ibmvnic: Remove unused bouce buffer (fate#322021,
    bsc#1031512).

  - ibmvnic: Replace is_closed with state field
    (fate#322021, bsc#1038297).

  - ibmvnic: Report errors when failing to release sub-crqs
    (fate#322021, bsc#1031512).

  - ibmvnic: Set real number of rx queues (fate#322021,
    bsc#1031512).

  - ibmvnic: Split initialization of scrqs to its own
    routine (fate#322021, bsc#1031512).

  - ibmvnic: Unmap longer term buffer before free
    (fate#322021, bsc#1031512).

  - ibmvnic: Updated reset handling (fate#322021,
    bsc#1038297).

  - ibmvnic: Update main crq initialization and release
    (fate#322021, bsc#1031512).

  - ibmvnic: Validate napi exist before disabling them
    (fate#322021, bsc#1031512).

  - ibmvnic: Wait for any pending scrqs entries at driver
    close (fate#322021, bsc#1038297).

  - ibmvnic: Whitespace correction in release_rx_pools
    (fate#322021, bsc#1038297).

  - iio: hid-sensor: Store restore poll and hysteresis on S3
    (bsc#1031717).

  - iio: Workaround for kABI breakage by 4.4.67 iio
    hid-sensor changes (stable-4.4.67).

  - infiniband: avoid dereferencing uninitialized dst on
    error path (git-fixes).

  - iommu/arm-smmu: Disable stalling faults for all
    endpoints (bsc#1038843).

  - iommu/dma: Respect IOMMU aperture when allocating
    (bsc#1038842).

  - iommu/exynos: Block SYSMMU while invalidating FLPD cache
    (bsc#1038848).

  - iommu: Handle default domain attach failure
    (bsc#1038846).

  - iommu/vt-d: Do not over-free page table directories
    (bsc#1038847).

  - ipv4, ipv6: ensure raw socket message is big enough to
    hold an IP header (4.4.68 stable queue).

  - ipv6: initialize route null entry in addrconf_init()
    (4.4.68 stable queue).

  - ipv6: reorder ip6_route_dev_notifier after ipv6_dev_notf
    (4.4.68 stable queue).

  - isa: Call isa_bus_init before dependent ISA bus drivers
    register (bsc#1031717).

  - iw_cxgb4: Guard against null cm_id in dump_ep/qp
    (bsc#1026570).

  - KABI: Hide new include in arch/powerpc/kernel/process.c
    (fate#322421).

  - kABI: move and hide new cxgbi device owner field
    (bsc#1018885).

  - kABI: protect cgroup include in kernel/kthread (kabi).

  - kABI: protect struct mnt_namespace (kabi).

  - kABI: protect struct snd_fw_async_midi_port (kabi).

  - kprobes/x86: Fix kernel panic when certain
    exception-handling addresses are probed (4.4.68 stable
    queue).

  - kvm: better MWAIT emulation for guests (bsc#1031142).

  - kvm: nVMX: do not leak PML full vmexit to L1 (4.4.68
    stable queue).

  - kvm: nVMX: initialize PML fields in vmcs02 (4.4.68
    stable queue).

  - leds: ktd2692: avoid harmless maybe-uninitialized
    warning (4.4.68 stable queue).

  - libata-scsi: Fixup ata_gen_passthru_sense()
    (bsc#1040125).

  - lib/mpi: mpi_read_raw_data(): fix nbits calculation
    (bsc#1003581).

  - lib/mpi: mpi_read_raw_data(): purge redundant clearing
    of nbits (bsc#1003581).

  - lib/mpi: mpi_read_raw_from_sgl(): do not include leading
    zero SGEs in nbytes (bsc#1003581).

  - lib/mpi: mpi_read_raw_from_sgl(): fix nbits calculation
    (bsc#1003581).

  - lib/mpi: mpi_read_raw_from_sgl(): fix out-of-bounds
    buffer access (bsc#1003581).

  - lib/mpi: mpi_read_raw_from_sgl(): purge redundant
    clearing of nbits (bsc#1003581).

  - lib/mpi: mpi_read_raw_from_sgl(): replace len argument
    by nbytes (bsc#1003581).

  - lib/mpi: mpi_read_raw_from_sgl(): sanitize meaning of
    indices (bsc#1003581).

  - libnvdimm, pfn: fix 'npfns' vs section alignment
    (bsc#1040125).

  - livepatch: Allow architectures to specify an alternate
    ftrace location (FATE#322421).

  - locking/ww_mutex: Fix compilation of
    __WW_MUTEX_INITIALIZER (bsc#1031717).

  - lpfc: remove incorrect lockdep assertion (bsc#1040125).

  - md.c:didn't unlock the mddev before return EINVAL in
    array_size_store (bsc#1038143).

  - md-cluster: fix potential lock issue in add_new_disk
    (bsc#1041087).

  - md: MD_CLOSING needs to be cleared after called
    md_set_readonly or do_md_stop (bsc#1038142).

  - md/raid1: avoid reusing a resync bio after error
    handling (Fate#311379).

  - media: am437x-vpfe: fix an uninitialized variable bug
    (bsc#1031717).

  - media: b2c2: use IS_REACHABLE() instead of open-coding
    it (bsc#1031717).

  - media: c8sectpfe: Rework firmware loading mechanism
    (bsc#1031717).

  - media: cx231xx-audio: fix NULL-deref at probe
    (bsc#1031717).

  - media: cx231xx-cards: fix NULL-deref at probe
    (bsc#1031717).

  - media: cx23885: uninitialized variable in
    cx23885_av_work_handler() (bsc#1031717).

  - media: DaVinci-VPBE: Check return value of a
    setup_if_config() call in vpbe_set_output()
    (bsc#1031717).

  - media: DaVinci-VPFE-Capture: fix error handling
    (bsc#1031717).

  - media: dib0700: fix NULL-deref at probe (bsc#1031717).

  - media: dvb-usb: avoid link error with dib3000m(b,c|
    (bsc#1031717).

  - media: exynos4-is: fix a format string bug
    (bsc#1031717).

  - media: gspca: konica: add missing endpoint sanity check
    (bsc#1031717).

  - media: lirc_imon: do not leave imon_probe() with mutex
    held (bsc#1031717).

  - media: pvrusb2: reduce stack usage pvr2_eeprom_analyze()
    (bsc#1031717).

  - media: rc: allow rc modules to be loaded if rc-main is
    not a module (bsc#1031717).

  - media: s5p-mfc: Fix unbalanced call to clock management
    (bsc#1031717).

  - media: sh-vou: clarify videobuf2 dependency
    (bsc#1031717).

  - media: staging: media: davinci_vpfe: unlock on error in
    vpfe_reqbufs() (bsc#1031717).

  - media: usbvision: fix NULL-deref at probe (bsc#1031717).

  - media: uvcvideo: Fix empty packet statistic
    (bsc#1031717).

  - mips: R2-on-R6 MULTU/MADDU/MSUBU emulation bugfix
    (4.4.68 stable queue).

  - mmc: debugfs: correct wrong voltage value (bsc#1031717).

  - mm,compaction: serialize waitqueue_active() checks
    (bsc#971975).

  - mmc: sdhci-pxav3: fix higher speed mode capabilities
    (bsc#1031717).

  - mmc: sdhci: restore behavior when setting VDD via
    external regulator (bsc#1031717).

  - mm: fix <linux/pagemap.h> stray kernel-doc notation
    (bnc#971975 VM -- git fixes).

  - mwifiex: Avoid skipping WEP key deletion for AP (4.4.68
    stable queue).

  - mwifiex: debugfs: Fix (sometimes) off-by-1 SSID print
    (4.4.68 stable queue).

  - mwifiex: pcie: fix cmd_buf use-after-free in
    remove/reset (bsc#1031717).

  - mwifiex: Removed unused 'pkt_type' variable
    (bsc#1031717).

  - mwifiex: remove redundant dma padding in AMSDU (4.4.68
    stable queue).

  - mwifiex: Remove unused 'bcd_usb' variable (bsc#1031717).

  - mwifiex: Remove unused 'chan_num' variable
    (bsc#1031717).

  - mwifiex: Remove unused 'pm_flag' variable (bsc#1031717).

  - mwifiex: Remove unused 'sta_ptr' variable (bsc#1031717).

  - nfsd4: minor NFSv2/v3 write decoding cleanup
    (bsc#1034670).

  - nfsd: check for oversized NFSv2/v3 arguments
    (bsc#1034670).

  - nfsd: stricter decoding of write-like NFSv2/v3 ops
    (bsc#1034670).

  - nfs: Fix inode corruption in nfs_prime_dcache()
    (git-fixes).

  - nfs: Fix missing pg_cleanup after
    nfs_pageio_cond_complete() (git-fixes).

  - nfs: Use GFP_NOIO for two allocations in writeback
    (git-fixes).

  - nfsv4.1: Fix Oopsable condition in server callback races
    (git-fixes).

  - ocfs2/dlmglue: prepare tracking logic to avoid recursive
    cluster lock (bsc#1004003).

  - ocfs2: fix deadlock issue when taking inode lock at vfs
    entry points (bsc#1004003).

  - pci: pciehp: Prioritize data-link event over presence
    detect (bsc#1031040,bsc#1037483).

  - pci: Reverse standard ACS vs device-specific ACS
    enabling (bsc#1030057).

  - pci: Work around Intel Sunrise Point PCH incorrect ACS
    capability (bsc#1030057).

  - perf/x86/intel/uncore: Remove SBOX support for Broadwell
    server (bsc#1035887).

  - phy: qcom-usb-hs: Add depends on EXTCON (4.4.68 stable
    queue).

  - pid_ns: Sleep in TASK_INTERRUPTIBLE in
    zap_pid_ns_processes (bnc#1012985).

  - PKCS#7: fix missing break on OID_sha224 case
    (bsc#1031717).

  - platform/x86: fujitsu-laptop: use
    brightness_set_blocking for LED-setting callbacks
    (bsc#1031717).

  - PM / wakeirq: Enable dedicated wakeirq for suspend
    (bsc#1031717).

  - PM / wakeirq: Fix spurious wake-up events for dedicated
    wakeirqs (bsc#1031717).

  - PM / wakeirq: report a wakeup_event on dedicated wekup
    irq (bsc#1031717).

  - power: bq27xxx: fix register numbers of bq27500
    (bsc#1031717).

  - powerpc: Create a helper for getting the kernel toc
    value (FATE#322421).

  - powerpc/ftrace: Add Kconfig & Make glue for
    mprofile-kernel (FATE#322421).

  - powerpc/ftrace: Add support for -mprofile-kernel ftrace
    ABI (FATE#322421).

  - powerpc/ftrace: Use $(CC_FLAGS_FTRACE) when disabling
    ftrace (FATE#322421).

  - powerpc/ftrace: Use generic ftrace_modify_all_code()
    (FATE#322421).

  - powerpc: introduce TIF_KGR_IN_PROGRESS thread flag
    (FATE#322421).

  - powerpc/livepatch: Add livepatch header (FATE#322421).

  - powerpc/livepatch: Add live patching support on ppc64le
    (FATE#322421).

  - powerpc/livepatch: Add livepatch stack to struct
    thread_info (FATE#322421).

  - powerpc/module: Create a special stub for
    ftrace_caller() (FATE#322421).

  - powerpc/module: Mark module stubs with a magic value
    (FATE#322421).

  - powerpc/module: Only try to generate the ftrace_caller()
    stub once (FATE#322421).

  - powerpc/modules: Never restore r2 for a mprofile-kernel
    style mcount() call (FATE#322421).

  - powerpc/powernv: Fix opal_exit tracepoint opcode (4.4.68
    stable queue).

  - power: supply: bq24190_charger: Call
    power_supply_changed() for relevant component (4.4.68
    stable queue).

  - power: supply: bq24190_charger: Call set_mode_host() on
    pm_resume() (4.4.68 stable queue).

  - power: supply: bq24190_charger: Do not read fault
    register outside irq_handle_thread() (4.4.68 stable
    queue).

  - power: supply: bq24190_charger: Fix irq trigger to
    IRQF_TRIGGER_FALLING (4.4.68 stable queue).

  - power: supply: bq24190_charger: Handle fault before
    status on interrupt (4.4.68 stable queue).

  - power: supply: bq24190_charger: Install
    irq_handler_thread() at end of probe() (4.4.68 stable
    queue).

  - ppc64le: Update ppc64le config files to use KGRAFT.

  - printk: Switch to the sync mode when an emergency
    message is printed (bsc#1034995).

  - RDMA/iw_cxgb4: Add missing error codes for act open cmd
    (bsc#1026570).

  - RDMA/iw_cxgb4: Low resource fixes for Completion queue
    (bsc#1026570).

  - RDMA/iw_cxgb4: only read markers_enabled mod param once
    (bsc#1026570).

  - regulator: isl9305: fix array size (bsc#1031717).

  - Revert 'acpi, nfit, libnvdimm: fix interleave set cookie
    calculation (64-bit comparison)' (kabi).

  - Revert 'KVM: nested VMX: disable perf cpuid reporting'
    (4.4.68 stable queue).

  - Revert 'l2tp: take reference on sessions being dumped'
    (kabi).

  - Revert 'mac80211: pass block ack session timeout to to
    driver' (kabi).

  - Revert 'mac80211: RX BA support for sta
    max_rx_aggregation_subframes' (kabi).

  - Revert 'wlcore: Add RX_BA_WIN_SIZE_CHANGE_EVENT event'
    (kabi).

  - rpm/SLES-UEFI-SIGN-Certificate-2048.crt: Update the
    certificate (bsc#1035922)

  - rtnetlink: NUL-terminate IFLA_PHYS_PORT_NAME string
    (4.4.68 stable queue).

  - s390/dasd: check if query host access feature is
    supported (bsc#1037871).

  - scsi: be2iscsi: Add FUNCTION_RESET during driver unload
    (bsc#1038458).

  - scsi: be2iscsi: Add IOCTL to check UER supported
    (bsc#1038458).

  - scsi: be2iscsi: Add TPE recovery feature (bsc#1038458).

  - scsi: be2iscsi: Add V1 of EPFW cleanup IOCTL
    (bsc#1038458).

  - scsi: be2iscsi: allocate enough memory in
    beiscsi_boot_get_sinfo() (bsc#1038458).

  - scsi: be2iscsi: Check all zeroes IP before issuing IOCTL
    (bsc#1038458).

  - scsi: be2iscsi: Fail the sessions immediately after TPE
    (bsc#1038458).

  - scsi: be2iscsi: Fix async PDU handling path
    (bsc#1038458).

  - scsi: be2iscsi: Fix bad WRB index error (bsc#1038458).

  - scsi: be2iscsi: Fix checks for HBA in error state
    (bsc#1038458).

  - scsi: be2iscsi: Fix gateway APIs to support IPv4 & IPv6
    (bsc#1038458).

  - scsi: be2iscsi: Fix POST check and reset sequence
    (bsc#1038458).

  - scsi: be2iscsi: Fix queue and connection parameters
    (bsc#1038458).

  - scsi: be2iscsi: Fix release of DHCP IP in static mode
    (bsc#1038458).

  - scsi: be2iscsi: Fix to add timer for UE detection
    (bsc#1038458).

  - scsi: be2iscsi: Fix to make boot discovery non-blocking
    (bsc#1038458).

  - scsi: be2iscsi: Fix to use correct configuration values
    (bsc#1038458).

  - scsi: be2iscsi: Handle only NET_PARAM in iface_get_param
    (bsc#1038458).

  - scsi: be2iscsi: Move functions to right files
    (bsc#1038458).

  - scsi: be2iscsi: Move VLAN code to common iface_set_param
    (bsc#1038458).

  - scsi: be2iscsi: Reduce driver load/unload time
    (bsc#1038458).

  - scsi: be2iscsi: Remove alloc_mcc_tag &
    beiscsi_pci_soft_reset (bsc#1038458).

  - scsi: be2iscsi: Remove isr_lock and dead code
    (bsc#1038458).

  - scsi: be2iscsi: Rename iface get/set/create/destroy APIs
    (bsc#1038458).

  - scsi: be2iscsi: Replace _bh version for mcc_lock
    spinlock (bsc#1038458).

  - scsi: be2iscsi: Set and return right iface v4/v6 states
    (bsc#1038458).

  - scsi: be2iscsi: Update copyright information
    (bsc#1038458).

  - scsi: be2iscsi: Update iface handle before any set param
    (bsc#1038458).

  - scsi: be2iscsi: Update the driver version (bsc#1038458).

  - scsi: cxgb4i: libcxgbi: add missing module_put()
    (bsc#1018885).

  - scsi: cxlflash: Remove the device cleanly in the system
    shutdown path (bsc#1028310, fate#321597, bsc#1034762).
    cherry-pick from SP3

  - scsi_dh_alua: do not call BUG_ON when updating port
    group (bsc#1028340).

  - scsi_dh_alua: Do not retry for unmapped device
    (bsc#1012910).

  - scsi: fnic: Correcting rport check location in
    fnic_queuecommand_lck (bsc#1035920).

  - scsi: mac_scsi: Fix MAC_SCSI=m option when SCSI=m
    (4.4.68 stable queue).

  - scsi: scsi_dh_alua: Check scsi_device_get() return value
    (bsc#1040125).

  - scsi: scsi_dh_emc: return success in
    clariion_std_inquiry() (4.4.68 stable queue).

  - serial: 8250_omap: Fix probe and remove for PM runtime
    (4.4.68 stable queue).

  - staging: emxx_udc: remove incorrect __init annotations
    (4.4.68 stable queue).

  - staging: rtl8188eu: prevent an underflow in
    rtw_check_beacon_data() (bsc#1031717).

  - staging: wlan-ng: add missing byte order conversion
    (4.4.68 stable queue).

  - sunrpc: Allow xprt->ops->timer method to sleep
    (git-fixes).

  - sunrpc: fix UDP memory accounting (git-fixes).

  - tcp: do not inherit fastopen_req from parent (4.4.68
    stable queue).

  - tcp: do not underestimate skb->truesize in
    tcp_trim_head() (4.4.68 stable queue).

  - tcp: fix wraparound issue in tcp_lp (4.4.68 stable
    queue).

  - tracing/kprobes: Enforce kprobes teardown after testing
    (bnc#1012985).

  - usb: chipidea: Handle extcon events properly (4.4.68
    stable queue).

  - usb: chipidea: Only read/write OTGSC from one place
    (4.4.68 stable queue).

  - usb: host: ehci-exynos: Decrese node refcount on
    exynos_ehci_get_phy() error paths (4.4.68 stable queue).

  - usb: host: ohci-exynos: Decrese node refcount on
    exynos_ehci_get_phy() error paths (4.4.68 stable queue).

  - usb: musb: ux500: Fix NULL pointer dereference at system
    PM (bsc#1038033).

  - usb: serial: ark3116: fix open error handling
    (bnc#1038043).

  - usb: serial: ch341: add register and USB request
    definitions (bnc#1038043).

  - usb: serial: ch341: add support for parity, frame
    length, stop bits (bnc#1038043).

  - usb: serial: ch341: fix baud rate and line-control
    handling (bnc#1038043).

  - usb: serial: ch341: fix line settings after reset-resume
    (bnc#1038043).

  - usb: serial: ch341: fix modem-status handling
    (bnc#1038043).

  - usb: serial: ch341: reinitialize chip on reconfiguration
    (bnc#1038043).

  - usb: serial: digi_acceleport: fix incomplete rx sanity
    check (4.4.68 stable queue).

  - usb: serial: fix compare_const_fl.cocci warnings
    (bnc#1038043).

  - usb: serial: ftdi_sio: fix latency-timer error handling
    (4.4.68 stable queue).

  - usb: serial: io_edgeport: fix descriptor error handling
    (4.4.68 stable queue).

  - usb: serial: io_edgeport: fix epic-descriptor handling
    (bnc#1038043).

  - usb: serial: keyspan_pda: fix receive sanity checks
    (4.4.68 stable queue).

  - usb: serial: mct_u232: fix modem-status error handling
    (4.4.68 stable queue).

  - usb: serial: quatech2: fix control-message error
    handling (bnc#1038043).

  - usb: serial: sierra: fix bogus alternate-setting
    assumption (bnc#1038043).

  - usb: serial: ssu100: fix control-message error handling
    (bnc#1038043).

  - usb: serial: ti_usb_3410_5052: fix control-message error
    handling (4.4.68 stable queue).

  - Use make --output-sync feature when available
    (bsc#1012422). The mesages in make output can interleave
    making it impossible to extract warnings reliably. Since
    version 4 GNU Make supports --output-sync flag that
    prints output of each sub-command atomically preventing
    this issue. Detect the flag and use it if available.

  - Use up spare in struct module for livepatch
    (FATE#322421).

  - vsock: Detach QP check should filter out non matching
    QPs (bsc#1036752).

  - x86/ioapic: Restore IO-APIC irq_chip retrigger callback
    (4.4.68 stable queue).

  - x86/pci-calgary: Fix iommu_free() comparison of unsigned
    expression >= 0 (4.4.68 stable queue).

  - x86/platform/intel-mid: Correct MSI IRQ line for
    watchdog device (4.4.68 stable queue).

  - x86/platform/uv/BAU: Add generic function pointers
    (bsc#1035024).

  - x86/platform/uv/BAU: Add payload descriptor qualifier
    (bsc#1035024).

  - x86/platform/uv/BAU: Add status mmr location fields to
    bau_control (bsc#1035024).

  - x86/platform/uv/BAU: Add UV4-specific functions
    (bsc#1035024).

  - x86/platform/uv/BAU: Add uv_bau_version enumerated
    constants (bsc#1035024).

  - x86/platform/uv/BAU: Add wait_completion to
    bau_operations (bsc#1035024).

  - x86/platform/uv/BAU: Clean up and update printks
    (bsc#1035024).

  - x86/platform/uv/BAU: Cleanup bau_operations declaration
    and instances (bsc#1035024).

  - x86/platform/uv/BAU: Clean up pq_init() (bsc#1035024).

  - x86/platform/uv/BAU: Clean up vertical alignment
    (bsc#1035024).

  - x86/platform/uv/BAU: Convert uv_physnodeaddr() use to
    uv_gpa_to_offset() (bsc#1035024).

  - x86/platform/uv/BAU: Disable software timeout on UV4
    hardware (bsc#1035024).

  - x86/platform/uv/BAU: Fix HUB errors by remove initial
    write to sw-ack register (bsc#1035024).

  - x86/platform/uv/BAU: Fix payload queue setup on UV4
    hardware (bsc#1035024).

  - x86/platform/uv/BAU: Implement uv4_wait_completion with
    read_status (bsc#1035024).

  - x86/platform/uv/BAU: Populate ->uvhub_version with UV4
    version information (bsc#1035024).

  - x86/platform/uv/BAU: Use generic function pointers
    (bsc#1035024).

  - xen: adjust early dom0 p2m handling to xen hypervisor
    behavior (bnc#1031470).

  - xfs: do not assert fail on non-async buffers on ioacct
    decrement (bsc#1041160).

  - xfs: fix eofblocks race with file extending async dio
    writes (bsc#1040929).

  - xfs: Fix missed holes in SEEK_HOLE implementation
    (bsc#1041168).

  - xfs: fix off-by-one on max nr_pages in
    xfs_find_get_desired_pgoff() (bsc#1041168).

  - xfs: in _attrlist_by_handle, copy the cursor back to
    userspace (bsc#1041242).

  - xfs: only return -errno or success from attr
    ->put_listent (bsc#1041242).

  - xfs: Split default quota limits by quota type
    (bsc#1040941).

  - xfs: use ->b_state to fix buffer I/O accounting release
    race (bsc#1041160)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989311"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.70-18.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.70-18.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.70-18.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.70-18.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
