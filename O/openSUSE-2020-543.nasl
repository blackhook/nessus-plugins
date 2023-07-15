#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-543.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136006);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id("CVE-2019-19770", "CVE-2019-3701", "CVE-2019-9458", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11669", "CVE-2020-8834");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-543)");
  script_summary(english:"Check for the openSUSE-2020-543 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-11669: An issue was discovered on the powerpc
    platform. arch/powerpc/kernel/idle_book3s.S did not have
    save/restore functionality for PNV_POWERSAVE_AMR,
    PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR, aka
    CID-53a712bae5dd (bnc#1169390).

  - CVE-2020-8834: KVM on Power8 processors had a
    conflicting use of HSTATE_HOST_R1 to store r1 state in
    kvmppc_hv_entry plus in kvmppc_(save,restore)_tm,
    leading to a stack corruption. Because of this, an
    attacker with the ability run code in kernel space of a
    guest VM can cause the host kernel to panic. There were
    two commits that, according to the reporter, introduced
    the vulnerability: f024ee098476 ('KVM: PPC: Book3S HV:
    Pull out TM state save/restore into separate
    procedures') 87a11bb6a7f7 ('KVM: PPC: Book3S HV: Work
    around XER[SO] bug in fake suspend mode') (bnc#1168276).

  - CVE-2020-11494: An issue was discovered in slc_bump in
    drivers/net/can/slcan.c, which allowed attackers to read
    uninitialized can_frame data, potentially containing
    sensitive information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4 (bnc#1168424).

  - CVE-2019-9458: In the video driver there is a use after
    free due to a race condition. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation (bnc#1168295).

  - CVE-2019-3701: An issue was discovered in can_can_gw_rcv
    in net/can/gw.c. The CAN frame modification rules allow
    bitwise logical operations that can be also applied to
    the can_dlc field. The privileged user 'root' with
    CAP_NET_ADMIN can create a CAN frame modification rule
    that made the data length code a higher value than the
    available CAN frame data size. In combination with a
    configured checksum calculation where the result is
    stored relatively to the end of the data (e.g.
    cgw_csum_xor_rel) the tail of the skb (e.g. frag_list
    pointer in skb_shared_info) can be rewritten which
    finally can cause a system crash. Because of a missing
    check, the CAN drivers may write arbitrary content
    beyond the data registers in the CAN controller's I/O
    memory when processing can-gw manipulated outgoing
    frames (bnc#1120386).

  - CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c
    lacked validation of an sk_family field, which might
    allow attackers to trigger kernel stack corruption via
    crafted system calls (bnc#1167629).

  - CVE-2019-19770: A use-after-free in the debugfs_remove
    function in fs/debugfs/inode.c was fixed. (bnc#1159198).

The following non-security bugs were fixed :

  - ACPI: watchdog: Fix gas->access_width usage
    (bsc#1051510).

  - ACPICA: Introduce ACPI_ACCESS_BYTE_WIDTH() macro
    (bsc#1051510).

  - ALSA: ali5451: remove redundant variable capture_flag
    (bsc#1051510).

  - ALSA: core: Add snd_device_get_state() helper
    (bsc#1051510).

  - ALSA: core: Replace zero-length array with
    flexible-array member (bsc#1051510).

  - ALSA: emu10k1: Fix endianness annotations (bsc#1051510).

  - ALSA: hda/ca0132 - Add Recon3Di quirk to handle
    integrated sound on EVGA X99 Classified motherboard
    (bsc#1051510).

  - ALSA: hda/ca0132 - Replace zero-length array with
    flexible-array member (bsc#1051510).

  - ALSA: hda/realtek - Enable headset mic of Acer X2660G
    with ALC662 (git-fixes).

  - ALSA: hda/realtek - Enable the headset of Acer N50-600
    with ALC662 (git-fixes).

  - ALSA: hda/realtek - Remove now-unnecessary XPS 13
    headphone noise fixups (bsc#1051510).

  - ALSA: hda/realtek - Set principled PC Beep configuration
    for ALC256 (bsc#1051510).

  - ALSA: hda/realtek - a fake key event is triggered by
    running shutup (bsc#1051510).

  - ALSA: hda/realtek: Enable mute LED on an HP system
    (bsc#1051510).

  - ALSA: hda/realtek: Fix pop noise on ALC225 (git-fixes).

  - ALSA: hda: Fix potential access overflow in beep helper
    (bsc#1051510).

  - ALSA: hda: Use scnprintf() for string truncation
    (bsc#1051510).

  - ALSA: hda: default enable CA0132 DSP support
    (bsc#1051510).

  - ALSA: hda: remove redundant assignment to variable
    timeout (bsc#1051510).

  - ALSA: hda_codec: Replace zero-length array with
    flexible-array member (bsc#1051510).

  - ALSA: hdsp: remove redundant assignment to variable err
    (bsc#1051510).

  - ALSA: ice1724: Fix invalid access for enumerated ctl
    items (bsc#1051510).

  - ALSA: info: remove redundant assignment to variable c
    (bsc#1051510).

  - ALSA: korg1212: fix if-statement empty body warnings
    (bsc#1051510).

  - ALSA: line6: Fix endless MIDI read loop (git-fixes).

  - ALSA: pcm.h: add for_each_pcm_streams() (bsc#1051510).

  - ALSA: pcm: Fix superfluous snprintf() usage
    (bsc#1051510).

  - ALSA: pcm: Use a macro for parameter masks to reduce the
    needed cast (bsc#1051510).

  - ALSA: pcm: oss: Avoid plugin buffer overflow
    (git-fixes).

  - ALSA: pcm: oss: Fix regression by buffer overflow fix
    (bsc#1051510).

  - ALSA: pcm: oss: Remove WARNING from snd_pcm_plug_alloc()
    checks (git-fixes).

  - ALSA: pcm: oss: Unlock mutex temporarily for sleeping at
    read/write (bsc#1051510).

  - ALSA: seq: oss: Fix running status after receiving sysex
    (git-fixes).

  - ALSA: seq: virmidi: Fix running status after receiving
    sysex (git-fixes).

  - ALSA: usb-audio: Add delayed_register option
    (bsc#1051510).

  - ALSA: usb-audio: Add support for MOTU MicroBook IIc
    (bsc#1051510).

  - ALSA: usb-audio: Create a registration quirk for
    Kingston HyperX Amp (0951:16d8) (bsc#1051510).

  - ALSA: usb-audio: Do not create a mixer element with
    bogus volume range (bsc#1051510).

  - ALSA: usb-audio: Fix case when USB MIDI interface has
    more than one extra endpoint descriptor (bsc#1051510).

  - ALSA: usb-audio: Fix mixer controls' USB interface for
    Kingston HyperX Amp (0951:16d8) (bsc#1051510).

  - ALSA: usb-audio: Inform devices that need delayed
    registration (bsc#1051510).

  - ALSA: usb-audio: Parse source ID of UAC2 effect unit
    (bsc#1051510).

  - ALSA: usb-audio: Rewrite registration quirk handling
    (bsc#1051510).

  - ALSA: usb-midi: Replace zero-length array with
    flexible-array member (bsc#1051510).

  - ALSA: usx2y: use for_each_pcm_streams() macro
    (bsc#1051510).

  - ALSA: via82xx: Fix endianness annotations (bsc#1051510).

  - ASoC: Intel: atom: Take the drv->lock mutex before
    calling sst_send_slot_map() (bsc#1051510).

  - ASoC: Intel: mrfld: fix incorrect check on p->sink
    (bsc#1051510).

  - ASoC: Intel: mrfld: return error codes when an error
    occurs (bsc#1051510).

  - ASoC: jz4740-i2s: Fix divider written at incorrect
    offset in register (bsc#1051510).

  - ASoC: sun8i-codec: Remove unused dev from codec struct
    (bsc#1051510).

  - Bluetooth: RFCOMM: fix ODEBUG bug in rfcomm_dev_ioctl
    (bsc#1051510).

  - Btrfs: clean up error handling in btrfs_truncate()
    (bsc#1165949).

  - Btrfs: do not reset bio->bi_ops while writing bio
    (bsc#1168273).

  - Btrfs: fix missing delayed iputs on unmount
    (bsc#1165949).

  - Btrfs: fix qgroup double free after failure to reserve
    metadata for delalloc (bsc#1165949).

  - Btrfs: fix race leading to metadata space leak after
    task received signal (bsc#1165949).

  - Btrfs: fix unwritten extent buffers and hangs on future
    writeback attempts (bsc#1168273).

  - Btrfs: make plug in writing meta blocks really work
    (bsc#1168273).

  - Btrfs: only check delayed ref usage in
    should_end_transaction (bsc#1165949).

  - Btrfs: remove bio_flags which indicates a meta block of
    log-tree (bsc#1168273).

  - Crypto: chelsio - Fixes a deadlock between rtnl_lock and
    uld_mutex (bsc#1111666).

  - Crypto: chelsio - Fixes a hang issue during driver
    registration (bsc#1111666).

  - Deprecate NR_UNSTABLE_NFS, use NR_WRITEBACK
    (bsc#1163403).

  - HID: apple: Add support for recent firmware on Magic
    Keyboards (bsc#1051510).

  - IB/hfi1: convert to debugfs_file_get() and -put()
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - Input: add safety guards to input_set_keycode()
    (bsc#1168075).

  - Input: avoid BIT() macro usage in the serio.h UAPI
    header (bsc#1051510).

  - Input: raydium_i2c_ts - fix error codes in
    raydium_i2c_boot_trigger() (bsc#1051510).

  - Input: synaptics - enable RMI on HP Envy 13-ad105ng
    (bsc#1051510).

  - MM: replace PF_LESS_THROTTLE with PF_LOCAL_THROTTLE
    (bsc#1163403).

  - NFC: fdp: Fix a signedness bug in fdp_nci_send_patch()
    (bsc#1051510).

  - NFS: send state management on a single connection
    (bsc#1167005).

  - OMAP: DSS2: remove non-zero check on variable r
    (bsc#1114279)

  - PCI/AER: Factor message prefixes with dev_fmt()
    (bsc#1161561).

  - PCI/AER: Log which device prevents error recovery
    (bsc#1161561).

  - PCI/AER: Remove ERR_FATAL code from ERR_NONFATAL path
    (bsc#1161561).

  - PCI/ASPM: Clear the correct bits when enabling L1
    substates (bsc#1051510).

  - PCI/ERR: Always report current recovery status for udev
    (bsc#1161561).

  - PCI/ERR: Handle fatal error recovery (bsc#1161561).

  - PCI/ERR: Remove duplicated include from err.c
    (bsc#1161561).

  - PCI/ERR: Simplify broadcast callouts (bsc#1161561).

  - PCI/portdrv: Remove pcie_port_bus_type link order
    dependency (bsc#1161561).

  - PCI/switchtec: Fix init_completion race condition with
    poll_wait() (bsc#1051510).

  - PCI: Simplify disconnected marking (bsc#1161561).

  - PCI: Unify device inaccessible (bsc#1161561).

  - PCI: endpoint: Fix clearing start entry in configfs
    (bsc#1051510).

  - PCI: pciehp: Fix MSI interrupt race (bsc#1159037).

  - PCI: portdrv: Initialize service drivers directly
    (bsc#1161561).

  - PM: core: Fix handling of devices deleted during
    system-wide resume (git-fixes).

  - SUNRPC: defer slow parts of rpc_free_client() to a
    workqueue (bsc#1168202).

  - USB: Disable LPM on WD19's Realtek Hub (git-fixes).

  - USB: Fix novation SourceControl XL after suspend
    (git-fixes).

  - USB: cdc-acm: fix rounding error in TIOCSSERIAL
    (git-fixes).

  - USB: hub: Do not record a connect-change event during
    reset-resume (git-fixes).

  - USB: misc: iowarrior: add support for 2 OEMed devices
    (git-fixes).

  - USB: misc: iowarrior: add support for the 100 device
    (git-fixes).

  - USB: misc: iowarrior: add support for the 28 and 28L
    devices (git-fixes).

  - USB: serial: io_edgeport: fix slab-out-of-bounds read in
    edge_interrupt_callback (bsc#1051510).

  - USB: serial: option: add ME910G1 ECM composition 0x110b
    (git-fixes).

  - USB: serial: pl2303: add device-id for HP LD381
    (git-fixes).

  - ahci: Add support for Amazon's Annapurna Labs SATA
    controller (bsc#1169013).

  - apei/ghes: Do not delay GHES polling (bsc#1166982).

  - ath9k: Handle txpower changes even when TPC is disabled
    (bsc#1051510).

  - batman-adv: Avoid spurious warnings from bat_v neigh_cmp
    implementation (bsc#1051510).

  - batman-adv: Do not schedule OGM for disabled interface
    (bsc#1051510).

  - batman-adv: prevent TT request storms by not sending
    inconsistent TT TLVLs (bsc#1051510).

  - binfmt_elf: Do not move brk for INTERP-less ET_EXEC
    (bsc#1169013).

  - binfmt_elf: move brk out of mmap when doing direct
    loader exec (bsc#1169013).

  - blk-mq: Allow blocking queue tag iter callbacks
    (bsc#1167316).

  - block, bfq: fix use-after-free in
    bfq_idle_slice_timer_body (bsc#1168760).

  - block: keep bdi->io_pages in sync with max_sectors_kb
    for stacked devices (bsc#1168762).

  - bnxt_en: Support all variants of the 5750X chip family
    (bsc#1167216).

  - bpf: Explicitly memset some bpf info structures declared
    on the stack (bsc#1083647).

  - bpf: Explicitly memset the bpf_attr structure
    (bsc#1083647).

  - brcmfmac: abort and release host after error
    (bsc#1111666).

  - btrfs: Account for trans_block_rsv in
    may_commit_transaction (bsc#1165949).

  - btrfs: Add enospc_debug printing in
    metadata_reserve_bytes (bsc#1165949).

  - btrfs: Do mandatory tree block check before submitting
    bio (bsc#1168273).

  - btrfs: Improve global reserve stealing logic
    (bsc#1165949).

  - btrfs: Output ENOSPC debug info in inc_block_group_ro
    (bsc#1165949).

  - btrfs: Remove btrfs_inode::delayed_iput_count
    (bsc#1165949).

  - btrfs: Remove fs_info from do_chunk_alloc (bsc#1165949).

  - btrfs: Remove redundant argument of flush_space
    (bsc#1165949).

  - btrfs: Remove redundant mirror_num arg (bsc#1168273).

  - btrfs: Rename bin_search -> btrfs_bin_search
    (bsc#1168273).

  - btrfs: add a flush step for delayed iputs (bsc#1165949).

  - btrfs: add assertions for releasing trans handle
    reservations (bsc#1165949).

  - btrfs: add btrfs_delete_ref_head helper (bsc#1165949).

  - btrfs: add enospc debug messages for ticket failure
    (bsc#1165949).

  - btrfs: add new flushing states for the delayed refs rsv
    (bsc#1165949).

  - btrfs: add space reservation tracepoint for reserved
    bytes (bsc#1165949).

  - btrfs: adjust dirty_metadata_bytes after writeback
    failure of extent buffer (bsc#1168273).

  - btrfs: allow us to use up to 90% of the global rsv for
    unlink (bsc#1165949).

  - btrfs: always reserve our entire size for the global
    reserve (bsc#1165949).

  - btrfs: assert on non-empty delayed iputs (bsc##1165949).

  - btrfs: be more explicit about allowed flush states
    (bsc#1165949).

  - btrfs: call btrfs_create_pending_block_groups
    unconditionally (bsc#1165949).

  - btrfs: catch cow on deleting snapshots (bsc#1165949).

  - btrfs: change the minimum global reserve size
    (bsc#1165949).

  - btrfs: check if there are free block groups for commit
    (bsc#1165949).

  - btrfs: cleanup extent_op handling (bsc#1165949).

  - btrfs: cleanup root usage by btrfs_get_alloc_profile
    (bsc#1165949).

  - btrfs: cleanup the target logic in
    __btrfs_block_rsv_release (bsc#1165949).

  - btrfs: clear space cache inode generation always
    (bsc#1165949).

  - btrfs: delayed-ref: pass delayed_refs directly to
    btrfs_delayed_ref_lock (bsc#1165949).

  - btrfs: do not account global reserve in can_overcommit
    (bsc#1165949).

  - btrfs: do not allow reservations if we have pending
    tickets (bsc#1165949).

  - btrfs: do not call btrfs_start_delalloc_roots in
    flushoncommit (bsc#1165949).

  - btrfs: do not end the transaction for delayed refs in
    throttle (bsc#1165949).

  - btrfs: do not enospc all tickets on flush failure
    (bsc#1165949).

  - btrfs: do not run delayed refs in the end transaction
    logic (bsc#1165949).

  - btrfs: do not run delayed_iputs in commit
    (bsc##1165949).

  - btrfs: do not use ctl->free_space for max_extent_size
    (bsc##1165949).

  - btrfs: do not use global reserve for chunk allocation
    (bsc#1165949).

  - btrfs: drop get_extent from extent_page_data
    (bsc#1168273).

  - btrfs: drop min_size from evict_refill_and_join
    (bsc##1165949).

  - btrfs: drop unused space_info parameter from
    create_space_info (bsc#1165949).

  - btrfs: dump block_rsv details when dumping space info
    (bsc#1165949).

  - btrfs: export __btrfs_block_rsv_release (bsc#1165949).

  - btrfs: export block group accounting helpers
    (bsc#1165949).

  - btrfs: export block_rsv_use_bytes (bsc#1165949).

  - btrfs: export btrfs_block_rsv_add_bytes (bsc#1165949).

  - btrfs: export space_info_add_*_bytes (bsc#1165949).

  - btrfs: export the block group caching helpers
    (bsc#1165949).

  - btrfs: export the caching control helpers (bsc#1165949).

  - btrfs: export the excluded extents helpers
    (bsc#1165949).

  - btrfs: extent-tree: Add lockdep assert when updating
    space info (bsc#1165949).

  - btrfs: extent-tree: Add trace events for space info
    numbers update (bsc#1165949).

  - btrfs: extent-tree: Detect bytes_may_use underflow
    earlier (bsc#1165949).

  - btrfs: extent-tree: Detect bytes_pinned underflow
    earlier (bsc#1165949).

  - btrfs: extent_io: Handle errors better in
    btree_write_cache_pages() (bsc#1168273).

  - btrfs: extent_io: Handle errors better in
    extent_write_full_page() (bsc#1168273).

  - btrfs: extent_io: Handle errors better in
    extent_write_locked_range() (bsc#1168273).

  - btrfs: extent_io: Handle errors better in
    extent_writepages() (bsc#1168273).

  - btrfs: extent_io: Kill dead condition in
    extent_write_cache_pages() (bsc#1168273).

  - btrfs: extent_io: Kill the forward declaration of
    flush_write_bio (bsc#1168273).

  - btrfs: extent_io: Move the BUG_ON() in flush_write_bio()
    one level up (bsc#1168273).

  - btrfs: extent_io: add proper error handling to
    lock_extent_buffer_for_io() (bsc#1168273).

  - btrfs: factor our read/write stage off csum_tree_block
    into its callers (bsc#1168273).

  - btrfs: factor out the ticket flush handling
    (bsc#1165949).

  - btrfs: fix insert_reserved error handling
    (bsc##1165949).

  - btrfs: fix may_commit_transaction to deal with no
    partial filling (bsc#1165949).

  - btrfs: fix truncate throttling (bsc#1165949).

  - btrfs: force chunk allocation if our global rsv is
    larger than metadata (bsc#1165949).

  - btrfs: introduce an evict flushing state (bsc#1165949).

  - btrfs: introduce delayed_refs_rsv (bsc#1165949).

  - btrfs: loop in inode_rsv_refill (bsc#1165949).

  - btrfs: make btrfs_destroy_delayed_refs use
    btrfs_delayed_ref_lock (bsc#1165949).

  - btrfs: make btrfs_destroy_delayed_refs use
    btrfs_delete_ref_head (bsc#1165949).

  - btrfs: make caching_thread use btrfs_find_next_key
    (bsc#1165949).

  - btrfs: merge two flush_write_bio helpers (bsc#1168273).

  - btrfs: migrate btrfs_trans_release_chunk_metadata
    (bsc#1165949).

  - btrfs: migrate inc/dec_block_group_ro code
    (bsc#1165949).

  - btrfs: migrate nocow and reservation helpers
    (bsc#1165949).

  - btrfs: migrate the alloc_profile helpers (bsc#1165949).

  - btrfs: migrate the block group caching code
    (bsc#1165949).

  - btrfs: migrate the block group cleanup code
    (bsc#1165949).

  - btrfs: migrate the block group lookup code
    (bsc#1165949).

  - btrfs: migrate the block group read/creation code
    (bsc#1165949).

  - btrfs: migrate the block group ref counting stuff
    (bsc#1165949).

  - btrfs: migrate the block group removal code
    (bsc#1165949).

  - btrfs: migrate the block group space accounting helpers
    (bsc#1165949).

  - btrfs: migrate the block-rsv code to block-rsv.c
    (bsc#1165949).

  - btrfs: migrate the chunk allocation code (bsc#1165949).

  - btrfs: migrate the delalloc space stuff to it's own home
    (bsc#1165949).

  - btrfs: migrate the delayed refs rsv code (bsc#1165949).

  - btrfs: migrate the dirty bg writeout code (bsc#1165949).

  - btrfs: migrate the global_block_rsv helpers to
    block-rsv.c (bsc#1165949).

  - btrfs: move and export can_overcommit (bsc#1165949).

  - btrfs: move basic block_group definitions to their own
    header (bsc#1165949).

  - btrfs: move btrfs_add_free_space out of a header file
    (bsc#1165949).

  - btrfs: move btrfs_block_rsv definitions into it's own
    header (bsc#1165949).

  - btrfs: move btrfs_raid_group values to btrfs_raid_attr
    table (bsc#1165949).

  - btrfs: move btrfs_space_info_add_*_bytes to space-info.c
    (bsc#1165949).

  - btrfs: move dump_space_info to space-info.c
    (bsc#1165949).

  - btrfs: move reserve_metadata_bytes and supporting code
    to space-info.c (bsc#1165949).

  - btrfs: move space_info to space-info.h (bsc#1165949).

  - btrfs: move the space info update macro to space-info.h
    (bsc#1165949).

  - btrfs: move the space_info handling code to space-info.c
    (bsc#1165949).

  - btrfs: move the subvolume reservation stuff out of
    extent-tree.c (bsc#1165949).

  - btrfs: only check priority tickets for priority flushing
    (bsc#1165949).

  - btrfs: only free reserved extent if we didn't insert it
    (bsc##1165949).

  - btrfs: only reserve metadata_size for inodes
    (bsc#1165949).

  - btrfs: only track ref_heads in delayed_ref_updates
    (bsc#1165949).

  - btrfs: pass root to various extent ref mod functions
    (bsc#1165949).

  - btrfs: qgroup: Do not hold qgroup_ioctl_lock in
    btrfs_qgroup_inherit() (bsc#1165823).

  - btrfs: qgroup: Mark qgroup inconsistent if we're
    inherting snapshot to a new qgroup (bsc#1165823).

  - btrfs: refactor block group replication factor
    calculation to a helper (bsc#1165949).

  - btrfs: refactor priority_reclaim_metadata_space
    (bsc#1165949).

  - btrfs: refactor the ticket wakeup code (bsc#1165949).

  - btrfs: release metadata before running delayed refs
    (bsc##1165949).

  - btrfs: remove orig_bytes from reserve_ticket
    (bsc#1165949).

  - btrfs: rename btrfs_space_info_add_old_bytes
    (bsc#1165949).

  - btrfs: rename do_chunk_alloc to btrfs_chunk_alloc
    (bsc#1165949).

  - btrfs: rename the btrfs_calc_*_metadata_size helpers
    (bsc#1165949).

  - btrfs: replace cleaner_delayed_iput_mutex with a
    waitqueue (bsc#1165949).

  - btrfs: reserve delalloc metadata differently
    (bsc#1165949).

  - btrfs: reserve extra space during evict (bsc#1165949).

  - btrfs: reset max_extent_size on clear in a bitmap
    (bsc##1165949).

  - btrfs: reset max_extent_size properly (bsc##1165949).

  - btrfs: rework btrfs_check_space_for_delayed_refs
    (bsc#1165949).

  - btrfs: rework wake_all_tickets (bsc#1165949).

  - btrfs: roll tracepoint into btrfs_space_info_update
    helper (bsc#1165949).

  - btrfs: run btrfs_try_granting_tickets if a priority
    ticket fails (bsc#1165949).

  - btrfs: run delayed iput at unlink time (bsc#1165949).

  - btrfs: run delayed iputs before committing
    (bsc#1165949).

  - btrfs: set max_extent_size properly (bsc##1165949).

  - btrfs: sink extent_write_full_page tree argument
    (bsc#1168273).

  - btrfs: sink extent_write_locked_range tree parameter
    (bsc#1168273).

  - btrfs: sink flush_fn to extent_write_cache_pages
    (bsc#1168273).

  - btrfs: sink get_extent parameter to
    extent_write_full_page (bsc#1168273).

  - btrfs: sink get_extent parameter to
    extent_write_locked_range (bsc#1168273).

  - btrfs: sink get_extent parameter to extent_fiemap
    (bsc#1168273).

  - btrfs: sink get_extent parameter to extent_readpages
    (bsc#1168273).

  - btrfs: sink get_extent parameter to extent_writepages
    (bsc#1168273).

  - btrfs: sink get_extent parameter to
    get_extent_skip_holes (bsc#1168273).

  - btrfs: sink writepage parameter to
    extent_write_cache_pages (bsc#1168273).

  - btrfs: stop partially refilling tickets when releasing
    space (bsc#1165949).

  - btrfs: stop using block_rsv_release_bytes everywhere
    (bsc#1165949).

  - btrfs: switch to on-stack csum buffer in csum_tree_block
    (bsc#1168273).

  - btrfs: temporarily export btrfs_get_restripe_target
    (bsc#1165949).

  - btrfs: temporarily export fragment_free_space
    (bsc#1165949).

  - btrfs: temporarily export inc_block_group_ro
    (bsc#1165949).

  - btrfs: track DIO bytes in flight (bsc#1165949).

  - btrfs: tree-checker: Remove comprehensive root owner
    check (bsc#1168273).

  - btrfs: unexport can_overcommit (bsc#1165949).

  - btrfs: unexport the temporary exported functions
    (bsc#1165949).

  - btrfs: unify error handling for ticket flushing
    (bsc#1165949).

  - btrfs: unify extent_page_data type passed as void
    (bsc#1168273).

  - btrfs: update may_commit_transaction to use the delayed
    refs rsv (bsc#1165949).

  - btrfs: use btrfs_try_granting_tickets in
    update_global_rsv (bsc#1165949).

  - btrfs: wait on caching when putting the bg cache
    (bsc#1165949).

  - btrfs: wait on ordered extents on abort cleanup
    (bsc#1165949).

  - btrfs: wakeup cleaner thread when adding delayed iput
    (bsc#1165949).

  - ceph: canonicalize server path in place (bsc#1168443).

  - ceph: check POOL_FLAG_FULL/NEARFULL in addition to
    OSDMAP_FULL/NEARFULL (bsc#1169307).

  - ceph: remove the extra slashes in the server path
    (bsc#1168443).

  - cfg80211: check reg_rule for NULL in
    handle_channel_custom() (bsc#1051510).

  - cfg80211: check wiphy driver existence for drvinfo
    report (bsc#1051510).

  - cgroup: memcg: net: do not associate sock with unrelated
    cgroup (bsc#1167290).

  - cifs: ignore cached share root handle closing errors
    (bsc#1166780).

  - clk: imx: Align imx sc clock msg structs to 4
    (bsc#1111666).

  - clk: imx: Align imx sc clock msg structs to 4
    (git-fixes).

  - clk: qcom: rcg: Return failure for RCG update
    (bsc#1051510).

  - configfs: Fix bool initialization/comparison
    (bsc#1051510).

  - cpufreq: Register drivers only after CPU devices have
    been registered (bsc#1051510).

  - cpuidle: Do not unset the driver if it is there already
    (bsc#1051510).

  - crypto: arm64/sha-ce - implement export/import
    (bsc#1051510).

  - crypto: mxs-dcp - fix scatterlist linearization for hash
    (bsc#1051510).

  - crypto: tcrypt - fix printed skcipher [a]sync mode
    (bsc#1051510).

  - debugfs: add support for more elaborate ->d_fsdata
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - debugfs: call debugfs_real_fops() only after
    debugfs_file_get() (bsc#1159198 bsc#1109911).
    Prerequisite for bsc#1159198.

  - debugfs: call debugfs_real_fops() only after
    debugfs_file_get() (bsc#1159198). Prerequisite for
    bsc#1159198.

  - debugfs: convert to debugfs_file_get() and -put()
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - debugfs: debugfs_real_fops(): drop __must_hold sparse
    annotation (bsc#1159198 bsc#1109911). Prerequisite for
    bsc#1159198.

  - debugfs: debugfs_use_start/finish do not exist anymore
    (bsc#1159198). Prerequisite for bsc#1159198.

  - debugfs: defer debugfs_fsdata allocation to first usage
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - debugfs: defer debugfs_fsdata allocation to first usage
    (bsc#1159198). Prerequisite for bsc#1159198.

  - debugfs: fix debugfs_real_fops() build error
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - debugfs: implement per-file removal protection
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - debugfs: purge obsolete SRCU based removal protection
    (bsc#1159198 bsc#1109911). Prerequisite for bsc#1159198.

  - debugfs: simplify __debugfs_remove_file() (bsc#1159198).
    Prerequisite for bsc#1159198.

  - dmaengine: ste_dma40: fix unneeded variable warning
    (bsc#1051510).

  - drm/amd/amdgpu: Fix GPR read from debugfs (v2)
    (bsc#1113956)

  - drm/amd/display: Add link_rate quirk for Apple 15' MBP
    2017 (bsc#1111666).

  - drm/amd/display: Fix wrongly passed static prefix
    (bsc#1111666).

  - drm/amd/display: remove duplicated assignment to
    grph_obj_type (bsc#1051510).

  - drm/amdgpu: fix typo for vcn1 idle check (bsc#1111666).

  - drm/bochs: downgrade pci_request_region failure from
    error to warning (bsc#1051510).

  - drm/bridge: dw-hdmi: fix AVI frame colorimetry
    (bsc#1051510).

  - drm/drm_dp_mst:remove set but not used variable
    'origlen' (bsc#1051510).

  - drm/exynos: dsi: fix workaround for the legacy clock
    name (bsc#1111666).

  - drm/exynos: dsi: propagate error value and silence
    meaningless warning (bsc#1111666).

  - drm/lease: fix WARNING in idr_destroy (bsc#1113956)

  - drm/msm: Set dma maximum segment size for mdss
    (bsc#1051510).

  - drm/msm: Use the correct dma_sync calls harder
    (bsc#1051510).

  - drm/msm: Use the correct dma_sync calls in msm_gem
    (bsc#1051510).

  - drm/msm: stop abusing dma_map/unmap for cache
    (bsc#1051510).

  - drm/sun4i: dsi: Use NULL to signify 'no panel'
    (bsc#1111666).

  - drm/v3d: Replace wait_for macros to remove use of msleep
    (bsc#1111666).

  - drm/vc4: Fix HDMI mode validation (git-fixes).

  - drm_dp_mst_topology: fix broken
    drm_dp_sideband_parse_remote_dpcd_read() (bsc#1051510).

  - dt-bindings: allow up to four clocks for orion-mdio
    (bsc#1051510).

  - efi: Do not attempt to map RCI2 config table if it does
    not exist (jsc#ECO-366, bsc#1168367).

  - efi: Export Runtime Configuration Interface table to
    sysfs (jsc#ECO-366, bsc#1168367).

  - efi: Fix a race and a buffer overflow while reading
    efivars via sysfs (bsc#1164893).

  - efi: x86: move efi_is_table_address() into arch/x86
    (jsc#ECO-366, bsc#1168367).

  - ext4: Avoid ENOSPC when avoiding to reuse recently
    deleted inodes (bsc#1165019).

  - ext4: Check for non-zero journal inum in
    ext4_calculate_overhead (bsc#1167288).

  - ext4: add cond_resched() to __ext4_find_entry()
    (bsc#1166862).

  - ext4: do not assume that mmp_nodename/bdevname have NUL
    (bsc#1166860).

  - ext4: fix a data race in EXT4_I(inode)->i_disksize
    (bsc#1166861).

  - ext4: fix incorrect group count in ext4_fill_super error
    message (bsc#1168765).

  - ext4: fix incorrect inodes per group in error message
    (bsc#1168764).

  - ext4: fix potential race between online resizing and
    write operations (bsc#1166864).

  - ext4: fix potential race between s_flex_groups online
    resizing and access (bsc#1166867).

  - ext4: fix potential race between s_group_info online
    resizing and access (bsc#1166866).

  - ext4: fix race between writepages and enabling
    EXT4_EXTENTS_FL (bsc#1166870).

  - ext4: fix support for inode sizes > 1024 bytes
    (bsc#1164284).

  - ext4: potential crash on allocation error in
    ext4_alloc_flex_bg_array() (bsc#1166940).

  - ext4: rename s_journal_flag_rwsem to s_writepages_rwsem
    (bsc#1166868).

  - ext4: validate the debug_want_extra_isize mount option
    at parse time (bsc#1163897).

  - fat: fix uninit-memory access for partial initialized
    inode (bsc#1051510).

  - fat: work around race with userspace's read via blockdev
    while mounting (bsc#1051510).

  - fbdev/g364fb: Fix build failure (bsc#1051510).

  - fbdev: potential information leak in do_fb_ioctl()
    (bsc#1114279)

  - fbmem: Adjust indentation in fb_prepare_logo and
    fb_blank (bsc#1114279)

  - firmware: arm_sdei: fix double-lock on hibernate with
    shared events (bsc#1111666).

  - firmware: arm_sdei: fix possible double-lock on
    hibernate error path (bsc#1111666).

  - ftrace/kprobe: Show the maxactive number on
    kprobe_events (git-fixes).

  - i2c: hix5hd2: add missed clk_disable_unprepare in remove
    (bsc#1051510).

  - i2c: jz4780: silence log flood on txabrt (bsc#1051510).

  - ibmvfc: do not send implicit logouts prior to NPIV login
    (bsc#1169625 ltc#184611).

  - iio: gyro: adis16136: check ret val for non-zero vs
    less-than-zero (bsc#1051510).

  - iio: imu: adis16400: check ret val for non-zero vs
    less-than-zero (bsc#1051510).

  - iio: imu: adis16480: check ret val for non-zero vs
    less-than-zero (bsc#1051510).

  - iio: imu: adis: check ret val for non-zero vs
    less-than-zero (bsc#1051510).

  - iio: magnetometer: ak8974: Fix negative raw values in
    sysfs (bsc#1051510).

  - iio: potentiostat: lmp9100: fix
    iio_triggered_buffer_(predisable,postenable) positions
    (bsc#1051510).

  - intel_th: Fix user-visible error codes (bsc#1051510).

  - intel_th: pci: Add Elkhart Lake CPU support
    (bsc#1051510).

  - iommu/amd: Fix the configuration of GCR3 table root
    pointer (bsc#1169057).

  - ipmi: fix hung processes in __get_guid() (bsc#1111666).

  - ipmi:ssif: Handle a possible NULL pointer reference
    (bsc#1051510).

  - ipvlan: do not add hardware address of master to its
    unicast filter list (bsc#1137325).

  - irqchip/bcm2835: Quiesce IRQs left enabled by bootloader
    (bsc#1051510).

  - irqdomain: Fix a memory leak in irq_domain_push_irq()
    (bsc#1051510).

  - kABI workaround for pcie_port_bus_type change
    (bsc#1161561).

  - kABI: fixes for debugfs per-file removal protection
    backports (bsc#1159198 bsc#1109911). 

  - kABI: restore debugfs_remove_recursive() (bsc#1159198).

  - kabi fix for (bsc#1168202).

  - libceph: fix alloc_msg_with_page_vector() memory leaks
    (bsc#1169308).

  - libfs: fix infoleak in simple_attr_read() (bsc#1168881).

  - lpfc: add support for translating an RSCN rcv into a
    discovery rescan (bsc#1164777 bsc#1164780 bsc#1165211).

  - lpfc: add support to generate RSCN events for nport
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - mac80211: Do not send mesh HWMP PREQ if HWMP is disabled
    (bsc#1051510).

  - mac80211: consider more elements in parsing CRC
    (bsc#1051510).

  - mac80211: free peer keys before vif down in mesh
    (bsc#1051510).

  - mac80211: mesh: fix RCU warning (bsc#1051510).

  - mac80211: only warn once on chanctx_conf being NULL
    (bsc#1051510).

  - mac80211: rx: avoid RCU list traversal under mutex
    (bsc#1051510).

  - macsec: add missing attribute validation for port
    (bsc#1051510).

  - macsec: fix refcnt leak in module exit routine
    (bsc#1051510).

  - media: dib0700: fix rc endpoint lookup (bsc#1051510).

  - media: flexcop-usb: fix endpoint sanity check
    (git-fixes).

  - media: go7007: Fix URB type for interrupt handling
    (bsc#1051510).

  - media: ov519: add missing endpoint sanity checks
    (bsc#1168829).

  - media: ov6650: Fix .get_fmt() V4L2_SUBDEV_FORMAT_TRY
    support (bsc#1051510).

  - media: ov6650: Fix some format attributes not under
    control (bsc#1051510).

  - media: ov6650: Fix stored crop rectangle not in sync
    with hardware (bsc#1051510).

  - media: ov6650: Fix stored frame format not in sync with
    hardware (bsc#1051510).

  - media: stv06xx: add missing descriptor sanity checks
    (bsc#1168854).

  - media: tda10071: fix unsigned sign extension overflow
    (bsc#1051510).

  - media: usbtv: fix control-message timeouts
    (bsc#1051510).

  - media: v4l2-core: fix entity initialization in
    device_register_subdev (bsc#1051510).

  - media: vsp1: tidyup VI6_HGT_LBn_H() macro (bsc#1051510).

  - media: xirlink_cit: add missing descriptor sanity checks
    (bsc#1051510).

  - mfd: dln2: Fix sanity checking for endpoints
    (bsc#1051510).

  - misc: pci_endpoint_test: Fix to support > 10
    pci-endpoint-test devices (bsc#1051510).

  - mm/filemap.c: do not initiate writeback if mapping has
    no dirty pages (bsc#1168884).

  - mm/memory_hotplug.c: only respect mem= parameter during
    boot stage (bsc#1065600).

  - mmc: sdhci-of-at91: fix cd-gpios for SAMA5D2
    (bsc#1051510).

  - mwifiex: set needed_headroom, not hard_header_len
    (bsc#1051510).

  - net/nfc: Avoid stalls when nfc_alloc_send_skb() returned
    NULL (bsc#1051510).

  - net/sched: flower: add missing validation of
    TCA_FLOWER_FLAGS (networking-stable-20_02_19).

  - net/sched: matchall: add missing validation of
    TCA_MATCHALL_FLAGS (networking-stable-20_02_19).

  - net/smc: fix leak of kernel memory to user space
    (networking-stable-20_02_19).

  - net: dsa: tag_qca: Make sure there is headroom for tag
    (networking-stable-20_02_19).

  - net: ena: Add PCI shutdown handler to allow safe kexec
    (bsc#1167421, bsc#1167423).

  - net: nfc: fix bounds checking bugs on 'pipe'
    (bsc#1051510).

  - net: phy: micrel: kszphy_resume(): add delay after
    genphy_resume() before accessing PHY registers
    (bsc#1051510).

  - net_sched: keep alloc_hash updated after hash allocation
    (git-fixes).

  - netfilter: conntrack: sctp: use distinct states for new
    SCTP connections (bsc#1159199).

  - nvme-multipath: also check for a disabled path if there
    is a single sibling (bsc#1158983).

  - nvme-multipath: do not select namespaces which are about
    to be removed (bsc#1158983).

  - nvme-multipath: factor out a nvme_path_is_disabled
    helper (bsc#1158983).

  - nvme-multipath: fix crash in nvme_mpath_clear_ctrl_paths
    (bsc#1158983).

  - nvme-multipath: fix possible I/O hang when paths are
    updated (bsc#1158983).

  - nvme-multipath: fix possible io hang after ctrl
    reconnect (bsc#1158983).

  - nvme-multipath: remove unused groups_only mode in ana
    log (bsc#1158983).

  - nvme-multipath: round-robin I/O policy (bsc#1158983).

  - nvme: fix a possible deadlock when passthru commands
    sent to a multipath device (bsc#1158983).

  - nvme: fix controller removal race with scan work
    (bsc#1158983).

  - objtool: Add is_static_jump() helper (bsc#1169514).

  - objtool: Add relocation check for alternative sections
    (bsc#1169514).

  - partitions/efi: Fix partition name parsing in GUID
    partition entry (bsc#1168763).

  - perf/amd/uncore: Replace manual sampling check with
    CAP_NO_INTERRUPT flag (bsc#1114279).

  - perf: qcom_l2: fix column exclusion check (git-fixes).

  - pinctrl: core: Remove extra kref_get which blocks hogs
    being freed (bsc#1051510).

  - platform/x86: pmc_atom: Add Lex 2I385SW to
    critclk_systems DMI table (bsc#1051510).

  - powerpc/64/tm: Do not let userspace set regs->trap via
    sigreturn (bsc#1118338 ltc#173734).

  - powerpc/64: mark start_here_multiplatform as __ref
    (bsc#1148868).

  - powerpc/64s: Fix section mismatch warnings from boot
    code (bsc#1148868).

  - powerpc/hash64/devmap: Use H_PAGE_THP_HUGE when setting
    up huge devmap PTE entries (bsc#1065729).

  - powerpc/kprobes: Ignore traps that happened in real mode
    (bsc#1065729).

  - powerpc/mm: Fix section mismatch warning in
    stop_machine_change_mapping() (bsc#1148868).

  - powerpc/pseries/ddw: Extend upper limit for huge DMA
    window for persistent memory (bsc#1142685 ltc#179509).

  - powerpc/pseries/iommu: Fix set but not used values
    (bsc#1142685 ltc#179509).

  - powerpc/pseries/iommu: Use memory@ nodes in max RAM
    address calculation (bsc#1142685 ltc#179509).

  - powerpc/vmlinux.lds: Explicitly retain .gnu.hash
    (bsc#1148868).

  - powerpc/xive: Replace msleep(x) with
    msleep(OPAL_BUSY_DELAY_MS) (bsc#1085030).

  - powerpc/xive: Use XIVE_BAD_IRQ instead of zero to catch
    non configured IPIs (bsc#1085030).

  - pwm: bcm2835: Dynamically allocate base (bsc#1051510).

  - pwm: meson: Fix confusing indentation (bsc#1051510).

  - pwm: pca9685: Fix PWM/GPIO inter-operation
    (bsc#1051510).

  - pwm: rcar: Fix late Runtime PM enablement (bsc#1051510).

  - pwm: renesas-tpu: Fix late Runtime PM enablement
    (bsc#1051510).

  - pxa168fb: fix release function mismatch in probe failure
    (bsc#1051510).

  - qmi_wwan: unconditionally reject 2 ep interfaces
    (bsc#1051510).

  - rtlwifi: rtl8192de: Fix missing callback that tests for
    hw release of buffer (git-fixes).

  - s390/mm: fix dynamic pagetable upgrade for hugetlbfs
    (bsc#1165182 LTC#184102).

  - s390/qeth: fix potential deadlock on workqueue flush
    (bsc#1165185 LTC#184108).

  - scsi: core: avoid repetitive logging of device offline
    messages (bsc#1145929).

  - scsi: core: kABI fix offline_already (bsc#1145929).

  - scsi: fc: Update Descriptor definition and add RDF and
    Link Integrity FPINs (bsc#1164777 bsc#1164780
    bsc#1165211).

  - scsi: ibmvfc: Fix NULL return compiler warning
    (bsc#1161951 ltc#183551). 

  - scsi: lpfc: Change default SCSI LUN QD to 64
    (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654). 

  - scsi: lpfc: Clean up hba max_lun_queue_depth checks
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Copyright updates for 12.6.0.4 patches
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix Fabric hostname registration if system
    hostname changes (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix MDS Latency Diagnostics Err-drop rates
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix RQ buffer leakage when no IOCBs
    available (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix broken Credit Recovery after driver load
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix compiler warning on frame size
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix coverity errors in fmdi attribute
    handling (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix crash after handling a pci error
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix crash in target side cable pulls hitting
    WAIT_FOR_UNREG (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix disablement of FC-AL on lpe35000 models
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix driver nvme rescan logging (bsc#1164777
    bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix erroneous cpu limit of 128 on I/O
    statistics (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix improper flag check for IO type
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix incomplete NVME discovery when target
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix kasan slab-out-of-bounds error in
    lpfc_unreg_login (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix lockdep error - register non-static key
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix lpfc overwrite of sg_cnt field in
    nvmefc_tgt_fcp_req (bsc#1164777 bsc#1164780
    bsc#1165211).

  - scsi: lpfc: Fix lpfc_io_buf resource leak in
    lpfc_get_scsi_buf_s4 error path (bsc#1164777 bsc#1164780
    bsc#1165211).

  - scsi: lpfc: Fix memory leak on lpfc_bsg_write_ebuf_set
    func (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix missing check for CSF in Write Object
    Mbox Rsp (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix ras_log via debugfs (bsc#1164777
    bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix registration of ELS type support in fdmi
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix release of hwq to clear the eq
    relationship (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix scsi host template for SLI3 vports
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix unmap of dpp bars affecting next driver
    load (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Fix update of wq consumer index in
    lpfc_sli4_wq_release (bsc#1164777 bsc#1164780
    bsc#1165211).

  - scsi: lpfc: Fix: Rework setting of fdmi symbolic node
    name registration (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Make debugfs ktime stats generic for NVME
    and SCSI (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Make lpfc_defer_acc_rsp static (bsc#1164777
    bsc#1164780 bsc#1165211).

  - scsi: lpfc: Remove handler for obsolete ELS - Read Port
    Status (RPS) (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Remove prototype FIPS/DSS options from SLI-3
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: Update lpfc version to 12.6.0.3 (bsc#1164777
    bsc#1164780 bsc#1165211).

  - scsi: lpfc: Update lpfc version to 12.6.0.4 (bsc#1164777
    bsc#1164780 bsc#1165211).

  - scsi: lpfc: Update lpfc version to 12.8.0.0 (bsc#1164777
    bsc#1164780 bsc#1165211).

  - scsi: lpfc: add RDF registration and Link Integrity FPIN
    logging (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: fix spelling mistake 'Notication' ->
    'Notification' (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: lpfc: fix spelling mistakes of asynchronous
    (bsc#1164777 bsc#1164780 bsc#1165211).

  - scsi: qla2xxx: Fix I/Os being passed down when FC device
    is being deleted (bsc#1157424).

  - serdev: ttyport: restore client ops on deregistration
    (bsc#1051510).

  - staging: ccree: use signal safe completion wait
    (git-fixes).

  - staging: rtl8188eu: Add ASUS USB-N10 Nano B1 to device
    table (bsc#1051510).

  - staging: vt6656: fix sign of rx_dbm to bb_pre_ed_rssi
    (bsc#1051510).

  - staging: wlan-ng: fix ODEBUG bug in
    prism2sta_disconnect_usb (bsc#1051510).

  - staging: wlan-ng: fix use-after-free Read in
    hfa384x_usbin_callback (bsc#1051510).

  - swiotlb: do not panic on mapping failures (bsc#1162171).

  - swiotlb: remove the overflow buffer (bsc#1162171).

  - thermal: devfreq_cooling: inline all stubs for
    CONFIG_DEVFREQ_THERMAL=n (bsc#1051510).

  - tpm: ibmvtpm: Wait for buffer to be set before
    proceeding (bsc#1065729).

  - tty/serial: atmel: manage shutdown in case of RS485 or
    ISO7816 mode (bsc#1051510).

  - tty: evh_bytechan: Fix out of bounds accesses
    (bsc#1051510).

  - tty: serial: imx: setup the correct sg entry for tx dma
    (bsc#1051510).

  - usb: audio-v2: Add uac2_effect_unit_descriptor
    definition (bsc#1051510).

  - usb: core: hub: do error out if
    usb_autopm_get_interface() fails (git-fixes).

  - usb: core: port: do error out if
    usb_autopm_get_interface() fails (git-fixes).

  - usb: dwc2: Fix in ISOC request length checking
    (git-fixes).

  - usb: gadget: composite: Fix bMaxPower for SuperSpeedPlus
    (git-fixes).

  - usb: gadget: f_fs: Fix use after free issue as part of
    queue failure (bsc#1051510).

  - usb: host: xhci-plat: add a shutdown (git-fixes).

  - usb: musb: Disable pullup at init (git-fixes).

  - usb: musb: fix crash with highmen PIO and usbmon
    (bsc#1051510).

  - usb: quirks: add NO_LPM quirk for Logitech Screen Share
    (git-fixes).

  - usb: quirks: add NO_LPM quirk for RTL8153 based ethernet
    adapters (git-fixes).

  - usb: storage: Add quirk for Samsung Fit flash
    (git-fixes).

  - usb: uas: fix a plug & unplug racing (git-fixes).

  - usb: xhci: apply XHCI_SUSPEND_DELAY to AMD XHCI
    controller 1022:145c (git-fixes).

  - virtio-blk: improve virtqueue error to BLK_STS
    (bsc#1167627).

  - virtio_ring: fix unmap of indirect descriptors
    (bsc#1162171).

  - x86/mce: Fix logic and comments around MSR_PPIN_CTL
    (bsc#1114279).

  - x86/pkeys: Manually set X86_FEATURE_OSPKE to preserve
    existing changes (bsc#1114279).

  - xen/blkfront: fix memory allocation flags in
    blkfront_setup_indirect() (bsc#1168486).

  - xhci: Do not open code __print_symbolic() in xhci trace
    events (git-fixes).

  - xhci: apply XHCI_PME_STUCK_QUIRK to Intel Comet Lake
    platforms (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169625"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.48.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
