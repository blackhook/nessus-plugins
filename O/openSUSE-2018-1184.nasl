#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1184.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118194);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13096", "CVE-2018-13097", "CVE-2018-13098", "CVE-2018-13099", "CVE-2018-13100", "CVE-2018-14613", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-16276", "CVE-2018-16597", "CVE-2018-17182", "CVE-2018-7480", "CVE-2018-7757");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-1184)");
  script_summary(english:"Check for the openSUSE-2018-1184 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.159 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-13096: A denial of service (out-of-bounds
    memory access and BUG) can occur upon encountering an
    abnormal bitmap size when mounting a crafted f2fs image
    (bnc#1100062).

  - CVE-2018-13097: There is an out-of-bounds read or a
    divide-by-zero error for an incorrect user_block_count
    in a corrupted f2fs image, leading to a denial of
    service (BUG) (bnc#1100061).

  - CVE-2018-13098: A denial of service (slab out-of-bounds
    read and BUG) can occur for a modified f2fs filesystem
    image in which FI_EXTRA_ATTR is set in an inode
    (bnc#1100060).

  - CVE-2018-13099: A denial of service (out-of-bounds
    memory access and BUG) can occur for a modified f2fs
    filesystem image in which an inline inode contains an
    invalid reserved blkaddr (bnc#1100059).

  - CVE-2018-13100: An issue was discovered in
    fs/f2fs/super.c which did not properly validate
    secs_per_zone in a corrupted f2fs image, as demonstrated
    by a divide-by-zero error (bnc#1100056).

  - CVE-2018-14613: There is an invalid pointer dereference
    in io_ctl_map_page() when mounting and operating a
    crafted btrfs image, because of a lack of block group
    item validation in check_leaf_item in
    fs/btrfs/tree-checker.c (bnc#1102896).

  - CVE-2018-14617: There is a NULL pointer dereference and
    panic in hfsplus_lookup() in fs/hfsplus/dir.c when
    opening a file (that is purportedly a hard link) in an
    hfs+ filesystem that has malformed catalog data, and is
    mounted read-only without a metadata directory
    (bnc#1102870).

  - CVE-2018-14633: A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in the Linux kernel in a way an authentication
    request from an ISCSI initiator is processed. An
    unauthenticated remote attacker can cause a stack-based
    buffer overflow and smash up to 17 bytes of the stack.
    The attack requires the iSCSI target to be enabled on
    the victim host. Depending on how the target's code was
    built (i.e. depending on a compiler, compile flags and
    hardware architecture) an attack may lead to a system
    crash and thus to a denial-of-service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely. Kernel versions 4.18.x,
    4.14.x and 3.10.x are believed to be vulnerable
    (bnc#1107829).

  - CVE-2018-16276: Local attackers could use user access
    read/writes with incorrect bounds checking in the yurex
    USB driver to crash the kernel or potentially escalate
    privileges (bnc#1106095).

  - CVE-2018-16597: Incorrect access checking in overlayfs
    mounts could be used by local attackers to modify or
    truncate files in the underlying filesystem
    (bnc#1106512).

  - CVE-2018-17182: The vmacache_flush_all function in
    mm/vmacache.c mishandled sequence number overflows. An
    attacker can trigger a use-after-free (and possibly gain
    privileges) via certain thread creation, map, unmap,
    invalidation, and dereference operations (bnc#1108399).

  - CVE-2018-7480: The blkcg_init_queue function in
    block/blk-cgroup.c allowed local users to cause a denial
    of service (double free) or possibly have unspecified
    other impact by triggering a creation failure
    (bnc#1082863).

  - CVE-2018-7757: Memory leak in the sas_smp_get_phy_events
    function in drivers/scsi/libsas/sas_expander.c allowed
    local users to cause a denial of service (memory
    consumption) via many read accesses to files in the
    /sys/class/sas_phy directory, as demonstrated by the
    /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file
    (bnc#1084536).

The following non-security bugs were fixed :

  - alsa: bebob: use address returned by kmalloc() instead
    of kernel stack for streaming DMA mapping (bnc#1012382).

  - alsa: emu10k1: fix possible info leak to userspace on
    SNDRV_EMU10K1_IOCTL_INFO (bnc#1012382).

  - alsa: hda - Fix cancel_work_sync() stall from jackpoll
    work (bnc#1012382).

  - alsa: msnd: Fix the default sample sizes (bnc#1012382).

  - alsa: pcm: Fix snd_interval_refine first/last with open
    min/max (bnc#1012382).

  - alsa: usb-audio: Fix multiple definitions in
    AU0828_DEVICE() macro (bnc#1012382).

  - arc: [plat-axs*]: Enable SWAP (bnc#1012382).

  - arm64: bpf: jit JMP_JSET_(X,K) (bsc#1110613).

  - arm64: Correct type for PUD macros (bsc#1110600).

  - arm64: dts: qcom: db410c: Fix Bluetooth LED trigger
    (bnc#1012382).

  - arm64: fix erroneous __raw_read_system_reg() cases
    (bsc#1110606).

  - arm64: Fix potential race with hardware DBM in
    ptep_set_access_flags() (bsc#1110605).

  - arm64: fpsimd: Avoid FPSIMD context leakage for the init
    task (bsc#1110603).

  - arm64: kasan: avoid bad virt_to_pfn() (bsc#1110612).

  - arm64: kasan: avoid pfn_to_nid() before page array is
    initialized (bsc#1110619).

  - arm64/kasan: do not allocate extra shadow memory
    (bsc#1110611).

  - arm64: kernel: Update kerneldoc for cpu_suspend() rename
    (bsc#1110602).

  - arm64: kgdb: handle read-only text / modules
    (bsc#1110604).

  - arm64/mm/kasan: do not use vmemmap_populate() to
    initialize shadow (bsc#1110618).

  - arm64: ptrace: Avoid setting compat FP[SC]R to garbage
    if get_user fails (bsc#1110601).

  - arm64: supported.conf: mark armmmci as not supported

  - arm64 Update config files. (bsc#1110468) Set
    MMC_QCOM_DML to build-in and delete driver from
    supported.conf

  - arm64: vdso: fix clock_getres for 4GiB-aligned res
    (bsc#1110614).

  - arm: exynos: Clear global variable on init error path
    (bnc#1012382).

  - arm: hisi: check of_iomap and fix missing of_node_put
    (bnc#1012382).

  - arm: hisi: fix error handling and missing of_node_put
    (bnc#1012382).

  - arm: hisi: handle of_iomap and fix missing of_node_put
    (bnc#1012382).

  - asm/sections: add helpers to check for section data
    (bsc#1063026).

  - asoc: cs4265: fix MMTLR Data switch control
    (bnc#1012382).

  - asoc: wm8994: Fix missing break in switch (bnc#1012382).

  - ata: libahci: Correct setting of DEVSLP register
    (bnc#1012382).

  - ath10k: disable bundle mgmt tx completion event support
    (bnc#1012382).

  - ath10k: prevent active scans on potential unusable
    channels (bnc#1012382).

  - audit: fix use-after-free in audit_add_watch
    (bnc#1012382).

  - autofs: fix autofs_sbi() does not check super block type
    (bnc#1012382).

  - binfmt_elf: Respect error return from `regset->active'
    (bnc#1012382).

  - block: bvec_nr_vecs() returns value for wrong slab
    (bsc#1082979).

  - Bluetooth: h5: Fix missing dependency on
    BT_HCIUART_SERDEV (bnc#1012382).

  - Bluetooth: hidp: Fix handling of strncpy for hid->name
    information (bnc#1012382).

  - bpf: fix overflow in prog accounting (bsc#1012382).

  - btrfs: Add checker for EXTENT_CSUM (bsc#1102882,
    bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).

  - btrfs: Add sanity check for EXTENT_DATA when reading out
    leaf (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: Check if item pointer overlaps with the item
    itself (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: Check that each block group has corresponding
    chunk at mount time (bsc#1102882, bsc#1102896,
    bsc#1102879, bsc#1102877, bsc#1102875,).

  - btrfs: Introduce mount time chunk <-> dev extent mapping
    check (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: Move leaf and node validation checker to
    tree-checker.c (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: relocation: Only remove reloc rb_trees if reloc
    control has been initialized (bnc#1012382).

  - btrfs: replace: Reset on-disk dev stats value after
    replace (bnc#1012382).

  - btrfs: scrub: Do not use inode page cache in
    scrub_handle_errored_block() (bsc#1108096).

  - btrfs: tree-checker: Add checker for dir item
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: Detect invalid and empty essential
    trees (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: tree-checker: Enhance btrfs_check_node output
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: Enhance output for btrfs_check_leaf
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: Enhance output for check_csum_item
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: Enhance output for
    check_extent_data_item (bsc#1102882, bsc#1102896,
    bsc#1102879, bsc#1102877, bsc#1102875,).

  - btrfs: tree-checker: Fix false panic for sanity test
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: Replace root parameter with fs_info
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: use %zu format string for size_t
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: use %zu format string for size_t
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: tree-checker: Verify block_group_item
    (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875,).

  - btrfs: use correct compare function of
    dirty_metadata_bytes (bnc#1012382).

  - btrfs: Verify that every chunk has corresponding block
    group at mount time (bsc#1102882, bsc#1102896,
    bsc#1102879, bsc#1102877, bsc#1102875,).

  - cfq: Give a chance for arming slice idle timer in case
    of group_idle (bnc#1012382).

  - cifs: check if SMB2 PDU size has been padded and
    suppress the warning (bnc#1012382).

  - cifs: fix wrapping bugs in num_entries() (bnc#1012382).

  - cifs: integer overflow in in SMB2_ioctl() (bsc#1012382).

  - cifs: prevent integer overflow in nxt_dir_entry()
    (bnc#1012382).

  - clk: imx6ul: fix missing of_node_put() (bnc#1012382).

  - coresight: Handle errors in finding input/output ports
    (bnc#1012382).

  - coresight: tpiu: Fix disabling timeouts (bnc#1012382).

  - cpu/hotplug: Fix SMT supported evaluation (bsc#1089343).

  - crypto: clarify licensing of OpenSSL asm code ().

  - crypto: sharah - Unregister correct algorithms for
    SAHARA 3 (bnc#1012382).

  - crypto: vmx - Remove overly verbose printk from AES XTS
    init (git-fixes).

  - debugobjects: Make stack check warning more informative
    (bnc#1012382).

  - Define early_radix_enabled() (bsc#1094244).

  - Delete
    patches.fixes/slab-__GFP_ZERO-is-incompatible-with-a-con
    structor.patch (bnc#1110297) we still have a code which
    uses both __GFP_ZERO and constructors. The code seems to
    be correct and the warning does more harm than good so
    revert for the the meantime until we catch offenders.

  - dmaengine: pl330: fix irq race with terminate_all
    (bnc#1012382).

  - dm kcopyd: avoid softlockup in run_complete_job
    (bnc#1012382).

  - dm-mpath: do not try to access NULL rq (bsc#1110337).

  - dm-mpath: finally fixup cmd_flags (bsc#1110930).

  - drivers: net: cpsw: fix parsing of phy-handle DT
    property in dual_emac config (bnc#1012382).

  - drivers: net: cpsw: fix segfault in case of bad
    phy-handle (bnc#1012382).

  - drm/amdkfd: Fix error codes in kfd_get_process
    (bnc#1012382).

  - drm/nouveau/drm/nouveau: Use pm_runtime_get_noresume()
    in connector_detect() (bnc#1012382).

  - drm/nouveau: tegra: Detach from ARM DMA/IOMMU mapping
    (bnc#1012382).

  - EDAC: Fix memleak in module init error path
    (bsc#1109441).

  - EDAC, i7core: Fix memleaks and use-after-free on probe
    and remove (1109441).

  - ethernet: ti: davinci_emac: add missing of_node_put
    after calling of_parse_phandle (bnc#1012382).

  - ethtool: Remove trailing semicolon for static inline
    (bnc#1012382).

  - ext4: avoid divide by zero fault when deleting corrupted
    inline directories (bnc#1012382).

  - ext4: do not mark mmp buffer head dirty (bnc#1012382).

  - ext4: fix online resize's handling of a too-small final
    block group (bnc#1012382).

  - ext4: fix online resizing for bigalloc file systems with
    a 1k block size (bnc#1012382).

  - ext4: recalucate superblock checksum after updating free
    blocks/inodes (bnc#1012382).

  - f2fs: do not set free of current section (bnc#1012382).

  - f2fs: fix to do sanity check with
    (sit,nat)_ver_bitmap_bytesize (bnc#1012382).

  - fat: validate ->i_start before using (bnc#1012382).

  - fbdev: Distinguish between interlaced and progressive
    modes (bnc#1012382).

  - fbdev/via: fix defined but not used warning
    (bnc#1012382).

  - Follow-up fix for
    patches.arch/01-jump_label-reduce-the-size-of-struct-sta
    tic_key-kabi.patch. (bsc#1108803)

  - fork: do not copy inconsistent signal handler state to
    child (bnc#1012382).

  - fs/dcache.c: fix kmemcheck splat at
    take_dentry_name_snapshot() (bnc#1012382).

  - fs/eventpoll: loosen irq-safety when possible
    (bsc#1096052).

  - genirq: Delay incrementing interrupt count if it's
    disabled/pending (bnc#1012382).

  - gfs2: Special-case rindex for gfs2_grow (bnc#1012382).

  - gpiolib: Mark gpio_suffixes array with __maybe_unused
    (bnc#1012382).

  - gpio: ml-ioh: Fix buffer underwrite on probe error path
    (bnc#1012382).

  - gpio: tegra: Move driver registration to subsys_init
    level (bnc#1012382).

  - gso_segment: Reset skb->mac_len after modifying network
    header (bnc#1012382).

  - hfsplus: do not return 0 when fill_super() failed
    (bnc#1012382).

  - hfs: prevent crash on exit from failed search
    (bnc#1012382).

  - HID: sony: Support DS4 dongle (bnc#1012382).

  - HID: sony: Update device ids (bnc#1012382).

  - i2c: i801: fix DNV's SMBCTRL register offset
    (bnc#1012382).

  - i2c: xiic: Make the start and the byte count write
    atomic (bnc#1012382).

  - i2c: xlp9xx: Add support for SMBAlert (bsc#1103308).

  - i2c: xlp9xx: Fix case where SSIF read transaction
    completes early (bsc#1103308).

  - i2c: xlp9xx: Fix issue seen when updating receive length
    (bsc#1103308).

  - i2c: xlp9xx: Make sure the transfer size is not more
    than I2C_SMBUS_BLOCK_SIZE (bsc#1103308).

  - ib/ipoib: Avoid a race condition between start_xmit and
    cm_rep_handler (bnc#1012382).

  - ib_srp: Remove WARN_ON in srp_terminate_io()
    (bsc#1094562).

  - input: atmel_mxt_ts - only use first T9 instance
    (bnc#1012382).

  - iommu/amd: Return devid as alias for ACPI HID devices
    (bsc#1106105).

  - iommu/arm-smmu-v3: sync the OVACKFLG to PRIQ consumer
    register (bnc#1012382).

  - iommu/ipmmu-vmsa: Fix allocation in atomic context
    (bnc#1012382).

  - ipmi:ssif: Add support for multi-part transmit messages
    > 2 parts (bsc#1103308).

  - ipv6: fix possible use-after-free in ip6_xmit()
    (bnc#1012382).

  - ipvs: fix race between ip_vs_conn_new() and
    ip_vs_del_dest() (bnc#1012382).

  - irqchip/bcm7038-l1: Hide cpu offline callback when
    building for !SMP (bnc#1012382).

  - irqchip/gic-v3: Add missing barrier to 32bit version of
    gic_read_iar() (bnc#1012382).

  - iw_cxgb4: only allow 1 flush on user qps (bnc#1012382).

  - KABI: move the new handler to end of machdep_calls and
    hide it from genksyms (bsc#1094244).

  - kabi protect hnae_ae_ops (bsc#1107924).

  - kbuild: add .DELETE_ON_ERROR special target
    (bnc#1012382).

  - kbuild: make missing $DEPMOD a Warning instead of an
    Error (bnc#1012382).

  - kernel/params.c: downgrade warning for unsafe parameters
    (bsc#1050549).

  - kprobes/x86: Release insn_slot in failure path
    (bsc#1110006).

  - kthread: fix boot hang (regression) on MIPS/OpenRISC
    (bnc#1012382).

  - kthread: Fix use-after-free if kthread fork fails
    (bnc#1012382).

  - kvm: nVMX: Do not expose MPX VMX controls when guest MPX
    disabled (bsc#1106240).

  - kvm: nVMX: Do not flush TLB when vmcs12 uses VPID
    (bsc#1106240).

  - kvm: x86: Do not re-(try,execute) after failed emulation
    in L2 (bsc#1106240).

  - kvm: x86: Do not use kvm_x86_ops->mpx_supported()
    directly (bsc#1106240).

  - kvm: x86: fix APIC page invalidation (bsc#1106240).

  - kvm/x86: remove WARN_ON() for when vm_munmap() fails
    (bsc#1106240).

  - kvm: x86: SVM: Call x86_spec_ctrl_set_guest/host() with
    interrupts disabled (bsc#1106240).

  - l2tp: cast l2tp traffic counter to unsigned
    (bsc#1099810).

  - locking/osq_lock: Fix osq_lock queue corruption
    (bnc#1012382).

  - locking/rwsem-xadd: Fix missed wakeup due to reordering
    of load (bnc#1012382).

  - lpfc: fixup crash in lpfc_els_unsol_buffer()
    (bsc#1107318).

  - mac80211: restrict delayed tailroom needed decrement
    (bnc#1012382).

  - macintosh/via-pmu: Add missing mmio accessors
    (bnc#1012382).

  - md/raid1: exit sync request if MD_RECOVERY_INTR is set
    (git-fixes).

  - md/raid5: fix data corruption of replacements after
    originals dropped (bnc#1012382).

  - media: videobuf2-core: check for q->error in
    vb2_core_qbuf() (bnc#1012382).

  - mei: bus: type promotion bug in mei_nfc_if_version()
    (bnc#1012382).

  - mei: me: allow runtime pm for platform with D0i3
    (bnc#1012382).

  - mfd: sm501: Set coherent_dma_mask when creating
    subdevices (bnc#1012382).

  - mfd: ti_am335x_tscadc: Fix struct clk memory leak
    (bnc#1012382).

  - misc: hmc6352: fix potential Spectre v1 (bnc#1012382).

  - misc: mic: SCIF Fix scif_get_new_port() error handling
    (bnc#1012382).

  - misc: ti-st: Fix memory leak in the error path of
    probe() (bnc#1012382).

  - mmc: mmci: stop building qcom dml as module
    (bsc#1110468).

  - mm/fadvise.c: fix signed overflow UBSAN complaint
    (bnc#1012382).

  - mm: fix devmem_is_allowed() for sub-page System RAM
    intersections (bsc#1110006).

  - mm: get rid of vmacache_flush_all() entirely
    (bnc#1012382).

  - mm: shmem.c: Correctly annotate new inodes for lockdep
    (bnc#1012382).

  - mtdchar: fix overflows in adjustment of `count`
    (bnc#1012382).

  - mtd/maps: fix solutionengine.c printk format warnings
    (bnc#1012382).

  - neighbour: confirm neigh entries when ARP packet is
    received (bnc#1012382).

  - net/9p: fix error path of p9_virtio_probe (bnc#1012382).

  - net/appletalk: fix minor pointer leak to userspace in
    SIOCFINDIPDDPRT (bnc#1012382).

  - net: bcmgenet: use MAC link status for fixed phy
    (bnc#1012382).

  - net: dcb: For wild-card lookups, use priority -1, not 0
    (bnc#1012382).

  - net: ena: Eliminate duplicate barriers on weakly-ordered
    archs (bsc#1108240).

  - net: ena: fix device destruction to gracefully free
    resources (bsc#1108240).

  - net: ena: fix driver when PAGE_SIZE == 64kB
    (bsc#1108240).

  - net: ena: fix incorrect usage of memory barriers
    (bsc#1108240).

  - net: ena: fix missing calls to READ_ONCE (bsc#1108240).

  - net: ena: fix missing lock during device destruction
    (bsc#1108240).

  - net: ena: fix potential double ena_destroy_device()
    (bsc#1108240).

  - net: ena: fix surprise unplug NULL dereference kernel
    crash (bsc#1108240).

  - net: ethernet: mvneta: Fix napi structure mixup on
    armada 3700 (bsc#1110616).

  - net: ethernet: ti: cpsw: fix mdio device reference leak
    (bnc#1012382).

  - netfilter: x_tables: avoid stack-out-of-bounds read in
    xt_copy_counters_from_user (bnc#1012382).

  - net: hns: add netif_carrier_off before change speed and
    duplex (bsc#1107924).

  - net: hns: add the code for cleaning pkt in chip
    (bsc#1107924).

  - net: hp100: fix always-true check for link up state
    (bnc#1012382).

  - net: mvneta: fix mtu change on port without link
    (bnc#1012382).

  - net: mvneta: fix mvneta_config_rss on armada 3700
    (bsc#1110615).

  - nfc: Fix possible memory corruption when handling SHDLC
    I-Frame commands (bnc#1012382).

  - nfc: Fix the number of pipes (bnc#1012382).

  - nfs: Use an appropriate work queue for direct-write
    completion (bsc#1082519).

  - nfsv4.0 fix client reference leak in callback
    (bnc#1012382).

  - nvme_fc: add 'nvme_discovery' sysfs attribute to fc
    transport device (bsc#1044189).

  - nvmet: fixup crash on NULL device path (bsc#1082979).

  - ocfs2: fix ocfs2 read block panic (bnc#1012382).

  - ovl: modify ovl_permission() to do checks on two inodes
    (bsc#1106512)

  - ovl: proper cleanup of workdir (bnc#1012382).

  - ovl: rename is_merge to is_lowest (bnc#1012382).

  - parport: sunbpp: fix error return code (bnc#1012382).

  - partitions/aix: append null character to print data from
    disk (bnc#1012382).

  - partitions/aix: fix usage of uninitialized lv_info and
    lvname structures (bnc#1012382).

  - PCI: altera: Fix bool initialization in
    tlp_read_packet() (bsc#1109806).

  - PCI: designware: Fix I/O space page leak (bsc#1109806).

  - PCI: designware: Fix pci_remap_iospace() failure path
    (bsc#1109806).

  - PCI: mvebu: Fix I/O space end address calculation
    (bnc#1012382).

  - PCI: OF: Fix I/O space page leak (bsc#1109806).

  - PCI: pciehp: Fix unprotected list iteration in IRQ
    handler (bsc#1109806).

  - PCI: shpchp: Fix AMD POGO identification (bsc#1109806).

  - PCI: Supply CPU physical address (not bus address) to
    iomem_is_exclusive() (bsc#1109806).

  - PCI: versatile: Fix I/O space page leak (bsc#1109806).

  - PCI: versatile: Fix pci_remap_iospace() failure path
    (bsc#1109806).

  - PCI: xgene: Fix I/O space page leak (bsc#1109806).

  - PCI: xilinx: Add missing of_node_put() (bsc#1109806).

  - perf powerpc: Fix callchain ip filtering (bnc#1012382).

  - perf powerpc: Fix callchain ip filtering when return
    address is in a register (bnc#1012382).

  - perf tools: Allow overriding MAX_NR_CPUS at compile time
    (bnc#1012382).

  - phy: qcom-ufs: add MODULE_LICENSE tag (bsc#1110468).

  - pinctrl: qcom: spmi-gpio: Fix pmic_gpio_config_get() to
    be compliant (bnc#1012382).

  - pipe: actually allow root to exceed the pipe buffer
    limit (git-fixes).

  - platform/x86: alienware-wmi: Correct a memory leak
    (bnc#1012382).

  - platform/x86: asus-nb-wmi: Add keymap entry for lid flip
    action on UX360 (bnc#1012382).

  - platform/x86: toshiba_acpi: Fix defined but not used
    build warnings (bnc#1012382).

  - powerpc/64: Do load of PACAKBASE in LOAD_HANDLER
    (bsc#1094244).

  - powerpc/64s: move machine check SLB flushing to mm/slb.c
    (bsc#1094244).

  - powerpc/book3s: Fix MCE console messages for
    unrecoverable MCE (bsc#1094244).

  - powerpc/fadump: cleanup crash memory ranges support
    (bsc#1103269).

  - powerpc/fadump: re-register firmware-assisted dump if
    already registered (bsc#1108170, bsc#1108823).

  - powerpc: Fix size calculation using resource_size()
    (bnc#1012382).

  - powerpc/mce: Fix SLB rebolting during MCE recovery path
    (bsc#1094244).

  - powerpc/mce: Move 64-bit machine check code into mce.c
    (bsc#1094244).

  - powerpc/numa: Use associativity if VPHN hcall is
    successful (bsc#1110363).

  - powerpc/perf/hv-24x7: Fix off-by-one error in
    request_buffer check (git-fixes).

  - powerpc/powernv/ioda2: Reduce upper limit for DMA window
    size (bsc#1066223).

  - powerpc/powernv: opal_put_chars partial write fix
    (bnc#1012382).

  - powerpc/powernv: Rename machine_check_pSeries_early() to
    powernv (bsc#1094244).

  - powerpc/pseries: Avoid using the size greater than
    RTAS_ERROR_LOG_MAX (bnc#1012382).

  - powerpc/pseries: Defer the logging of rtas error to irq
    work queue (bsc#1094244).

  - powerpc/pseries: Define MCE error event section
    (bsc#1094244).

  - powerpc/pseries: Disable CPU hotplug across migrations
    (bsc#1066223).

  - powerpc/pseries: Display machine check error details
    (bsc#1094244).

  - powerpc/pseries: Dump the SLB contents on SLB MCE errors
    (bsc#1094244).

  - powerpc/pseries: Flush SLB contents on SLB MCE errors
    (bsc#1094244).

  - powerpc/pseries: Remove prrn_work workqueue
    (bsc#1102495, bsc#1109337).

  - powerpc/pseries: Remove unneeded uses of dlpar work
    queue (bsc#1102495, bsc#1109337).

  - powerpc/tm: Avoid possible userspace r1 corruption on
    reclaim (bsc#1109333).

  - powerpc/tm: Fix userspace r13 corruption (bsc#1109333).

  - printk: do not spin in printk when in nmi (bsc#1094244).

  - pstore: Fix incorrect persistent ram buffer mapping
    (bnc#1012382).

  - rdma/cma: Do not ignore net namespace for unbound cm_id
    (bnc#1012382).

  - rdma/cma: Protect cma dev list with lock (bnc#1012382).

  - rdma/rw: Fix rdma_rw_ctx_signature_init() kernel-doc
    header (bsc#1082979).

  - reiserfs: change j_timestamp type to time64_t
    (bnc#1012382).

  - Revert 'ARM: imx_v6_v7_defconfig: Select ULPI support'
    (bnc#1012382).

  - Revert 'dma-buf/sync-file: Avoid enable fence signaling
    if poll(.timeout=0)' (bsc#1111363).

  - Revert 'Drop kernel trampoline stack.' This reverts
    commit 85dead31706c1c1755adff90405ff9861c39c704.

  - Revert 'kabi/severities: Ignore missing cpu_tss_tramp
    (bsc#1099597)' This reverts commit
    edde1f21880e3bfe244c6f98a3733b05b13533dc.

  - Revert 'mm: get rid of vmacache_flush_all() entirely'
    (kabi).

  - Revert 'NFC: Fix the number of pipes' (kabi).

  - ring-buffer: Allow for rescheduling when removing pages
    (bnc#1012382).

  - rtc: bq4802: add error handling for devm_ioremap
    (bnc#1012382).

  - s390/dasd: fix hanging offline processing due to
    canceled worker (bnc#1012382).

  - s390/facilites: use stfle_fac_list array size for
    MAX_FACILITY_BIT (bnc#1108315, LTC#171326).

  - s390/lib: use expoline for all bcr instructions
    (LTC#171029 bnc#1012382 bnc#1106934).

  - s390/qeth: fix race in used-buffer accounting
    (bnc#1012382).

  - s390/qeth: reset layer2 attribute on layer switch
    (bnc#1012382).

  - s390/qeth: use vzalloc for QUERY OAT buffer
    (bnc#1108315, LTC#171527).

  - sched/fair: Fix bandwidth timer clock drift condition
    (Git-fixes).

  - sched/fair: Fix vruntime_normalized() for remote
    non-migration wakeup (Git-fixes).

  - sch_hhf: fix NULL pointer dereference on init failure
    (bnc#1012382).

  - sch_htb: fix crash on init failure (bnc#1012382).

  - sch_multiq: fix double free on init failure
    (bnc#1012382).

  - sch_netem: avoid NULL pointer deref on init failure
    (bnc#1012382).

  - sch_tbf: fix two NULL pointer dereferences on init
    failure (bnc#1012382).

  - scripts: modpost: check memory allocation results
    (bnc#1012382).

  - scsi: 3ware: fix return 0 on the error path of probe
    (bnc#1012382).

  - scsi: aic94xx: fix an error code in aic94xx_init()
    (bnc#1012382).

  - scsi: ipr: System hung while dlpar adding primary ipr
    adapter back (bsc#1109336).

  - scsi: qla2xxx: Add changes for devloss timeout in driver
    (bsc#1084427).

  - scsi: qla2xxx: Add FC-NVMe abort processing
    (bsc#1084427).

  - scsi: qla2xxx: Add longer window for chip reset
    (bsc#1094555).

  - scsi: qla2xxx: Avoid double completion of abort command
    (bsc#1094555).

  - scsi: qla2xxx: Cleanup code to improve FC-NVMe error
    handling (bsc#1084427).

  - scsi: qla2xxx: Cleanup for N2N code (bsc#1094555).

  - scsi: qla2xxx: correctly shift host byte (bsc#1094555).

  - scsi: qla2xxx: Correct setting of
    SAM_STAT_CHECK_CONDITION (bsc#1094555).

  - scsi: qla2xxx: Delete session for nport id change
    (bsc#1094555).

  - scsi: qla2xxx: Fix Async GPN_FT for FCP and FC-NVMe scan
    (bsc#1084427).

  - scsi: qla2xxx: Fix crash on qla2x00_mailbox_command
    (bsc#1094555).

  - scsi: qla2xxx: Fix double free bug after firmware
    timeout (bsc#1094555).

  - scsi: qla2xxx: Fix driver unload by shutting down chip
    (bsc#1094555).

  - scsi: qla2xxx: fix error message on <qla2400
    (bsc#1094555).

  - scsi: qla2xxx: Fix FC-NVMe IO abort during driver reset
    (bsc#1084427).

  - scsi: qla2xxx: Fix function argument descriptions
    (bsc#1094555).

  - scsi: qla2xxx: Fix Inquiry command being dropped in
    Target mode (bsc#1094555).

  - scsi: qla2xxx: Fix issue reported by static checker for
    qla2x00_els_dcmd2_sp_done() (bsc#1094555).

  - scsi: qla2xxx: Fix login retry count (bsc#1094555).

  - scsi: qla2xxx: Fix Management Server NPort handle
    reservation logic (bsc#1094555).

  - scsi: qla2xxx: Fix memory leak for allocating abort IOCB
    (bsc#1094555).

  - scsi: qla2xxx: Fix n2n_ae flag to prevent dev_loss on
    PDB change (bsc#1084427).

  - scsi: qla2xxx: Fix N2N link re-connect (bsc#1094555).

  - scsi: qla2xxx: Fix NPIV deletion by calling
    wait_for_sess_deletion (bsc#1094555).

  - scsi: qla2xxx: Fix race between switch cmd completion
    and timeout (bsc#1094555).

  - scsi: qla2xxx: Fix race condition between iocb timeout
    and initialisation (bsc#1094555).

  - scsi: qla2xxx: Fix redundant fc_rport registration
    (bsc#1094555).

  - scsi: qla2xxx: Fix retry for PRLI RJT with reason of
    BUSY (bsc#1084427).

  - scsi: qla2xxx: Fix Rport and session state getting out
    of sync (bsc#1094555).

  - scsi: qla2xxx: Fix sending ADISC command for login
    (bsc#1094555).

  - scsi: qla2xxx: Fix session state stuck in Get Port DB
    (bsc#1094555).

  - scsi: qla2xxx: Fix stalled relogin (bsc#1094555).

  - scsi: qla2xxx: Fix TMF and Multi-Queue config
    (bsc#1094555).

  - scsi: qla2xxx: Fix unintended Logout (bsc#1094555).

  - scsi: qla2xxx: Fix unintialized List head crash
    (bsc#1094555).

  - scsi: qla2xxx: Flush mailbox commands on chip reset
    (bsc#1094555).

  - scsi: qla2xxx: fx00 copypaste typo (bsc#1094555).

  - scsi: qla2xxx: Migrate NVME N2N handling into state
    machine (bsc#1094555).

  - scsi: qla2xxx: Move GPSC and GFPNID out of session
    management (bsc#1094555).

  - scsi: qla2xxx: Prevent relogin loop by removing stale
    code (bsc#1094555).

  - scsi: qla2xxx: Prevent sysfs access when chip is down
    (bsc#1094555).

  - scsi: qla2xxx: Reduce redundant ADISC command for RSCNs
    (bsc#1094555).

  - scsi: qla2xxx: remove irq save in qla2x00_poll()
    (bsc#1094555).

  - scsi: qla2xxx: Remove nvme_done_list (bsc#1084427).

  - scsi: qla2xxx: Remove stale debug value for login_retry
    flag (bsc#1094555).

  - scsi: qla2xxx: Remove unneeded message and minor cleanup
    for FC-NVMe (bsc#1084427).

  - scsi: qla2xxx: Restore ZIO threshold setting
    (bsc#1084427).

  - scsi: qla2xxx: Return busy if rport going away
    (bsc#1084427).

  - scsi: qla2xxx: Save frame payload size from ICB
    (bsc#1094555).

  - scsi: qla2xxx: Set IIDMA and fcport state before
    qla_nvme_register_remote() (bsc#1084427).

  - scsi: qla2xxx: Silent erroneous message (bsc#1094555).

  - scsi: qla2xxx: Update driver version to 10.00.00.06-k
    (bsc#1084427).

  - scsi: qla2xxx: Update driver version to 10.00.00.07-k
    (bsc#1094555).

  - scsi: qla2xxx: Update driver version to 10.00.00.08-k
    (bsc#1094555).

  - scsi: qla2xxx: Use dma_pool_zalloc() (bsc#1094555).

  - scsi: qla2xxx: Use predefined get_datalen_for_atio()
    inline function (bsc#1094555).

  - scsi: target: fix __transport_register_session locking
    (bnc#1012382).

  - selftests/powerpc: Kill child processes on SIGINT
    (bnc#1012382).

  - selftest: timers: Tweak raw_skew to SKIP when
    ADJ_OFFSET/other clock adjustments are in progress
    (bnc#1012382).

  - selinux: use GFP_NOWAIT in the AVC kmem_caches
    (bnc#1012382).

  - smb3: fix reset of bytes read and written stats
    (bnc#1012382).

  - SMB3: Number of requests sent should be displayed for
    SMB3 not just CIFS (bnc#1012382).

  - srcu: Allow use of Tiny/Tree SRCU from both process and
    interrupt context (bsc#1050549).

  - staging: android: ion: fix ION_IOC_(MAP,SHARE)
    use-after-free (bnc#1012382).

  - staging: comedi: ni_mio_common: fix subdevice flags for
    PFI subdevice (bnc#1012382).

  - staging: rt5208: Fix a sleep-in-atomic bug in
    xd_copy_page (bnc#1012382).

  - staging/rts5208: Fix read overflow in memcpy
    (bnc#1012382).

  - stop_machine: Atomically queue and wake stopper threads
    (git-fixes).

  - tcp: do not restart timewait timer on rst reception
    (bnc#1012382).

  - Tools: hv: Fix a bug in the key delete code
    (bnc#1012382).

  - tty: Drop tty->count on tty_reopen() failure
    (bnc#1105428). As this depends on earlier tty patches,
    they were moved to the sorted section too.

  - tty: rocket: Fix possible buffer overwrite on
    register_PCI (bnc#1012382).

  - tty: vt_ioctl: fix potential Spectre v1 (bnc#1012382).

  - uio: potential double frees if __uio_register_device()
    fails (bnc#1012382).

  - Update
    patches.suse/dm-Always-copy-cmd_flags-when-cloning-a-req
    uest.patch (bsc#1088087, bsc#1103156).

  - USB: add quirk for WORLDE Controller KS49 or Prodipe
    MIDI 49C USB controller (bnc#1012382).

  - USB: Add quirk to support DJI CineSSD (bnc#1012382).

  - usb: Avoid use-after-free by flushing endpoints early in
    usb_set_interface() (bnc#1012382).

  - usb: cdc-wdm: Fix a sleep-in-atomic-context bug in
    service_outstanding_interrupt() (bnc#1012382).

  - usb: Do not die twice if PCI xhci host is not responding
    in resume (bnc#1012382).

  - usb: host: u132-hcd: Fix a sleep-in-atomic-context bug
    in u132_get_frame() (bnc#1012382).

  - usbip: vhci_sysfs: fix potential Spectre v1
    (bsc#1096547).

  - usb: misc: uss720: Fix two sleep-in-atomic-context bugs
    (bnc#1012382).

  - USB: net2280: Fix erroneous synchronization change
    (bnc#1012382).

  - USB: serial: io_ti: fix array underflow in completion
    handler (bnc#1012382).

  - USB: serial: ti_usb_3410_5052: fix array underflow in
    completion handler (bnc#1012382).

  - USB: yurex: Fix buffer over-read in yurex_write()
    (bnc#1012382).

  - VFS: do not test owner for NFS in set_posix_acl()
    (bsc#1103405).

  - video: goldfishfb: fix memory leak on driver remove
    (bnc#1012382).

  - vmw_balloon: include asm/io.h (bnc#1012382).

  - vti6: remove !skb->ignore_df check from vti6_xmit()
    (bnc#1012382).

  - watchdog: w83627hf: Added NCT6102D support
    (bsc#1106434).

  - watchdog: w83627hf_wdt: Add quirk for Inves system
    (bsc#1106434).

  - x86/apic: Fix restoring boot IRQ mode in reboot and
    kexec/kdump (bsc#1110006).

  - x86/apic: Split disable_IO_APIC() into two functions to
    fix CONFIG_KEXEC_JUMP=y (bsc#1110006).

  - x86/apic: Split out restore_boot_irq_mode() from
    disable_IO_APIC() (bsc#1110006).

  - x86/boot: Fix 'run_size' calculation (bsc#1110006).

  - x86/entry/64: Remove %ebx handling from error_entry/exit
    (bnc#1102715).

  - x86/kaiser: Avoid loosing NMIs when using trampoline
    stack (bsc#1106293 bsc#1099597).

  - x86/mm: Remove in_nmi() warning from vmalloc_fault()
    (bnc#1012382).

  - x86: msr-index.h: Correct SNB_C1/C3_AUTO_UNDEMOTE
    defines (bsc#1110006).

  - x86/pae: use 64 bit atomic xchg function in
    native_ptep_get_and_clear (bnc#1012382).

  - x86/speculation/l1tf: Fix up pte->pfn conversion for PAE
    (bnc#1012382).

  - x86/vdso: Fix asm constraints on vDSO syscall fallbacks
    (bsc#1110006).

  - x86/vdso: Fix vDSO build if a retpoline is emitted
    (bsc#1110006).

  - x86/vdso: Fix vDSO syscall fallback asm constraint
    regression (bsc#1110006).

  - x86/vdso: Only enable vDSO retpolines when enabled and
    supported (bsc#1110006).

  - xen: avoid crash in disable_hotplug_cpu (bsc#1106594).

  - xen/blkfront: correct purging of persistent grants
    (bnc#1065600).

  - xen: issue warning message when out of grant maptrack
    entries (bsc#1105795).

  - xen/netfront: do not bug in case of too many frags
    (bnc#1012382).

  - xen-netfront: fix queue name setting (bnc#1012382).

  - xen/netfront: fix waiting for xenbus state change
    (bnc#1012382).

  - xen-netfront: fix warn message as irq device name has
    '/' (bnc#1012382).

  - xen/x86/vpmu: Zero struct pt_regs before calling into
    sample handling code (bnc#1012382).

  - xfs: add a new xfs_iext_lookup_extent_before helper
    (bsc#1095344).

  - xfs: add asserts for the mmap lock in
    xfs_(insert,collapse)_file_space (bsc#1095344).

  - xfs: add a xfs_bmap_fork_to_state helper (bsc#1095344).

  - xfs: add a xfs_iext_update_extent helper (bsc#1095344).

  - xfs: add comments documenting the rebalance algorithm
    (bsc#1095344).

  - xfs: add some comments to
    xfs_iext_insert/xfs_iext_insert_node (bsc#1095344).

  - xfs: add xfs_trim_extent (bsc#1095344).

  - xfs: allow unaligned extent records in
    xfs_bmbt_disk_set_all (bsc#1095344).

  - xfs: borrow indirect blocks from freed extent when
    available (bsc#1095344).

  - xfs: cleanup xfs_bmap_last_before (bsc#1095344).

  - xfs: do not create overlapping extents in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: do not rely on extent indices in
    xfs_bmap_collapse_extents (bsc#1095344).

  - xfs: do not rely on extent indices in
    xfs_bmap_insert_extents (bsc#1095344).

  - xfs: do not set XFS_BTCUR_BPRV_WASDEL in xfs_bunmapi
    (bsc#1095344).

  - xfs: during btree split, save new block key & ptr for
    future insertion (bsc#1095344).

  - xfs: factor out a helper to initialize a local format
    inode fork (bsc#1095344).

  - xfs: fix memory leak in xfs_iext_free_last_leaf
    (bsc#1095344).

  - xfs: fix number of records handling in
    xfs_iext_split_leaf (bsc#1095344).

  - xfs: fix transaction allocation deadlock in IO path
    (bsc#1090535).

  - xfs: handle indlen shortage on delalloc extent merge
    (bsc#1095344).

  - xfs: handle zero entries case in xfs_iext_rebalance_leaf
    (bsc#1095344).

  - xfs: improve kmem_realloc (bsc#1095344).

  - xfs: inline xfs_shift_file_space into callers
    (bsc#1095344).

  - xfs: introduce the xfs_iext_cursor abstraction
    (bsc#1095344).

  - xfs: iterate over extents in xfs_bmap_extents_to_btree
    (bsc#1095344).

  - xfs: iterate over extents in xfs_iextents_copy
    (bsc#1095344).

  - xfs: make better use of the 'state' variable in
    xfs_bmap_del_extent_real (bsc#1095344).

  - xfs: merge xfs_bmap_read_extents into xfs_iread_extents
    (bsc#1095344).

  - xfs: move pre/post-bmap tracing into
    xfs_iext_update_extent (bsc#1095344).

  - xfs: move some code around inside xfs_bmap_shift_extents
    (bsc#1095344).

  - xfs: move some more code into xfs_bmap_del_extent_real
    (bsc#1095344).

  - xfs: move xfs_bmbt_irec and xfs_exntst_t to xfs_types.h
    (bsc#1095344).

  - xfs: move xfs_iext_insert tracepoint to report useful
    information (bsc#1095344).

  - xfs: new inode extent list lookup helpers (bsc#1095344).

  - xfs: only run torn log write detection on dirty logs
    (bsc#1095753).

  - xfs: pass an on-disk extent to xfs_bmbt_validate_extent
    (bsc#1095344).

  - xfs: pass a struct xfs_bmbt_irec to xfs_bmbt_lookup_eq
    (bsc#1095344).

  - xfs: pass a struct xfs_bmbt_irec to xfs_bmbt_update
    (bsc#1095344).

  - xfs: pass struct xfs_bmbt_irec to
    xfs_bmbt_validate_extent (bsc#1095344).

  - xfs: provide helper for counting extents from if_bytes
    (bsc#1095344).

  - xfs: refactor delalloc accounting in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: refactor delalloc indlen reservation split into
    helper (bsc#1095344).

  - xfs: refactor dir2 leaf readahead shadow buffer
    cleverness (bsc#1095344).

  - xfs: refactor in-core log state update to helper
    (bsc#1095753).

  - xfs: refactor unmount record detection into helper
    (bsc#1095753).

  - xfs: refactor xfs_bmap_add_extent_delay_real
    (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_hole_delay
    (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_hole_real
    (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_unwritten_real
    (bsc#1095344).

  - xfs: refactor xfs_bunmapi_cow (bsc#1095344).

  - xfs: refactor xfs_del_extent_real (bsc#1095344).

  - xfs: remove a duplicate assignment in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: remove all xfs_bmbt_set_* helpers except for
    xfs_bmbt_set_all (bsc#1095344).

  - xfs: remove a superflous assignment in
    xfs_iext_remove_node (bsc#1095344).

  - xfs: remove if_rdev (bsc#1095344).

  - xfs: remove prev argument to xfs_bmapi_reserve_delalloc
    (bsc#1095344).

  - xfs: remove support for inlining data/extents into the
    inode fork (bsc#1095344).

  - xfs: remove the never fully implemented UUID fork format
    (bsc#1095344).

  - xfs: remove the nr_extents argument to xfs_iext_insert
    (bsc#1095344).

  - xfs: remove the nr_extents argument to xfs_iext_remove
    (bsc#1095344).

  - xfs: remove XFS_BMAP_MAX_SHIFT_EXTENTS (bsc#1095344).

  - xfs: remove XFS_BMAP_TRACE_EXLIST (bsc#1095344).

  - xfs: remove xfs_bmbt_get_state (bsc#1095344).

  - xfs: remove xfs_bmse_shift_one (bsc#1095344).

  - xfs: rename bno to end in __xfs_bunmapi (bsc#1095344).

  - xfs: replace xfs_bmbt_lookup_ge with
    xfs_bmbt_lookup_first (bsc#1095344).

  - xfs: replace xfs_qm_get_rtblks with a direct call to
    xfs_bmap_count_leaves (bsc#1095344).

  - xfs: rewrite getbmap using the xfs_iext_* helpers
    (bsc#1095344).

  - xfs: rewrite xfs_bmap_count_leaves using
    xfs_iext_get_extent (bsc#1095344).

  - xfs: rewrite xfs_bmap_first_unused to make better use of
    xfs_iext_get_extent (bsc#1095344).

  - xfs: separate log head record discovery from
    verification (bsc#1095753).

  - xfs: simplify the xfs_getbmap interface (bsc#1095344).

  - xfs: simplify validation of the unwritten extent bit
    (bsc#1095344).

  - xfs: split indlen reservations fairly when under
    reserved (bsc#1095344).

  - xfs: split xfs_bmap_shift_extents (bsc#1095344).

  - xfs: switch xfs_bmap_local_to_extents to use
    xfs_iext_insert (bsc#1095344).

  - xfs: treat idx as a cursor in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: treat idx as a cursor in
    xfs_bmap_add_extent_hole_delay (bsc#1095344).

  - xfs: treat idx as a cursor in
    xfs_bmap_add_extent_hole_real (bsc#1095344).

  - xfs: treat idx as a cursor in
    xfs_bmap_add_extent_unwritten_real (bsc#1095344).

  - xfs: treat idx as a cursor in xfs_bmap_collapse_extents
    (bsc#1095344).

  - xfs: treat idx as a cursor in xfs_bmap_del_extent_*
    (bsc#1095344).

  - xfs: update freeblocks counter after extent deletion
    (bsc#1095344).

  - xfs: update got in xfs_bmap_shift_update_extent
    (bsc#1095344).

  - xfs: use a b+tree for the in-core extent list
    (bsc#1095344).

  - xfs: use correct state defines in
    xfs_bmap_del_extent_(cow,delay) (bsc#1095344).

  - xfs: use new extent lookup helpers in xfs_bmapi_read
    (bsc#1095344).

  - xfs: use new extent lookup helpers in xfs_bmapi_write
    (bsc#1095344).

  - xfs: use new extent lookup helpers in __xfs_bunmapi
    (bsc#1095344).

  - xfs: use the state defines in xfs_bmap_del_extent_real
    (bsc#1095344).

  - xfs: use xfs_bmap_del_extent_delay for the data fork as
    well (bsc#1095344).

  - xfs: use xfs_iext_*_extent helpers in
    xfs_bmap_shift_extents (bsc#1095344).

  - xfs: use xfs_iext_*_extent helpers in
    xfs_bmap_split_extent_at (bsc#1095344).

  - xfs: use xfs_iext_get_extent instead of open coding it
    (bsc#1095344).

  - xfs: use xfs_iext_get_extent in xfs_bmap_first_unused
    (bsc#1095344).

  - xfrm: fix 'passing zero to ERR_PTR()' warning
    (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111363"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.159-73.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.159-73.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.159-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.159-73.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
