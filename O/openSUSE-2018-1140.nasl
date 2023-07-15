#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1140.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117988);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-10940", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-14613", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-9363");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-1140)");
  script_summary(english:"Check for the openSUSE-2018-1140 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-14633: A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in a way an authentication request from an ISCSI
    initiator is processed. An unauthenticated remote
    attacker can cause a stack-based buffer overflow and
    smash up to 17 bytes of the stack. The attack requires
    the iSCSI target to be enabled on the victim host.
    Depending on how the target's code was built (i.e.
    depending on a compiler, compile flags and hardware
    architecture) an attack may lead to a system crash and
    thus to a denial-of-service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely. Kernel versions 4.18.x,
    4.14.x and 3.10.x are believed to be vulnerable
    (bnc#1107829).

  - CVE-2018-17182: The vmacache_flush_all function in
    mm/vmacache.c mishandled sequence number overflows. An
    attacker can trigger a use-after-free (and possibly gain
    privileges) via certain thread creation, map, unmap,
    invalidation, and dereference operations (bnc#1108399).

  - CVE-2018-14617: There is a NULL pointer dereference and
    panic in hfsplus_lookup() in fs/hfsplus/dir.c when
    opening a file (that is purportedly a hard link) in an
    hfs+ filesystem that has malformed catalog data, and is
    mounted read-only without a metadata directory
    (bnc#1102870).

  - CVE-2018-14613: There is an invalid pointer dereference
    in io_ctl_map_page() when mounting and operating a
    crafted btrfs image, because of a lack of block group
    item validation in check_leaf_item in
    fs/btrfs/tree-checker.c (bnc#1102896).

  - CVE-2018-10940: The cdrom_ioctl_media_changed function
    in drivers/cdrom/cdrom.c allowed local attackers to use
    a incorrect bounds check in the CDROM driver
    CDROM_MEDIA_CHANGED ioctl to read out kernel memory
    (bnc#1092903).

  - CVE-2018-13093: There is a NULL pointer dereference and
    panic in lookup_slow() on a NULL inode->i_ops pointer
    when doing pathwalks on a corrupted xfs image. This
    occurs because of a lack of proper validation that
    cached inodes are free during allocation (bnc#1100001).

  - CVE-2018-13094: An OOPS may occur for a corrupted xfs
    image after xfs_da_shrink_inode() is called with a NULL
    bp (bnc#1100000).

  - CVE-2018-13095: A denial of service (memory corruption
    and BUG) can occur for a corrupted xfs image upon
    encountering an inode that is in extent format, but has
    more extents than fit in the inode fork (bnc#1099999).

  - CVE-2018-12896: An Integer Overflow in
    kernel/time/posix-timers.c in the POSIX timer code is
    caused by the way the overrun accounting works.
    Depending on interval and expiry time values, the
    overrun can be larger than INT_MAX, but the accounting
    is int based. This basically made the accounting values,
    which are visible to user space via timer_getoverrun(2)
    and siginfo::si_overrun, random. For example, a local
    user can cause a denial of service (signed integer
    overflow) via crafted mmap, futex, timer_create, and
    timer_settime system calls (bnc#1099922).

  - CVE-2018-16658: An information leak in
    cdrom_ioctl_drive_status in drivers/cdrom/cdrom.c could
    be used by local attackers to read kernel memory because
    a cast from unsigned long to int interferes with bounds
    checking. This is similar to CVE-2018-10940
    (bnc#1107689).

  - CVE-2018-6555: The irda_setsockopt function allowed
    local users to cause a denial of service (ias_object
    use-after-free and system crash) or possibly have
    unspecified other impact via an AF_IRDA socket
    (bnc#1106511).

  - CVE-2018-6554: Memory leak in the irda_bind function
    kernel allowed local users to cause a denial of service
    (memory consumption) by repeatedly binding an AF_IRDA
    socket (bnc#1106509).

  - CVE-2018-1129: An attacker having access to ceph cluster
    network who is able to alter the message payload was
    able to bypass signature checks done by cephx protocol.
    Ceph branches master, mimic, luminous and jewel are
    believed to be vulnerable (bnc#1096748).

  - CVE-2018-1128: It was found that cephx authentication
    protocol did not verify ceph clients correctly and was
    vulnerable to replay attack. Any attacker having access
    to ceph cluster network who is able to sniff packets on
    network can use this vulnerability to authenticate with
    ceph service and perform actions allowed by ceph
    service. Ceph branches master, mimic, luminous and jewel
    are believed to be vulnerable (bnc#1096748).

  - CVE-2018-10938: A crafted network packet sent remotely
    by an attacker may force the kernel to enter an infinite
    loop in the cipso_v4_optptr() function in
    net/ipv4/cipso_ipv4.c leading to a denial-of-service. A
    certain non-default configuration of LSM (Linux Security
    Module) and NetLabel should be set up on a system before
    an attacker could leverage this flaw (bnc#1106016).

  - CVE-2018-15572: The spectre_v2_select_mitigation
    function in arch/x86/kernel/cpu/bugs.c did not always
    fill RSB upon a context switch, which made it easier for
    attackers to conduct userspace-userspace spectreRSB
    attacks (bnc#1102517 bnc#1105296).

  - CVE-2018-10902: It was found that the raw midi kernel
    driver did not protect against concurrent access which
    leads to a double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation (bnc#1105322).

  - CVE-2018-9363: A buffer overflow in bluetooth HID report
    processing could be used by malicious bluetooth devices
    to crash the kernel or potentially execute code
    (bnc#1105292).

The following non-security bugs were fixed :

  - 9p: fix multiple NULL-pointer-dereferences
    (bsc#1051510).

  - 9p/net: Fix zero-copy path in the 9p virtio transport
    (bsc#1051510).

  - 9p/virtio: fix off-by-one error in sg list bounds check
    (bsc#1051510).

  - ACPI / APEI: Remove ghes_ioremap_area (bsc#1051510).

  - ACPI / bus: Only call dmi_check_system on X86
    (bsc#1105597, bsc#1106178).

  - ACPICA: iasl: Add SMMUv3 device ID mapping index support
    (bsc#1103387).

  - ACPI / EC: Add another entry for Thinkpad X1 Carbon 6th
    (bsc#1051510).

  - ACPI / EC: Add parameter to force disable the GPE on
    suspend (bsc#1051510).

  - ACPI / EC: Use ec_no_wakeup on more Thinkpad X1 Carbon
    6th systems (bsc#1051510).

  - ACPI / EC: Use ec_no_wakeup on Thinkpad X1 Carbon 6th
    (bsc#1051510).

  - ACPI / EC: Use ec_no_wakeup on ThinkPad X1 Yoga 3rd
    (bsc#1051510).

  - ACPI/IORT: Remove temporary iort_get_id_mapping_index()
    ACPICA guard (bsc#1103387).

  - ACPI / pci: Bail early in acpi_pci_add_bus() if there is
    no ACPI handle (bsc#1051510).

  - ACPI / pci: pci_link: Allow the absence of _PRS and
    change log level (bsc#1104172).

  - ACPI/pci: pci_link: reduce verbosity when IRQ is enabled
    (bsc#1104172).

  - ACPI / PM: save NVS memory for ASUS 1025C laptop
    (bsc#1051510).

  - ACPI / scan: Initialize status to ACPI_STA_DEFAULT
    (bsc#1051510).

  - affs_lookup(): close a race with affs_remove_link()
    (bsc#1105355).

  - ahci: Add Intel Ice Lake LP PCI ID (bsc#1051510).

  - ALSA: bebob: fix memory leak for M-Audio FW1814 and
    ProjectMix I/O at error path (bsc#1051510).

  - ALSA: bebob: use address returned by kmalloc() instead
    of kernel stack for streaming DMA mapping (bsc#1051510).

  - ALSA: cs46xx: Deliver indirect-PCM transfer error ().

  - ALSA: cs5535audio: Fix invalid endian conversion
    (bsc#1051510).

  - ALSA: emu10k1: Deliver indirect-PCM transfer error ().

  - ALSA: emu10k1: fix possible info leak to userspace on
    SNDRV_EMU10K1_IOCTL_INFO (bsc#1051510).

  - ALSA: fireface: fix memory leak in
    ff400_switch_fetching_mode() (bsc#1051510).

  - ALSA: firewire-digi00x: fix memory leak of private data
    (bsc#1051510).

  - ALSA: firewire-tascam: fix memory leak of private data
    (bsc#1051510).

  - ALSA: fireworks: fix memory leak of response buffer at
    error path (bsc#1051510).

  - ALSA: hda: Add AZX_DCAPS_PM_RUNTIME for AMD Raven Ridge
    (bsc#1051510).

  - ALSA: hda: Correct Asrock B85M-ITX power_save blacklist
    entry (bsc#1051510).

  - ALSA: hda - Fix cancel_work_sync() stall from jackpoll
    work (bsc#1051510).

  - ALSA: hda - Sleep for 10ms after entering D3 on Conexant
    codecs (bsc#1051510).

  - ALSA: hda - Turn CX8200 into D3 as well upon reboot
    (bsc#1051510).

  - ALSA: memalloc: Do not exceed over the requested size
    (bsc#1051510).

  - ALSA: mips: Deliver indirect-PCM transfer error ().

  - ALSA: msnd: Fix the default sample sizes (bsc#1051510).

  - ALSA: oxfw: fix memory leak for model-dependent data at
    error path (bsc#1051510).

  - ALSA: oxfw: fix memory leak of discovered stream formats
    at error path (bsc#1051510).

  - ALSA: oxfw: fix memory leak of private data
    (bsc#1051510).

  - ALSA: pcm: Fix negative appl_ptr handling in
    pcm-indirect helpers ().

  - ALSA: pcm: Fix snd_interval_refine first/last with open
    min/max (bsc#1051510).

  - ALSA: pcm: Simplify forward/rewind codes ().

  - ALSA: pcm: Use a common helper for PCM state check and
    hwsync ().

  - ALSA: pcm: Workaround for weird PulseAudio behavior on
    rewind error ().

  - ALSA: rme32: Deliver indirect-PCM transfer error ().

  - ALSA: snd-aoa: add of_node_put() in error path
    (bsc#1051510).

  - ALSA: usb-audio: Fix multiple definitions in
    AU0828_DEVICE() macro (bsc#1051510).

  - ALSA: virmidi: Fix too long output trigger loop
    (bsc#1051510).

  - ALSA: vx222: Fix invalid endian conversions
    (bsc#1051510).

  - ALSA: vxpocket: Fix invalid endian conversions
    (bsc#1051510).

  - apparmor: ensure that undecidable profile attachments
    fail (bsc#1106427).

  - apparmor: fix an error code in __aa_create_ns()
    (bsc#1106427).

  - apparmor: Fix regression in profile conflict logic
    (bsc#1106427)

  - apparmor: remove no-op permission check in policy_unpack
    (bsc#1106427).

  - arm64/acpi: Create arch specific cpu to acpi id helper
    (bsc#1106903).

  - arm64: dma-mapping: clear buffers allocated with
    FORCE_CONTIGUOUS flag (bsc#1106902).

  - arm64: enable thunderx gpio driver

  - arm64: Enforce BBM for huge IO/VMAP mappings
    (bsc#1106890).

  - arm64: export memblock_reserve()d regions via
    /proc/iomem (bsc#1106892).

  - arm64: fix unwind_frame() for filtered out fn for
    function graph tracing (bsc#1106900).

  - arm64: fix vmemmap BUILD_BUG_ON() triggering on !vmemmap
    setups (bsc#1106896).

  - arm64: fpsimd: Avoid FPSIMD context leakage for the init
    task (bsc#1106894).

  - arm64: Ignore hardware dirty bit updates in
    ptep_set_wrprotect() (bsc#1108010).

  - arm64: kasan: avoid pfn_to_nid() before page array is
    initialized (bsc#1106899).

  - arm64/kasan: do not allocate extra shadow memory
    (bsc#1106897).

  - arm64: Make sure permission updates happen for pmd/pud
    (bsc#1106891).

  - arm64: mm: check for upper PAGE_SHIFT bits in
    pfn_valid() (bsc#1106893).

  - arm64: mm: Ensure writes to swapper are ordered wrt
    subsequent cache maintenance (bsc#1106906).

  - arm64/mm/kasan: do not use vmemmap_populate() to
    initialize shadow (bsc#1106898).

  - arm64: numa: rework ACPI NUMA initialization
    (bsc#1106905).

  - arm64: Update config files. (bsc#1110716) Enable ST
    LPS25H pressure sensor.

  - arm64: vgic-v2: Fix proxying of cpuif access
    (bsc#1106901).

  - ARM: 8780/1: ftrace: Only set kernel memory back to
    read-only after boot (bsc#1051510).

  - arm/asm/tlb.h: Fix build error implicit func declaration
    (bnc#1105467 Reduce IPIs and atomic ops with improved
    lazy TLB).

  - ARM: DRA7/OMAP5: Enable ACTLR[0] (Enable invalidates of
    BTB) for secondary cores (bsc#1051510).

  - ARM: hisi: fix error handling and missing of_node_put
    (bsc#1051510).

  - ARM: hisi: handle of_iomap and fix missing of_node_put
    (bsc#1051510).

  - ARM: imx: flag failure of of_iomap (bsc#1051510).

  - ARM: imx_v4_v5_defconfig: Select ULPI support
    (bsc#1051510).

  - ARM: imx_v6_v7_defconfig: Select ULPI support
    (bsc#1051510).

  - ARM: pxa: irq: fix handling of ICMR registers in
    suspend/resume (bsc#1051510).

  - ASoC: cs4265: fix MMTLR Data switch control
    (bsc#1051510).

  - ASoC: dapm: Fix potential DAI widget pointer deref when
    linking DAIs (bsc#1051510).

  - ASoC: dpcm: do not merge format from invalid codec dai
    (bsc#1051510).

  - ASoC: es7134: remove 64kHz rate from the supported rates
    (bsc#1051510).

  - ASoC: Intel: cht_bsw_max98090: remove useless code,
    align with ChromeOS driver (bsc#1051510).

  - ASoC: Intel: cht_bsw_max98090_ti: Fix jack
    initialization (bsc#1051510).

  - ASoC: msm8916-wcd-digital: fix RX2 MIX1 and RX3 MIX1
    (bsc#1051510).

  - ASoC: rsnd: cmd: Add missing newline to debug message
    (bsc#1051510).

  - ASoC: rsnd: fixup not to call clk_get/set under
    non-atomic (bsc#1051510).

  - ASoC: rsnd: move rsnd_ssi_config_init() execute
    condition into it (bsc#1051510).

  - ASoC: rsnd: update pointer more accurate (bsc#1051510).

  - ASoC: rt5514: Add the I2S ASRC support (bsc#1051510).

  - ASoC: rt5514: Add the missing register in the readable
    table (bsc#1051510).

  - ASoC: rt5514: Eliminate the noise in the ASRC case
    (bsc#1051510).

  - ASoC: rt5514: Fix the issue of the delay volume applied
    (bsc#1051510).

  - ASoC: sirf: Fix potential NULL pointer dereference
    (bsc#1051510).

  - ASoC: wm8994: Fix missing break in switch (bsc#1051510).

  - ASoC: zte: Fix incorrect PCM format bit usages
    (bsc#1051510).

  - ata: Fix ZBC_OUT all bit handling (bsc#1051510).

  - ata: Fix ZBC_OUT command block check (bsc#1051510).

  - ata: libahci: Allow reconfigure of DEVSLP register
    (bsc#1051510).

  - ata: libahci: Correct setting of DEVSLP register
    (bsc#1051510).

  - ath10k: disable bundle mgmt tx completion event support
    (bsc#1051510).

  - ath10k: prevent active scans on potential unusable
    channels (bsc#1051510).

  - ath10k: update the phymode along with bandwidth change
    request (bsc#1051510).

  - ath9k: add MSI support ().

  - ath9k_hw: fix channel maximum power level test
    (bsc#1051510).

  - ath9k: report tx status on EOSP (bsc#1051510).

  - atm: horizon: Fix irq release error (bsc#1105355).

  - atm: Preserve value of skb->truesize when accounting to
    vcc (networking-stable-18_07_19).

  - atm: zatm: fix memcmp casting (bsc#1105355).

  - atm: zatm: Fix potential Spectre v1
    (networking-stable-18_07_19).

  - audit: allow not equal op for audit by executable
    (bsc#1051510).

  - audit: Fix extended comparison of GID/EGID
    (bsc#1051510).

  - ax88179_178a: Check for supported Wake-on-LAN modes
    (bsc#1051510).

  - b43/leds: Ensure NUL-termination of LED name string
    (bsc#1051510).

  - b43legacy/leds: Ensure NUL-termination of LED name
    string (bsc#1051510).

  - bcache: avoid unncessary cache prefetch
    bch_btree_node_get().

  - bcache: calculate the number of incremental GC nodes
    according to the total of btree nodes.

  - bcache: display rate debug parameters to 0 when
    writeback is not running.

  - bcache: do not check return value of
    debugfs_create_dir().

  - bcache: finish incremental GC.

  - bcache: fix error setting writeback_rate through sysfs
    interface.

  - bcache: fix I/O significant decline while backend
    devices registering.

  - bcache: free heap cache_set->flush_btree in
    bch_journal_free.

  - bcache: make the pr_err statement used for ENOENT only
    in sysfs_attatch section.

  - bcache: release dc->writeback_lock properly in
    bch_writeback_thread().

  - bcache: set max writeback rate when I/O request is idle.

  - bcache: simplify the calculation of the total amount of
    flash dirty data.

  - binfmt_elf: Respect error return from `regset->active'
    (bsc#1051510).

  - blkdev: __blkdev_direct_IO_simple: fix leak in error
    case (bsc#1083663).

  - blk-mq: avoid to synchronize rcu inside
    blk_cleanup_queue() (bsc#1077989).

  - block, bfq: return nbytes and not zero from struct
    cftype .write() method (bsc#1106238).

  - block: bio_iov_iter_get_pages: fix size of last iovec
    (bsc#1083663).

  - block: bio_iov_iter_get_pages: pin more pages for
    multi-segment IOs (bsc#1083663).

  - block, dax: remove dead code in blkdev_writepages()
    (bsc#1104888).

  - block: do not print a message when the device went away
    (bsc#1098459).

  - block: do not warn for flush on read-only device
    (bsc#1107756).

  - block: fix warning when I/O elevator is changed as
    request_queue is being removed (bsc#1109979).

  - block: Invalidate cache on discard v2 (bsc#1109992).

  - block: pass inclusive 'lend' parameter to
    truncate_inode_pages_range (bsc#1109992).

  - block: properly protect the 'queue' kobj in
    blk_unregister_queue (bsc#1109979).

  - bluetooth: Add a new Realtek 8723DE ID 0bda:b009
    (bsc#1051510).

  - bluetooth: avoid killing an already killed socket
    (bsc#1051510).

  - bluetooth: btsdio: Do not bind to non-removable BCM43430
    (bsc#1103587).

  - bluetooth: h5: Fix missing dependency on
    BT_HCIUART_SERDEV (bsc#1051510).

  - bluetooth: hidp: buffer overflow in hidp_process_report
    (bsc#1051510).

  - bluetooth: hidp: Fix handling of strncpy for hid->name
    information (bsc#1051510).

  - bluetooth: Use lock_sock_nested in bt_accept_enqueue
    (bsc#1051510).

  - bnxt_en: Clean up unused functions (bsc#1086282).

  - bnxt_en: Do not adjust max_cp_rings by the ones used by
    RDMA (bsc#1086282).

  - bnxt_en: Fix VF mac address regression (bsc#1086282 ).

  - bnxt_re: Fix couple of memory leaks that could lead to
    IOMMU call traces (bsc#1050244).

  - bonding: avoid lockdep confusion in bond_get_stats()
    (netfilter-stable-18_08_04).

  - bpf: fix references to free_bpf_prog_info() in comments
    (bsc#1083647).

  - bpf: fix uninitialized variable in bpf tools
    (bsc#1083647).

  - bpf: hash map: decrement counter on error (bsc#1083647).

  - bpf: powerpc64: pad function address loads with NOPs
    (bsc#1083647).

  - bpf, s390: fix potential memleak when later bpf_jit_prog
    fails (bsc#1083647).

  - bpf: use GFP_ATOMIC instead of GFP_KERNEL in
    bpf_parse_prog() (bsc#1083647).

  - brcmfmac: stop watchdog before detach and free
    everything (bsc#1051510).

  - brcmsmac: fix wrap around in conversion from constant to
    s16 (bsc#1051510).

  - btrfs: add a comp_refs() helper (dependency for
    bsc#1031392).

  - btrfs: Add checker for EXTENT_CSUM (bsc#1102882,
    bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).

  - btrfs: Add sanity check for EXTENT_DATA when reading out
    leaf (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: add tracepoints for outstanding extents mods
    (dependency for bsc#1031392).

  - btrfs: Check if item pointer overlaps with the item
    itself (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: check-integrity: Fix NULL pointer dereference for
    degraded mount (bsc#1107947).

  - btrfs: Check that each block group has corresponding
    chunk at mount time (bsc#1102882, bsc#1102896,
    bsc#1102879, bsc#1102877, bsc#1102875,).

  - btrfs: cleanup extent locking sequence (dependency for
    bsc#1031392).

  - btrfs: delayed-inode: Remove wrong qgroup meta
    reservation calls (bsc#1031392).

  - btrfs: delayed-inode: Use new qgroup meta rsv for
    delayed inode and item (bsc#1031392).

  - btrfs: fix data corruption when deduplicating between
    different files (bsc#1110647).

  - btrfs: fix duplicate extents after fsync of file with
    prealloc extents (bsc#1110644).

  - btrfs: fix error handling in btrfs_dev_replace_start
    (bsc#1107535).

  - btrfs: fix fsync after hole punching when using no-holes
    feature (bsc#1110642).

  - btrfs: fix loss of prealloc extents past i_size after
    fsync log replay (bsc#1110643).

  - btrfs: fix return value on rename exchange failure
    (bsc#1110645).

  - btrfs: fix send failure when root has deleted files
    still open (bsc#1110650).

  - btrfs: Fix use-after-free when cleaning up fs_devs with
    a single stale device (bsc#1097105).

  - btrfs: Fix wrong btrfs_delalloc_release_extents
    parameter (bsc#1031392).

  - btrfs: Handle error from btrfs_uuid_tree_rem call in
    _btrfs_ioctl_set_received_subvol (bsc#1097105).

  - btrfs: Introduce mount time chunk <-> dev extent mapping
    check (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: log csums for all modified extents (bsc#1110639).

  - btrfs: make the delalloc block rsv per inode (dependency
    for bsc#1031392).

  - btrfs: Manually implement device_total_bytes
    getter/setter (bsc#1043912).

  - btrfs: Move leaf and node validation checker to
    tree-checker.c (bsc#1102882, bsc#1102896, bsc#1102879,
    bsc#1102877, bsc#1102875,).

  - btrfs: qgroup: Add quick exit for non-fs extents
    (dependency for bsc#1031392).

  - btrfs: qgroup: Cleanup
    btrfs_qgroup_prepare_account_extents function
    (dependency for bsc#1031392).

  - btrfs: qgroup: Cleanup the remaining old reservation
    counters (bsc#1031392).

  - btrfs: qgroup: Commit transaction in advance to reduce
    early EDQUOT (bsc#1031392).

  - btrfs: qgroup: Do not use root->qgroup_meta_rsv for
    qgroup (bsc#1031392).

  - btrfs: qgroup: Fix qgroup reserved space underflow by
    only freeing reserved ranges (dependency for
    bsc#1031392).

  - btrfs: qgroup: Fix qgroup reserved space underflow
    caused by buffered write and quotas being enabled
    (dependency for bsc#1031392).

  - btrfs: qgroup: Fix wrong qgroup reservation update for
    relationship modification (bsc#1031392).

  - btrfs: qgroup: Introduce extent changeset for qgroup
    reserve functions (dependency for bsc#1031392).

  - btrfs: qgroup: Introduce function to convert
    META_PREALLOC into META_PERTRANS (bsc#1031392).

  - btrfs: qgroup: Introduce helpers to update and access
    new qgroup rsv (bsc#1031392).

  - btrfs: qgroup: Make qgroup_reserve and its callers to
    use separate reservation type (bsc#1031392).

  - btrfs: qgroup: Return actually freed bytes for qgroup
    release or free data (dependency for bsc#1031392).

  - btrfs: qgroup: Skeleton to support separate qgroup
    reservation type (bsc#1031392).

  - btrfs: qgroup: Split meta rsv type into meta_prealloc
    and meta_pertrans (bsc#1031392).

  - btrfs: qgroup: Update trace events for metadata
    reservation (bsc#1031392).

  - btrfs: qgroup: Update trace events to use new separate
    rsv types (bsc#1031392).

  - btrfs: qgroup: Use independent and accurate per inode
    qgroup rsv (bsc#1031392).

  - btrfs: qgroup: Use root::qgroup_meta_rsv_* to record
    qgroup meta reserved space (bsc#1031392).

  - btrfs: qgroup: Use separate meta reservation type for
    delalloc (bsc#1031392).

  - btrfs: remove type argument from comp_tree_refs
    (dependency for bsc#1031392).

  - btrfs: Remove unused parameters from various functions
    (bsc#1110649).

  - btrfs: rework outstanding_extents (dependency for
    bsc#1031392).

  - btrfs: round down size diff when shrinking/growing
    device (bsc#1097105).

  - btrfs: Round down values which are written for
    total_bytes_size (bsc#1043912).

  - btrfs: scrub: Do not use inode page cache in
    scrub_handle_errored_block() (follow up for
    bsc#1108096).

  - btrfs: scrub: Do not use inode pages for device replace
    (follow up for bsc#1108096).

  - btrfs: switch args for comp_*_refs (dependency for
    bsc#1031392).

  - btrfs: sync log after logging new name (bsc#1110646).

  - btrfs: tests/qgroup: Fix wrong tree backref level
    (bsc#1107928).

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

  - btrfs: Verify that every chunk has corresponding block
    group at mount time (bsc#1102882, bsc#1102896,
    bsc#1102879, bsc#1102877, bsc#1102875,).

  - cdrom: Fix info leak/OOB read in
    cdrom_ioctl_drive_status (bsc#1051510).

  - ceph: fix incorrect use of strncpy (bsc#1107319).

  - ceph: return errors from posix_acl_equiv_mode()
    correctly (bsc#1107320).

  - cfg80211: nl80211_update_ft_ies() to validate
    NL80211_ATTR_IE (bsc#1051510).

  - cfg80211: reg: Init wiphy_idx in regulatory_hint_core()
    (bsc#1051510).

  - cgroup: avoid copying strings longer than the buffers
    (bsc#1051510).

  - cifs: check kmalloc before use (bsc#1051510).

  - cifs: Fix stack out-of-bounds in
    smb{2,3}_create_lease_buf() (bsc#1051510).

  - cifs: store the leaseKey in the fid on SMB2_open
    (bsc#1051510).

  - clk: core: Potentially free connection id (bsc#1051510).

  - clk: imx6ul: fix missing of_node_put() (bsc#1051510).

  - clk: meson: gxbb: remove HHI_GEN_CLK_CTNL duplicate
    definition (bsc#1051510).

  - clk: mvebu: armada-38x: add support for 1866MHz variants
    (bsc#1105355).

  - clk: mvebu: armada-38x: add support for missing clocks
    (bsc#1105355).

  - clk: rockchip: fix clk_i2sout parent selection bits on
    rk3399 (bsc#1051510).

  - cls_matchall: fix tcf_unbind_filter missing
    (networking-stable-18_08_21).

  - coresight: Handle errors in finding input/output ports
    (bsc#1051510).

  - coresight: tpiu: Fix disabling timeouts (bsc#1051510).

  - cpufreq: CPPC: Do not set transition_latency
    (bsc#1101480).

  - cpufreq / CPPC: Set platform specific
    transition_delay_us (bsc#1101480).

  - cpufreq: CPPC: Use transition_delay_us depending
    transition_latency (bsc#1101480).

  - cpufreq: remove setting of policy->cpu in policy->cpus
    during init (bsc#1101480).

  - crypto: ablkcipher - fix crash flushing dcache in error
    path (bsc#1051510).

  - crypto: blkcipher - fix crash flushing dcache in error
    path (bsc#1051510).

  - crypto: caam/jr - fix descriptor DMA unmapping
    (bsc#1051510).

  - crypto: caam/qi - fix error path in xts setkey
    (bsc#1051510).

  - crypto: ccp - Check for NULL PSP pointer at module
    unload (bsc#1051510).

  - crypto: ccp - Fix command completion detection race
    (bsc#1051510).

  - crypto: clarify licensing of OpenSSL asm code ().

  - crypto: sharah - Unregister correct algorithms for
    SAHARA 3 (bsc#1051510).

  - crypto: skcipher - fix aligning block size in
    skcipher_copy_iv() (bsc#1051510).

  - crypto: skcipher - fix crash flushing dcache in error
    path (bsc#1051510).

  - crypto: skcipher - Fix -Wstringop-truncation warnings
    (bsc#1051510).

  - crypto: vmac - require a block cipher with 128-bit block
    size (bsc#1051510).

  - crypto: vmac - separate tfm and request context
    (bsc#1051510).

  - crypto: vmx - Fix sleep-in-atomic bugs (bsc#1051510).

  - crypto: vmx - Use skcipher for ctr fallback to SLE12-SP4
    (bsc#1106464).

  - crypto: x86/sha256-mb - fix digest copy in
    sha256_mb_mgr_get_comp_job_avx2() (bsc#1051510).

  - cxgb4: Fix the condition to check if the card is T5
    (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588
    bsc#1097583 bsc#1097584).

  - cxl: Configure PSL to not use APC virtual machines
    (bsc#1055014, git-fixes).

  - cxl: Fix wrong comparison in cxl_adapter_context_get()
    (bsc#1055014, git-fixes).

  - dax: Introduce a ->copy_to_iter dax operation
    (bsc#1098782).

  - dax: Make extension of dax_operations transparent
    (bsc#1098782).

  - dax: remove default copy_from_iter fallback
    (bsc#1098782).

  - dax: remove VM_MIXEDMAP for fsdax and device dax
    (bsc#1106007).

  - dax: Report bytes remaining in dax_iomap_actor()
    (bsc#1098782).

  - dax: require 'struct page' by default for filesystem dax
    (bsc#1104888).

  - dax: store pfns in the radix (bsc#1104888).

  - dccp: fix undefined behavior with 'cwnd' shift in
    ccid2_cwnd_restart() (netfilter-stable-18_08_17).

  - devicectree: bindings: fix location of leds common file
    (bsc#1051510).

  - device-dax: Add missing address_space_operations
    (bsc#1107783).

  - device-dax: Enable page_mapping() (bsc#1107783).

  - device-dax: Set page->index (bsc#1107783).

  - /dev/mem: Add bounce buffer for copy-out (git-fixes).

  - /dev/mem: Avoid overwriting 'err' in read_mem()
    (git-fixes).

  - dma-buf: remove redundant initialization of sg_table
    (bsc#1051510).

  - dmaengine: hsu: Support dmaengine_terminate_sync()
    (bsc#1051510).

  - dmaengine: idma64: Support dmaengine_terminate_sync()
    (bsc#1051510).

  - dmaengine: mv_xor_v2: kill the tasklets upon exit
    (bsc#1051510).

  - doc/README.SUSE: Remove mentions of cloneconfig
    (bsc#1103636).

  - docs: zh_CN: fix location of oops-tracing.txt
    (bsc#1051510).

  - Documentation: add some docs for errseq_t (bsc#1107008).

  - Documentation: ip-sysctl.txt: document addr_gen_mode
    (bsc#1051510).

  - driver core: add __printf verification to
    __ata_ehi_pushv_desc (bsc#1051510).

  - drivers: hv: vmbus: do not mark HV_PCIE as perf_device
    (bsc#1051510).

  - drivers: hv: vmbus: Fix the offer_in_progress in
    vmbus_process_offer() (bsc#1051510).

  - drm: Add and handle new aspect ratios in DRM layer ().

  - drm: Add aspect ratio parsing in DRM layer ().

  - drm: Add DRM client cap for aspect-ratio ().

  - drm/amdgpu:add new firmware id for VCN (bsc#1051510).

  - drm/amdgpu:add tmr mc address into amdgpu_firmware_info
    (bsc#1051510).

  - drm/amdgpu: Fix RLC safe mode test in
    gfx_v9_0_enter_rlc_safe_mode (bsc#1051510).

  - drm/amdgpu: fix swapped emit_ib_size in vce3
    (bsc#1051510).

  - drm/amdgpu: update tmr mc address (bsc#1100132).

  - drm/amd/pp/Polaris12: Fix a chunk of registers missed to
    program (bsc#1051510).

  - drm/armada: fix colorkey mode property (bsc#1051510).

  - drm/armada: fix irq handling (bsc#1051510).

  - drm/arm/malidp: Preserve LAYER_FORMAT contents when
    setting format (bsc#1051510).

  - drm/bridge: adv7511: Reset registers on hotplug
    (bsc#1051510).

  - drm/bridge/sii8620: Fix display of packed pixel modes
    (bsc#1051510).

  - drm/bridge/sii8620: fix display of packed pixel modes in
    MHL2 (bsc#1051510).

  - drm/bridge/sii8620: fix loops in EDID fetch logic
    (bsc#1051510).

  - drm/cirrus: Use drm_framebuffer_put to avoid kernel oops
    in clean-up (bsc#1101822).

  - drm/edid: Add 6 bpc quirk for SDC panel in Lenovo B50-80
    (bsc#1051510).

  - drm: Expose modes with aspect ratio, only if requested
    ().

  - drm/exynos: decon5433: Fix per-plane global alpha for
    XRGB modes (bsc#1051510).

  - drm/exynos: decon5433: Fix WINCONx reset value
    (bsc#1051510).

  - drm/exynos: gsc: Fix support for NV16/61, YUV420/YVU420
    and YUV422 modes (bsc#1051510).

  - drm/fb-helper: Fix typo on kerneldoc (bsc#1051510).

  - drm: Handle aspect ratio info in legacy modeset path ().

  - drm/i915/aml: Introducing Amber Lake platform ().

  - drm/i915/audio: Fix audio enumeration issue on BXT ().

  - drm/i915/cfl: Add a new CFL PCI ID ().

  - drm/i915/gvt: clear ggtt entries when destroy vgpu
    (bsc#1051510).

  - drm/i915/gvt: Fix the incorrect length of
    child_device_config issue (bsc#1051510).

  - drm/i915/gvt: Off by one in intel_vgpu_write_fence()
    (bsc#1051510).

  - drm/i915/gvt: request srcu_read_lock before checking if
    one gfn is valid (bsc#1051510).

  - drm/i915: Increase LSPCON timeout (bsc#1051510).

  - drm/i915/kvmgt: Fix potential Spectre v1 (bsc#1051510).

  - drm/i915/lpe: Mark LPE audio runtime pm as 'no
    callbacks' (bsc#1051510).

  - drm/i915: Nuke the LVDS lid notifier (bsc#1051510).

  - drm/i915: Only show debug for state changes when banning
    (bsc#1051510).

  - drm/i915/overlay: Allocate physical registers from
    stolen (bsc#1051510).

  - drm/i915: Restore user forcewake domains across suspend
    (bsc#1100132).

  - drm/i915: set DP Main Stream Attribute for color range
    on DDI platforms (bsc#1051510).

  - drm/i915: Unmask user interrupts writes into HWSP on
    snb/ivb/vlv/hsw (bsc#1051510).

  - drm/i915/whl: Introducing Whiskey Lake platform ().

  - drm/imx: imx-ldb: check if channel is enabled before
    printing warning (bsc#1051510).

  - drm/imx: imx-ldb: disable LDB on driver bind
    (bsc#1051510).

  - drm: mali-dp: Enable Global SE interrupts mask for DP500
    (bsc#1051510).

  - drm/modes: Introduce drm_mode_match() ().

  - drm/nouveau/drm/nouveau: Fix bogus
    drm_kms_helper_poll_enable() placement (bsc#1051510).

  - drm/panel: type promotion bug in s6e8aa0_read_mtp_id()
    (bsc#1051510).

  - drm/rockchip: lvds: add missing of_node_put
    (bsc#1051510).

  - drm/tegra: Check for malformed offsets and sizes in the
    'submit' IOCTL (bsc#1106170).

  - drm/tegra: Fix comparison operator for buffer size
    (bsc#1100132).

  - drm/vc4: Fix the 'no scaling' case on multi-planar YUV
    formats (bsc#1051510).

  - dwc2: gadget: Fix ISOC IN DDMA PID bitfield value
    calculation (bsc#1051510).

  - EDAC, altera: Fix ARM64 build warning (bsc#1051510).

  - EDAC: Fix memleak in module init error path
    (bsc#1051510).

  - EDAC, i7core: Fix memleaks and use-after-free on probe
    and remove (bsc#1051510).

  - EDAC, mv64x60: Fix an error handling path (bsc#1051510).

  - EDAC, octeon: Fix an uninitialized variable warning
    (bsc#1051510).

  - EDAC, sb_edac: Fix missing break in switch
    (bsc#1051510).

  - errseq: Add to documentation tree (bsc#1107008).

  - errseq: Always report a writeback error once
    (bsc#1107008).

  - ext2: auto disable dax instead of failing mount
    (bsc#1104888).

  - ext2, dax: introduce ext2_dax_aops (bsc#1104888).

  - ext4: auto disable dax instead of failing mount
    (bsc#1104888).

  - ext4, dax: add ext4_bmap to ext4_dax_aops (bsc#1104888).

  - ext4, dax: introduce ext4_dax_aops (bsc#1104888).

  - ext4, dax: set ext4_dax_aops for dax files
    (bsc#1104888).

  - ext4: sysfs: print ext4_super_block fields as
    little-endian (bsc#1106229).

  - extcon: Release locking when sending the notification of
    connector state (bsc#1051510).

  - f2fs: remove unneeded memory footprint accounting
    (bsc#1106233).

  - f2fs: remove unneeded memory footprint accounting
    (bsc#1106297).

  - f2fs: validate before set/clear free nat bitmap
    (bsc#1106231).

  - f2fs: validate before set/clear free nat bitmap
    (bsc#1106297).

  - fat: fix memory allocation failure handling of
    match_strdup() (bsc#1051510).

  - fbdev: Distinguish between interlaced and progressive
    modes (bsc#1051510).

  - fbdev: omapfb: off by one in omapfb_register_client()
    (bsc#1051510).

  - fbdev/via: fix defined but not used warning
    (bsc#1051510).

  - fb: fix lost console when the user unplugs a USB adapter
    (bsc#1051510).

  - filesystem-dax: Introduce dax_lock_mapping_entry()
    (bsc#1107783).

  - filesystem-dax: Set page->index (bsc#1107783).

  - fix a page leak in vhost_scsi_iov_to_sgl() error
    recovery (bsc#1051510).

  - Fix buggy backport in
    patches.fixes/dax-check-for-queue_flag_dax-in-bdev_dax_s
    upported.patch (bsc#1109859)

  - Fix kABI breakage due to enum addition for ath10k
    (bsc#1051510).

  - Fix kABI breakage with libertas dev field addition
    (bsc#1051510).

  - Fix kABI breakage with removing field addition to
    power_supply (bsc#1051510).

  - Fix kexec forbidding kernels signed with keys in the
    secondary keyring to boot (bsc#1110006).

  - fix __legitimize_mnt()/mntput() race (bsc#1106297).

  - fix mntput/mntput race (bsc#1106297).

  - fs/9p/xattr.c: catch the error of p9_client_clunk when
    setting xattr failed (bsc#1051510).

  - fs, dax: prepare for dax-specific
    address_space_operations (bsc#1104888).

  - fs, dax: use page->mapping to warn if truncate collides
    with a busy page (bsc#1104888).

  - fs/proc/proc_sysctl.c: fix potential page fault while
    unregistering sysctl table (bsc#1106297).

  - fuse: Add missed unlock_page() to fuse_readpages_fill()
    (bsc#1106291).

  - fuse: fix double request_end() (bsc#1106291).

  - fuse: fix initial parallel dirops (bsc#1106291).

  - fuse: Fix oops at process_init_reply() (bsc#1106291).

  - fuse: fix unlocked access to processing queue
    (bsc#1106291).

  - fuse: umount should wait for all requests (bsc#1106291).

  - geneve: update skb dst pmtu on tx path (bsc#1051510).

  - genirq: Add handle_fasteoi_{level,edge}_irq flow
    handlers (bsc#1105378).

  - genirq: Export more irq_chip_*_parent() functions
    (bsc#1105378).

  - genirq: Fix editing error in a comment (bsc#1051510).

  - genirq: Make force irq threading setup more robust
    (bsc#1051510).

  - gen_stats: Fix netlink stats dumping in the presence of
    padding (netfilter-stable-18_07_23).

  - getxattr: use correct xattr length (bsc#1106235).

  - getxattr: use correct xattr length (bsc#1106297).

  - gpio: Add gpio driver support for ThunderX and OCTEON-TX
    (bsc#1105378).

  - gpio: Fix wrong rounding in gpio-menz127 (bsc#1051510).

  - gpiolib-acpi: make sure we trigger edge events at least
    once on boot (bsc#1051510).

  - gpiolib: acpi: Switch to cansleep version of GPIO
    library call (bsc#1051510).

  - gpiolib: Mark gpio_suffixes array with __maybe_unused
    (bsc#1051510).

  - gpio: ml-ioh: Fix buffer underwrite on probe error path
    (bsc#1051510).

  - gpio: pxa: Fix potential NULL dereference (bsc#1051510).

  - gpio: tegra: Move driver registration to subsys_init
    level (bsc#1051510).

  - gpio: thunderx: fix error return code in
    thunderx_gpio_probe() (bsc#1105378).

  - gpio: thunderx: remove unused .map() hook from
    irq_domain_ops (bsc#1105378).

  - gpu: host1x: Check whether size of unpin isn't 0
    (bsc#1051510).

  - gpu: ipu-v3: csi: pass back mbus_code_to_bus_cfg error
    codes (bsc#1051510).

  - gpu: ipu-v3: default to id 0 on missing OF alias
    (bsc#1051510).

  - gtp: Initialize 64-bit per-cpu stats correctly
    (bsc#1051510).

  - HID: add quirk for another PIXART OEM mouse used by HP
    (bsc#1051510).

  - HID: hid-ntrig: add error handling for
    sysfs_create_group (bsc#1051510).

  - HID: i2c-hid: Add no-irq-after-reset quirk for 0911:5288
    device ().

  - hotplug/cpu: Add operation queuing function ().

  - hotplug/cpu: Conditionally acquire/release DRC index ().

  - hotplug/cpu: Provide CPU readd operation ().

  - i2c: core: ACPI: Properly set status byte to 0 for
    multi-byte writes (bsc#1051510).

  - i2c: davinci: Avoid zero value of CLKH (bsc#1051510).

  - i2c: i801: Add missing documentation entries for
    Braswell and Kaby Lake (bsc#1051510).

  - i2c: i801: Add support for Intel Cedar Fork
    (bsc#1051510).

  - i2c: i801: Add support for Intel Ice Lake (bsc#1051510).

  - i2c: i801: Allow ACPI AML access I/O ports not reserved
    for SMBus (bsc#1051510).

  - i2c: i801: Consolidate chipset names in documentation
    and Kconfig (bsc#1051510).

  - i2c: i801: fix DNV's SMBCTRL register offset
    (bsc#1051510).

  - i2c: imx: Fix race condition in dma read (bsc#1051510).

  - i2c: imx: Fix reinit_completion() use (bsc#1051510).

  - i2c: uniphier-f: issue STOP only for last message or
    I2C_M_STOP (bsc#1051510).

  - i2c: uniphier: issue STOP only for last message or
    I2C_M_STOP (bsc#1051510).

  - i2c: xiic: Make the start and the byte count write
    atomic (bsc#1051510).

  - i2c: xlp9xx: Fix case where SSIF read transaction
    completes early (bsc#1105907).

  - i2c: xlp9xx: Fix issue seen when updating receive length
    (bsc#1105907).

  - i2c: xlp9xx: Make sure the transfer size is not more
    than I2C_SMBUS_BLOCK_SIZE (bsc#1105907).

  - i40e: fix condition of WARN_ONCE for stat strings
    (bsc#1107522).

  - IB/core: type promotion bug in rdma_rw_init_one_mr()
    (bsc#1046306).

  - IB/hfi1: Invalid NUMA node information can cause a
    divide by zero (bsc#1060463).

  - IB/hfi1: Remove incorrect call to do_interrupt callback
    (bsc#1060463).

  - IB/hfi1: Set in_use_ctxts bits for user ctxts only
    (bsc#1060463 ).

  - IB/ipoib: Avoid a race condition between start_xmit and
    cm_rep_handler (bsc#1046307).

  - IB/ipoib: Fix error return code in ipoib_dev_init()
    (bsc#1046307 ).

  - IB/IPoIB: Set ah valid flag in multicast send flow
    (bsc#1046307 ).

  - IB/mlx4: Test port number before querying type
    (bsc#1046302 ).

  - IB/mlx4: Use 4K pages for kernel QP's WQE buffer
    (bsc#1046302 ).

  - IB/mlx5: fix uaccess beyond 'count' in debugfs
    read/write handlers (bsc#1046305).

  - ibmvnic: Include missing return code checks in reset
    function (bnc#1107966).

  - ib_srpt: Fix a use-after-free in srpt_close_ch()
    (bsc#1046306 ).

  - ieee802154: ca8210: fix uninitialised data read
    (bsc#1051510).

  - ieee802154: fix gcc-4.9 warnings (bsc#1051510).

  - ieee802154: mrf24j40: fix incorrect mask in
    mrf24j40_stop (bsc#1051510).

  - iio: 104-quad-8: Fix off-by-one error in register
    selection (bsc#1051510).

  - iio: ad9523: Fix displayed phase (bsc#1051510).

  - iio: ad9523: Fix return value for ad952x_store()
    (bsc#1051510).

  - iio: adc: ina2xx: avoid kthread_stop() with stale
    task_struct (bsc#1051510).

  - iio: adc: sun4i-gpadc: select REGMAP_IRQ (bsc#1051510).

  - iio: sca3000: Fix an error handling path in
    'sca3000_probe()' (bsc#1051510).

  - iio: sca3000: Fix missing return in switch
    (bsc#1051510).

  - ima: based on policy verify firmware signatures
    (pre-allocated buffer) (bsc#1051510).

  - include/rdma/opa_addr.h: Fix an endianness issue
    (bsc#1046306 ).

  - init: rename and re-order boot_cpu_state_init()
    (bsc#1104365).

  - Input: atmel_mxt_ts - only use first T9 instance
    (bsc#1051510).

  - Input: edt-ft5x06 - fix error handling for factory mode
    on non-M06 (bsc#1051510).

  - Input: edt-ft5x06 - implement support for the EDT-M12
    series (bsc#1051510).

  - Input: edt-ft5x06 - make distinction between
    m06/m09/generic more clear (bsc#1051510).

  - Input: elantech - enable middle button of touchpad on
    ThinkPad P72 (bsc#1051510).

  - input: rohm_bu21023: switch to i2c_lock_bus(...,
    I2C_LOCK_SEGMENT) (bsc#1051510).

  - Input: synaptics-rmi4 - fix axis-swap behavior
    (bsc#1051510).

  - intel_th: Fix device removal logic (bsc#1051510).

  - iommu/amd: Add support for higher 64-bit IOMMU Control
    Register ().

  - iommu/amd: Add support for IOMMU XT mode ().

  - iommu/amd: Finish TLB flush in amd_iommu_unmap()
    (bsc#1106105).

  - iommu/amd: make sure TLB to be flushed before IOVA freed
    (bsc#1106105).

  - iommu/amd: Return devid as alias for ACPI HID devices
    (bsc#1106105).

  - iommu/arm-smmu-v3: Do not free page table ops twice
    (bsc#1106237).

  - iommu/vt-d: Fix a potential memory leak (bsc#1106105).

  - iommu/vt-d: Ratelimit each dmar fault printing
    (bsc#1106105).

  - ioremap: Update pgtable free interfaces with addr
    (bsc#1110006).

  - ipc/shm: fix shmat() nil address after round-down when
    remapping (bsc#1090078).

  - ip: hash fragments consistently
    (netfilter-stable-18_07_27).

  - ip: in cmsg IP(V6)_ORIGDSTADDR call pskb_may_pull
    (netfilter-stable-18_07_27).

  - ipmi:bt: Set the timeout before doing a capabilities
    check (bsc#1051510).

  - ipmi: Fix some counter issues (bsc#1105907).

  - ipmi: Move BT capabilities detection to the detect call
    (bsc#1106779).

  - ipmi/powernv: Fix error return code in
    ipmi_powernv_probe() (git-fixes).

  - ipmi: Remove ACPI SPMI probing from the SSIF (I2C)
    driver (bsc#1105907).

  - ipv4: remove BUG_ON() from fib_compute_spec_dst
    (netfilter-stable-18_08_01).

  - ipv4: Return EINVAL when ping_group_range sysctl does
    not map to user ns (netfilter-stable-18_07_23).

  - ipv6: fix useless rol32 call on hash
    (netfilter-stable-18_07_23).

  - ipv6: ila: select CONFIG_DST_CACHE
    (netfilter-stable-18_07_23).

  - ipv6: make DAD fail with enhanced DAD when nonce length
    differs (netfilter-stable-18_07_23).

  - ipv6: sr: fix passing wrong flags to
    crypto_alloc_shash() (networking-stable-18_07_19).

  - ipvlan: fix IFLA_MTU ignored on NEWLINK
    (networking-stable-18_07_19).

  - irqchip/bcm7038-l1: Hide cpu offline callback when
    building for !SMP (bsc#1051510).

  - irqdomain: Add irq_domain_{push,pop}_irq() functions
    (bsc#1105378).

  - irqdomain: Check for NULL function pointer in
    irq_domain_free_irqs_hierarchy() (bsc#1105378).

  - irqdomain: Factor out code to add and remove items to
    and from the revmap (bsc#1105378).

  - irqdomain: Prevent potential NULL pointer dereference in
    irq_domain_push_irq() (bsc#1105378).

  - irqdomain: Update the comments of fwnode field of
    irq_domain structure (bsc#1051510).

  - isdn: Disable IIOCDBGVAR (bsc#1051510).

  - iw_cxgb4: remove duplicate memcpy() in
    c4iw_create_listen() (bsc#1046543).

  - iwlwifi: pcie: do not access periphery registers when
    not available (bsc#1051510).

  - ixgbe: Refactor queue disable logic to take completion
    time into account (bsc#1101557).

  - ixgbe: Reorder Tx/Rx shutdown to reduce time needed to
    stop device (bsc#1101557).

  - kabi fix for check_disk_size_change() (bsc#1098459).

  - kabi: move s390 mm_context_t lock to mm_struct and
    ignore the change (bsc#1103421).

  - kabi: move the new handler to end of machdep_calls and
    hide it from genksyms (bsc#1094244).

  - kabi protect hnae_ae_ops (bsc#1107924).

  - kabi protect struct kvm_sync_regs (bsc#1106948).

  - kabi/severities: Whitelist libceph, rbd, and ceph
    (bsc#1096748).

  - kabi: tpm: change relinquish_locality return value back
    to void (bsc#1082555).

  - kabi: tpm: do keep the cmd_ready and go_idle as pm ops
    (bsc#1082555).

  - kabi: x86/speculation/l1tf: Increase l1tf memory limit
    for Nehalem+ (bnc#1105536).

  - kprobes/x86: Release insn_slot in failure path
    (bsc#1110006).

  - kthread, tracing: Do not expose half-written comm when
    creating kthreads (bsc#1104897).

  - kvm: arm64: Convert kvm_set_s2pte_readonly() from inline
    asm to cmpxchg() (bsc#1108010).

  - kvm: Enforce error in ioctl for compat tasks when
    !KVM_COMPAT (bsc#1106240).

  - kvm: nVMX: Do not flush TLB when vmcs12 uses VPID
    (bsc#1106240).

  - kvm: nVMX: Fix fault vector for VMX operation at CPL > 0
    (bsc#1106105).

  - kvm: nVMX: Fix injection to L2 when L1 do not intercept
    external-interrupts (bsc#1106240).

  - kvm: nVMX: Fix races when sending nested PI while dest
    enters/leaves L2 (bsc#1106240).

  - kvm: nVMX: Re-evaluate L1 pending events when running L2
    and L1 got posted-interrupt (bsc#1106240).

  - kvm: nVMX: Use nested_run_pending rather than
    from_vmentry (bsc#1106240).

  - kvm: PPC: Book3S: Fix guest DMA when guest partially
    backed by THP pages (bsc#1077761, git-fixes,
    bsc#1103948, bsc#1103949).

  - kvm: PPC: Book3S HV: Use correct pagesize in
    kvm_unmap_radix() (bsc#1061840, git-fixes).

  - kvm: s390: add etoken support for guests (bsc#1106948,
    LTC#171029).

  - kvm: s390: force bp isolation for VSIE (bsc#1103421).

  - kvm: s390: implement CPU model only facilities
    (bsc#1106948, LTC#171029).

  - kvm: VMX: Do not allow reexecute_instruction() when
    skipping MMIO instr (bsc#1106240).

  - kvm: VMX: fixes for vmentry_l1d_flush module parameter
    (bsc#1106369).

  - kvm: VMX: Work around kABI breakage in 'enum
    vmx_l1d_flush_state' (bsc#1106369).

  - kvm: x86: Change __kvm_apic_update_irr() to also return
    if max IRR updated (bsc#1106240).

  - kvm: x86: Default to not allowing emulation retry in
    kvm_mmu_page_fault (bsc#1106240).

  - kvm: x86: Do not re-{try,execute} after failed emulation
    in L2 (bsc#1106240).

  - kvm: x86: fix APIC page invalidation (bsc#1106240).

  - kvm: x86: Invert emulation re-execute behavior to make
    it opt-in (bsc#1106240).

  - kvm: x86: Merge EMULTYPE_RETRY and
    EMULTYPE_ALLOW_REEXECUTE (bsc#1106240).

  - kvm/x86: remove WARN_ON() for when vm_munmap() fails
    (bsc#1106240).

  - kvm: x86: SVM: Call x86_spec_ctrl_set_guest/host() with
    interrupts disabled (git-fixes 1f50ddb4f418).

  - kvm: x86: vmx: fix vpid leak (bsc#1106240).

  - l2tp: use sk_dst_check() to avoid race on
    sk->sk_dst_cache (netfilter-stable-18_08_17).

  - lan78xx: Check for supported Wake-on-LAN modes
    (bsc#1051510).

  - lan78xx: Lan7801 Support for Fixed PHY (bsc#1085262).

  - lan78xx: remove redundant initialization of pointer
    'phydev' (bsc#1085262).

  - lan78xx: Set ASD in MAC_CR when EEE is enabled
    (bsc#1085262).

  - leds: max8997: use mode when calling
    max8997_led_set_mode (bsc#1051510).

  - libahci: Fix possible Spectre-v1 pmp indexing in
    ahci_led_store() (bsc#1051510).

  - libata: Fix command retry decision (bsc#1051510).

  - libata: Fix compile warning with ATA_DEBUG enabled
    (bsc#1051510).

  - libbpf: Makefile set specified permission mode
    (bsc#1083647).

  - libceph: check authorizer reply/challenge length before
    reading (bsc#1096748).

  - libceph: factor out __ceph_x_decrypt() (bsc#1096748).

  - libceph: factor out encrypt_authorizer() (bsc#1096748).

  - libceph: factor out __prepare_write_connect()
    (bsc#1096748).

  - libceph: store ceph_auth_handshake pointer in
    ceph_connection (bsc#1096748).

  - libceph: weaken sizeof check in
    ceph_x_verify_authorizer_reply() (bsc#1096748).

  - libertas: fix suspend and resume for SDIO connected
    cards (bsc#1051510).

  - lib/iov_iter: Fix pipe handling in
    _copy_to_iter_mcsafe() (bsc#1098782).

  - libnvdimm, btt: fix uninitialized err_lock
    (bsc#1103961).

  - libnvdimm: fix ars_status output length calculation
    (bsc#1104890).

  - libnvdimm, nfit: enable support for volatile ranges
    (bsc#1103961).

  - libnvdimm, nfit: move the check on nd_reserved2 to the
    endpoint (bsc#1103961).

  - libnvdimm, pmem: Fix memcpy_mcsafe() return code
    handling in nsio_rw_bytes() (bsc#1098782).

  - libnvdimm, pmem: Restore page attributes when clearing
    errors (bsc#1107783).

  - libnvdimm: rename nd_sector_size_{show,store} to
    nd_size_select_{show,store} (bsc#1103961).

  - libnvdimm: Use max contiguous area for namespace size
    (git-fixes).

  - lib/rhashtable: consider param->min_size when setting
    initial table size (bsc#1051510).

  - lib/test_hexdump.c: fix failure on big endian cpu
    (bsc#1051510).

  - lib/vsprintf: Remove atomic-unsafe support for %pCr
    (bsc#1051510).

  - Limit kernel-source build to architectures for which we
    build binaries (bsc#1108281).

  - livepatch: Remove reliable stacktrace check in
    klp_try_switch_task() (bsc#1071995).

  - livepatch: Validate module/old func name length
    (bsc#1071995).

  - llc: use refcount_inc_not_zero() for llc_sap_find()
    (netfilter-stable-18_08_17).

  - mac80211: add stations tied to AP_VLANs during hw
    reconfig (bsc#1051510).

  - mac80211: always account for A-MSDU header changes
    (bsc#1051510).

  - mac80211: avoid kernel panic when building AMSDU from
    non-linear SKB (bsc#1051510).

  - mac80211: fix an off-by-one issue in A-MSDU max_subframe
    computation (bsc#1051510).

  - mac80211: fix pending queue hang due to TX_DROP
    (bsc#1051510).

  - mac80211: restrict delayed tailroom needed decrement
    (bsc#1051510).

  - macros.kernel-source: pass -b properly in kernel module
    package (bsc#1107870).

  - mailbox: xgene-slimpro: Fix potential NULL pointer
    dereference (bsc#1051510).

  - MAINTAINERS: fix location of ina2xx.txt device tree file
    (bsc#1051510).

  - md-cluster: clear another node's suspend_area after the
    copy is finished (bsc#1106333).

  - md-cluster: do not send msg if array is closing
    (bsc#1106333).

  - md-cluster: release RESYNC lock after the last resync
    message (bsc#1106688).

  - md-cluster: show array's status more accurate
    (bsc#1106333).

  - media: exynos4-is: Prevent NULL pointer dereference in
    __isp_video_try_fmt() (bsc#1051510).

  - media: mem2mem: Remove excessive try_run call
    (bsc#1051510).

  - media: omap3isp: fix unbalanced dma_iommu_mapping
    (bsc#1051510).

  - media: omap3isp: zero-initialize the isp cam_xclk{a,b}
    initial data (bsc#1051510).

  - media: Revert '[media] tvp5150: fix pad format frame
    height' (bsc#1051510).

  - media: rtl28xxu: be sure that it won't go past the array
    size (bsc#1051510).

  - media: tw686x: Fix oops on buffer alloc failure
    (bsc#1051510).

  - media: v4l2-mem2mem: Fix missing v4l2_m2m_try_run call
    (bsc#1051510).

  - media: videobuf2-core: do not call memop 'finish' when
    queueing (bsc#1051510).

  - mei: bus: type promotion bug in mei_nfc_if_version()
    (bsc#1051510).

  - mei: do not update offset in write (bsc#1051510).

  - mei: ignore not found client in the enumeration
    (bsc#1051510).

  - mei: me: enable asynchronous probing ().

  - memcg, thp: do not invoke oom killer on thp charges
    (bnc#1089663).

  - memory: tegra: Apply interrupts mask per SoC
    (bsc#1051510).

  - memory: tegra: Do not handle spurious interrupts
    (bsc#1051510).

  - mfd: 88pm860x-i2c: switch to i2c_lock_bus(...,
    I2C_LOCK_SEGMENT) (bsc#1051510).

  - mfd: arizona: Do not use regmap_read_poll_timeout
    (bsc#1051510).

  - mfd: intel-lpss: Add Ice Lake PCI IDs (bsc#1051510).

  - mfd: lpc_ich: Do not touch SPI-NOR write protection bit
    on Apollo Lake (bsc#1051510).

  - mfd: sm501: Set coherent_dma_mask when creating
    subdevices (bsc#1051510).

  - mfd: ti_am335x_tscadc: Fix struct clk memory leak
    (bsc#1051510).

  - mlxsw: core_acl_flex_actions: Return error for
    conflicting actions (netfilter-stable-18_08_17).

  - mmc: omap_hsmmc: fix wakeirq handling on removal
    (bsc#1051510).

  - mmc: sdhci: do not try to use 3.3V signaling if not
    supported (bsc#1051510).

  - mmc: sdhci-of-esdhc: set proper dma mask for ls104x
    chips (bsc#1051510).

  - mmc: tegra: prevent HS200 on Tegra 3 (bsc#1051510).

  - mm, dax: introduce pfn_t_special() (bsc#1104888).

  - mm: fix devmem_is_allowed() for sub-page System RAM
    intersections (bsc#1106800).

  - mm/huge_memory.c: fix data loss when splitting a file
    pmd (bnc#1107074).

  - mm/hugetlb: filter out hugetlb pages if HUGEPAGE
    migration is not supported (bnc#1106697).

  - mm, madvise_inject_error: Disable MADV_SOFT_OFFLINE for
    ZONE_DEVICE pages (bsc#1107783).

  - mm, madvise_inject_error: Let memory_failure()
    optionally take a page reference (bsc#1107783).

  - mm: memcg: fix use after free in mem_cgroup_iter()
    (bnc#1107065).

  - mm, memory_failure: Collect mapping size in
    collect_procs() (bsc#1107783).

  - mm, memory_failure: Teach memory_failure() about
    dev_pagemap pages (bsc#1107783).

  - mm, numa: Migrate pages to local nodes quicker early in
    the lifetime of a task (bnc#1101669 optimise numa
    balancing for fast migrate).

  - mm, numa: Remove rate-limiting of automatic numa
    balancing migration (bnc#1101669 optimise numa balancing
    for fast migrate).

  - mm, numa: Remove rate-limiting of automatic numa
    balancing migration kabi (bnc#1101669 optimise numa
    balancing for fast migrate).

  - mm, page_alloc: double zone's batchsize (bnc#971975 VM
    performance -- page allocator).

  - mm/vmalloc: add interfaces to free unmapped page table
    (bsc#1110006).

  - mm/vmscan: wake up flushers for legacy cgroups too
    (bnc#1107061).

  - module: exclude SHN_UNDEF symbols from kallsyms api
    (bsc#1071995).

  - Move the previous hv netvsc fix to the sorted section
    (bsc#1104708)

  - net/9p/client.c: version pointer uninitialized
    (bsc#1051510).

  - net/9p: fix error path of p9_virtio_probe (bsc#1051510).

  - net/9p: Switch to wait_event_killable() (bsc#1051510).

  - net/9p/trans_fd.c: fix race by holding the lock
    (bsc#1051510).

  - net/9p/trans_fd.c: fix race-condition by flushing
    workqueue before the kfree() (bsc#1051510).

  - net: bcmgenet: correct bad merge (bsc#1051510).

  - net: bcmgenet: enable loopback during UniMAC sw_reset
    (bsc#1051510).

  - net: bcmgenet: Fix sparse warnings in
    bcmgenet_put_tx_csum() (bsc#1051510).

  - net: bcmgenet: Fix unmapping of fragments in
    bcmgenet_xmit() (bsc#1051510).

  - net: bcmgenet: prevent duplicate calls of
    bcmgenet_dma_teardown (bsc#1051510).

  - net: dccp: avoid crash in ccid3_hc_rx_send_feedback()
    (networking-stable-18_07_19).

  - net: dccp: switch rx_tstamp_last_feedback to monotonic
    clock (networking-stable-18_07_19).

  - net: diag: Do not double-free TCP_NEW_SYN_RECV sockets
    in tcp_abort (netfilter-stable-18_07_23).

  - net: dsa: Do not suspend/resume closed slave_dev
    (netfilter-stable-18_08_04).

  - net: ena: Eliminate duplicate barriers on weakly-ordered
    archs (bsc#1108093).

  - net: ena: fix device destruction to gracefully free
    resources (bsc#1108093).

  - net: ena: fix driver when PAGE_SIZE == 64kB
    (bsc#1108093).

  - net: ena: fix incorrect usage of memory barriers
    (bsc#1108093).

  - net: ena: fix missing calls to READ_ONCE (bsc#1108093).

  - net: ena: fix missing lock during device destruction
    (bsc#1108093).

  - net: ena: fix potential double ena_destroy_device()
    (bsc#1108093).

  - net: ena: fix surprise unplug NULL dereference kernel
    crash (bsc#1108093).

  - net: ena: Fix use of uninitialized DMA address bits
    field (netfilter-stable-18_08_01).

  - net: ethernet: mvneta: Fix napi structure mixup on
    armada 3700 (networking-stable-18_08_21).

  - netfilter: do not set F_IFACE on ipv6 fib lookups
    (netfilter-stable-18_06_25).

  - netfilter: ip6t_rpfilter: provide input interface for
    route lookup (netfilter-stable-18_06_25).

  - netfilter: ip6t_rpfilter: set F_IFACE for linklocal
    addresses (git-fixes).

  - netfilter: nat: Revert 'netfilter: nat: convert nat
    bysrc hash to rhashtable' (netfilter-stable-17_11_16).

  - netfilter: nf_tables: add missing netlink attrs to
    policies (netfilter-stable-18_06_27).

  - netfilter: nf_tables: do not assume chain stats are set
    when jumplabel is set (netfilter-stable-18_06_27).

  - netfilter: nf_tables: fix memory leak on error exit
    return (netfilter-stable-18_06_27).

  - netfilter: nf_tables: nft_compat: fix refcount leak on
    xt module (netfilter-stable-18_06_27).

  - netfilter: nf_tables: use WARN_ON_ONCE instead of BUG_ON
    in nft_do_chain() (netfilter-stable-18_06_25).

  - netfilter: nft_compat: fix handling of large matchinfo
    size (netfilter-stable-18_06_27).

  - netfilter: nft_compat: prepare for indirect info storage
    (netfilter-stable-18_06_27).

  - netfilter: nft_meta: fix wrong value dereference in
    nft_meta_set_eval (netfilter-stable-18_06_27).

  - net: fix amd-xgbe flow-control issue
    (netfilter-stable-18_08_01).

  - net: fix use-after-free in GRO with ESP
    (networking-stable-18_07_19).

  - net: hns3: add unlikely for error check (bsc#1104353 ).

  - net: hns3: Fix comments for
    hclge_get_ring_chain_from_mbx (bsc#1104353).

  - net: hns3: Fix desc num set to default when setting
    channel (bsc#1104353).

  - net: hns3: Fix for command format parsing error in
    hclge_is_all_function_id_zero (bsc#1104353).

  - net: hns3: Fix for information of phydev lost problem
    when down/up (bsc#1104353).

  - net: hns3: Fix for l4 checksum offload bug (bsc#1104353
    ).

  - net: hns3: Fix for mac pause not disable in pfc mode
    (bsc#1104353).

  - net: hns3: Fix for mailbox message truncated problem
    (bsc#1104353).

  - net: hns3: Fix for phy link issue when using marvell phy
    driver (bsc#1104353).

  - net: hns3: Fix for reset_level default assignment
    probelm (bsc#1104353).

  - net: hns3: Fix for using wrong mask and shift in
    hclge_get_ring_chain_from_mbx (bsc#1104353).

  - net: hns3: Fix for waterline not setting correctly
    (bsc#1104353 ).

  - net: hns3: Fix get_vector ops in hclgevf_main module
    (bsc#1104353).

  - net: hns3: Fix MSIX allocation issue for VF (bsc#1104353
    ).

  - net: hns3: fix page_offset overflow when
    CONFIG_ARM64_64K_PAGES (bsc#1104353).

  - net: hns3: Fix return value error in
    hns3_reset_notify_down_enet (bsc#1104353).

  - net: hns3: fix return value error while
    hclge_cmd_csq_clean failed (bsc#1104353).

  - net: hns3: Fix warning bug when doing lp selftest
    (bsc#1104353 ).

  - net: hns3: modify hnae_ to hnae3_ (bsc#1104353).

  - net: hns3: Prevent sending command during global or core
    reset (bsc#1104353).

  - net: hns3: remove some redundant assignments
    (bsc#1104353 ).

  - net: hns3: remove unnecessary ring configuration
    operation while resetting (bsc#1104353).

  - net: hns3: simplify hclge_cmd_csq_clean (bsc#1104353 ).

  - net: hns3: Standardize the handle of return value
    (bsc#1104353 ).

  - net: hns: add netif_carrier_off before change speed and
    duplex (bsc#1107924).

  - net: hns: add the code for cleaning pkt in chip
    (bsc#1107924).

  - net/ipv4: Set oif in fib_compute_spec_dst
    (netfilter-stable-18_07_23).

  - netlink: Do not shift on 64 for ngroups (git-fixes).

  - netlink: Do not shift with UB on nlk->ngroups
    (netfilter-stable-18_08_01).

  - netlink: Do not subscribe to non-existent groups
    (netfilter-stable-18_08_01).

  - netlink: Fix spectre v1 gadget in netlink_create()
    (netfilter-stable-18_08_04).

  - net: mdio-mux: bcm-iproc: fix wrong getter and setter
    pair (netfilter-stable-18_08_01).

  - net/mlx5e: Avoid dealing with vport representors if not
    being e-switch manager (networking-stable-18_07_19).

  - net/mlx5: E-Switch, Avoid setup attempt if not being
    e-switch manager (networking-stable-18_07_19).

  - net: mvneta: fix mvneta_config_rss on armada 3700
    (networking-stable-18_08_21).

  - net: mvneta: fix the Rx desc DMA address in the Rx path
    (networking-stable-18_07_19).

  - net/packet: fix use-after-free
    (networking-stable-18_07_19).

  - Netperf performance issue due to AppArmor net mediation
    (bsc#1108520)

  - net: phy: consider PHY_IGNORE_INTERRUPT in
    phy_start_aneg_priv (netfilter-stable-18_07_27).

  - net: phy: fix flag masking in __set_phy_supported
    (netfilter-stable-18_07_23).

  - net: rtnl_configure_link: fix dev flags changes arg to
    __dev_notify_flags (git-fixes).

  - net_sched: blackhole: tell upper qdisc about dropped
    packets (networking-stable-18_07_19).

  - net_sched: Fix missing res info when create new tc_index
    filter (netfilter-stable-18_08_17).

  - net: skb_segment() should not return NULL
    (netfilter-stable-18_07_27).

  - net: stmmac: align DMA stuff to largest cache line
    length (netfilter-stable-18_08_01).

  - net: stmmac: Fix WoL for PCI-based setups
    (netfilter-stable-18_08_04).

  - net: stmmac: mark PM functions as __maybe_unused
    (git-fixes).

  - net: sungem: fix rx checksum support
    (networking-stable-18_07_19).

  - net: systemport: Fix CRC forwarding check for SYSTEMPORT
    Lite (netfilter-stable-18_07_23).

  - nfc: Fix possible memory corruption when handling SHDLC
    I-Frame commands (bsc#1051510).

  - nfs41: do not return ENOMEM on LAYOUTUNAVAILABLE
    (git-fixes).

  - nfsd: remove blocked locks on client teardown
    (git-fixes).

  - nfs/filelayout: fix oops when freeing filelayout segment
    (bsc#1105190).

  - nfs/filelayout: Fix racy setting of fl->dsaddr in
    filelayout_check_deviceid() (bsc#1105190).

  - nfs/pnfs: fix nfs_direct_req ref leak when i/o falls
    back to the mds (git-fixes).

  - nfs: Use an appropriate work queue for direct-write
    completion (bsc#1082519).

  - nfsv4 client live hangs after live data migration
    recovery (git-fixes).

  - nfsv4: Fix a sleep in atomic context in
    nfs4_callback_sequence() (git-fixes).

  - nfsv4: Fix possible 1-byte stack overflow in
    nfs_idmap_read_and_verify_message (git-fixes).

  - nl80211: Add a missing break in parse_station_flags
    (bsc#1051510).

  - nl80211: check nla_parse_nested() return values
    (bsc#1051510).

  - nvme_fc: add 'nvme_discovery' sysfs attribute to fc
    transport device (bsc#1044189).

  - nvme: register ns_id attributes as default sysfs groups
    (bsc#1105247).

  - parport: sunbpp: fix error return code (bsc#1051510).

  - partitions/aix: append null character to print data from
    disk (bsc#1051510).

  - partitions/aix: fix usage of uninitialized lv_info and
    lvname structures (bsc#1051510).

  - pci: aardvark: Fix I/O space page leak (git-fixes).

  - pci: aardvark: Size bridges before resources allocation
    (bsc#1109806).

  - pci: Add pci_resize_resource() for resizing BARs
    (bsc#1105355).

  - pci: Add PCI resource type mask #define (bsc#1105355).

  - pci: Add resizable BAR infrastructure (bsc#1105355).

  - pci: Allow release of resources that were never assigned
    (bsc#1105355).

  - pci: Cleanup PCI_REBAR_CTRL_BAR_SHIFT handling
    (bsc#1105355).

  - pci: designware: Fix I/O space page leak (bsc#1109806).

  - pci: faraday: Add missing of_node_put() (bsc#1109806).

  - pci: faraday: Fix I/O space page leak (bsc#1109806).

  - pci: hotplug: Do not leak pci_slot on registration
    failure (bsc#1051510).

  - pci: hv: Make sure the bus domain is really unique
    (git-fixes).

  - pci: Match Root Port's MPS to endpoint's MPSS as
    necessary (bsc#1109269).

  - pci: mvebu: Fix I/O space end address calculation
    (bsc#1051510).

  - pci: OF: Fix I/O space page leak (git-fixes).

  - pci: pciehp: Fix unprotected list iteration in IRQ
    handler (bsc#1051510).

  - pci: pciehp: Fix use-after-free on unplug (bsc#1051510).

  - PCI/portdrv: Compute MSI/MSI-X IRQ vectors after final
    allocation (bsc#1109806).

  - PCI/portdrv: Factor out Interrupt Message Number lookup
    (bsc#1109806).

  - pci: Restore resized BAR state on resume (bsc#1105355).

  - pci: Skip MPS logic for Virtual Functions (VFs)
    (bsc#1051510).

  - pci: versatile: Fix I/O space page leak (bsc#1109806).

  - pci: xgene: Fix I/O space page leak (bsc#1109806).

  - pci: xilinx: Add missing of_node_put() (bsc#1109806).

  - pci: xilinx-nwl: Add missing of_node_put()
    (bsc#1109806).

  - pinctrl/amd: only handle irq if it is pending and
    unmasked (bsc#1051510).

  - pinctrl: cannonlake: Fix community ordering for H
    variant (bsc#1051510).

  - pinctrl: cannonlake: Fix HOSTSW_OWN register offset of H
    variant (bsc#1051510).

  - pinctrl: core: Return selector to the pinctrl driver
    (bsc#1051510).

  - pinctrl: freescale: off by one in
    imx1_pinconf_group_dbg_show() (bsc#1051510).

  - pinctrl: imx: off by one in imx_pinconf_group_dbg_show()
    (bsc#1051510).

  - pinctrl: pinmux: Return selector to the pinctrl driver
    (bsc#1051510).

  - pinctrl: qcom: spmi-gpio: Fix pmic_gpio_config_get() to
    be compliant (bsc#1051510).

  - pinctrl: single: Fix group and function selector use
    (bsc#1051510).

  - pipe: actually allow root to exceed the pipe buffer
    limits (bsc#1106297).

  - platform/x86: alienware-wmi: Correct a memory leak
    (bsc#1051510).

  - platform/x86: asus-nb-wmi: Add keymap entry for lid flip
    action on UX360 (bsc#1051510).

  - platform/x86: thinkpad_acpi: Proper model/release
    matching (bsc#1051510).

  - platform/x86: toshiba_acpi: Fix defined but not used
    build warnings (bsc#1051510).

  - PM / clk: signedness bug in of_pm_clk_add_clks()
    (bsc#1051510).

  - PM / devfreq: rk3399_dmc: Fix duplicated opp table on
    reload (bsc#1051510).

  - PM / Domains: Fix error path during attach in genpd
    (bsc#1051510).

  - pmem: Switch to copy_to_iter_mcsafe() (bsc#1098782).

  - PM / runtime: Drop usage count for suppliers at device
    link removal (bsc#1100132).

  - PM / sleep: wakeup: Fix build error caused by missing
    SRCU support (bsc#1051510).

  - pnfs/blocklayout: off by one in bl_map_stripe()
    (git-fixes).

  - power: gemini-poweroff: Avoid more spurious poweroffs
    (bsc#1051510).

  - power: generic-adc-battery: check for duplicate
    properties copied from iio channels (bsc#1051510).

  - power: generic-adc-battery: fix out-of-bounds write when
    copying channel properties (bsc#1051510).

  - powernv/pseries: consolidate code for mce early handling
    (bsc#1094244).

  - powerpc/64s: Default l1d_size to 64K in RFI fallback
    flush (bsc#1068032, git-fixes).

  - powerpc/64s: Fix compiler store ordering to SLB shadow
    area (bsc#1094244).

  - powerpc/64s: Fix DT CPU features Power9 DD2.1 logic
    (bsc#1055117).

  - powerpc/64s: move machine check SLB flushing to mm/slb.c
    (bsc#1094244).

  - powerpc64s: Show ori31 availability in spectre_v1 sysfs
    file not v2 (bsc#1068032, bsc#1080157, git-fixes).

  - powerpc: Avoid code patching freed init sections
    (bnc#1107735).

  - powerpc/fadump: cleanup crash memory ranges support
    (bsc#1103269).

  - powerpc/fadump: re-register firmware-assisted dump if
    already registered (bsc#1108170, bsc#1108823).

  - powerpc: Fix size calculation using resource_size()
    (bnc#1012382).

  - powerpc: KABI add aux_ptr to hole in paca_struct to
    extend it with additional members (bsc#1094244).

  - powerpc: kabi: move mce_data_buf into paca_aux
    (bsc#1094244).

  - powerpc/kprobes: Fix call trace due to incorrect preempt
    count (bsc#1065729).

  - powerpc/lib: Fix the feature fixup tests to actually
    work (bsc#1065729).

  - powerpc: make feature-fixup tests fortify-safe
    (bsc#1065729).

  - powerpc/mce: Fix SLB rebolting during MCE recovery path
    (bsc#1094244).

  - powerpc/numa: Use associativity if VPHN hcall is
    successful (bsc#1110363).

  - powerpc/perf: Fix IMC allocation routine (bsc#1054914).

  - powerpc/perf: Fix memory allocation for core-imc based
    on num_possible_cpus() (bsc#1054914).

  - powerpc/perf: Remove sched_task function defined for
    thread-imc (bsc#1054914).

  - powerpc/pkeys: Fix reading of ibm,
    processor-storage-keys property (bsc#1109244).

  - powerpc/powernv/npu: Do a PID GPU TLB flush when
    invalidating a large address range (bsc#1055120).

  - powerpc/pseries: Avoid using the size greater than
    RTAS_ERROR_LOG_MAX (bsc#1094244).

  - powerpc/pseries: Defer the logging of rtas error to irq
    work queue (bsc#1094244).

  - powerpc/pseries: Define MCE error event section
    (bsc#1094244).

  - powerpc/pseries: Disable CPU hotplug across migrations
    (bsc#1065729).

  - powerpc/pseries: Display machine check error details
    (bsc#1094244).

  - powerpc/pseries: Dump the SLB contents on SLB MCE errors
    (bsc#1094244).

  - powerpc/pseries: fix EEH recovery of some IOV devices
    (bsc#1078720, git-fixes).

  - powerpc/pseries: Fix endianness while restoring of r3 in
    MCE handler (bsc#1094244).

  - powerpc/pseries: Flush SLB contents on SLB MCE errors
    (bsc#1094244).

  - powerpc/pseries: Remove prrn_work workqueue
    (bsc#1102495, bsc#1109337).

  - powerpc/pseries: Remove unneeded uses of dlpar work
    queue (bsc#1102495, bsc#1109337).

  - powerpc/tm: Avoid possible userspace r1 corruption on
    reclaim (bsc#1109333).

  - powerpc/tm: Fix userspace r13 corruption (bsc#1109333).

  - powerpc/topology: Get topology for shared processors at
    boot (bsc#1104683).

  - powerpc/xive: Fix trying to 'push' an already active
    pool VP (bsc#1085030, git-fixes).

  - power: remove possible deadlock when unregistering
    power_supply (bsc#1051510).

  - power: supply: axp288_charger: Fix initial
    constant_charge_current value (bsc#1051510).

  - power: supply: max77693_charger: fix unintentional
    fall-through (bsc#1051510).

  - power: vexpress: fix corruption in notifier registration
    (bsc#1051510).

  - ppp: Destroy the mutex when cleanup (bsc#1051510).

  - ppp: fix __percpu annotation (bsc#1051510).

  - pstore: Fix incorrect persistent ram buffer mapping
    (bsc#1051510).

  - ptp: fix missing break in switch (bsc#1105355).

  - ptr_ring: fail early if queue occupies more than
    KMALLOC_MAX_SIZE (bsc#1105355).

  - ptr_ring: fix up after recent ptr_ring changes
    (bsc#1105355).

  - ptr_ring: prevent integer overflow when calculating size
    (bsc#1105355).

  - pwm: tiehrpwm: Fix disabling of output of PWMs
    (bsc#1051510).

  - qlge: Fix netdev features configuration (bsc#1098822).

  - r8152: Check for supported Wake-on-LAN Modes
    (bsc#1051510).

  - r8169: add support for NCube 8168 network card
    (bsc#1051510).

  - random: add new ioctl RNDRESEEDCRNG (bsc#1051510).

  - random: fix possible sleeping allocation from irq
    context (bsc#1051510).

  - random: mix rdrand with entropy sent in from userspace
    (bsc#1051510).

  - random: set up the NUMA crng instances after the CRNG is
    fully initialized (bsc#1051510).

  - RDMA/bnxt_re: Fix a bunch of off by one bugs in
    qplib_fp.c (bsc#1050244).

  - RDMA/bnxt_re: Fix a couple off by one bugs (bsc#1050244
    ).

  - RDMA/i40w: Hold read semaphore while looking after VMA
    (bsc#1058659).

  - RDMA/uverbs: Expand primary and alt AV port checks
    (bsc#1046306 ).

  - readahead: stricter check for bdi io_pages (VM
    Functionality, git fixes).

  - regulator: fix crash caused by null driver data
    (bsc#1051510).

  - reiserfs: fix broken xattr handling (heap corruption,
    bad retval) (bsc#1106236).

  - Replace magic for trusting the secondary keyring with
    #define (bsc#1051510).

  - Revert 'btrfs: qgroups: Retry after commit on getting
    EDQUOT' (bsc#1031392).

  - Revert 'ipc/shm: Fix shmat mmap nil-page protection'
    (bsc#1090078).

  - Revert 'mm: page_alloc: skip over regions of invalid
    pfns where possible' (bnc#1107078).

  - Revert 'pci: Add ACS quirk for Intel 300 series'
    (bsc#1051510).

  - Revert 'UBIFS: Fix potential integer overflow in
    allocation' (bsc#1051510).

  - Revert 'vhost: cache used event for better performance'
    (bsc#1090528).

  - Revert 'vmalloc: back off when the current task is
    killed' (bnc#1107073).

  - rhashtable: add schedule points (bsc#1051510).

  - rndis_wlan: potential buffer overflow in
    rndis_wlan_auth_indication() (bsc#1051510).

  - root dentries need RCU-delayed freeing (bsc#1106297).

  - rsi: Fix 'invalid vdd' warning in mmc (bsc#1051510).

  - rtc: ensure rtc_set_alarm fails when alarms are not
    supported (bsc#1051510).

  - rtnetlink: add rtnl_link_state check in
    rtnl_configure_link (netfilter-stable-18_07_27).

  - rxrpc: Fix user call ID check in
    rxrpc_service_prealloc_one (netfilter-stable-18_08_04).

  - s390: always save and restore all registers on context
    switch (bsc#1103421).

  - s390/crypto: Fix return code checking in
    cbc_paes_crypt() (bnc#1108323, LTC#171709).

  - s390: detect etoken facility (bsc#1103421).

  - s390/entry.S: use assembler alternatives (bsc#1103421).

  - s390: fix br_r1_trampoline for machines without exrl
    (git-fixes, bsc#1103421).

  - s390: fix compat system call table (bsc#1103421).

  - s390: fix handling of -1 in set{,fs}id16 syscalls
    (bsc#1103421).

  - s390/lib: use expoline for all bcr instructions
    (git-fixes, bsc#1103421).

  - s390/mm: fix local TLB flushing vs. detach of an mm
    address space (bsc#1103421).

  - s390/mm: fix race on mm->context.flush_mm (bsc#1103421).

  - s390/pci: fix out of bounds access during irq setup
    (bnc#1108323, LTC#171068).

  - s390: Prevent hotplug rwsem recursion (bsc#1105731).

  - s390/qdio: reset old sbal_state flags (LTC#171525,
    bsc#1106948).

  - s390/qeth: consistently re-enable device features
    (bsc#1104482, LTC#170340).

  - s390/qeth: do not clobber buffer on async TX completion
    (bsc#1104482, LTC#170340).

  - s390/qeth: rely on kernel for feature recovery
    (bsc#1104482, LTC#170340).

  - s390/qeth: use vzalloc for QUERY OAT buffer (LTC#171527,
    bsc#1106948).

  - s390/runtime instrumentation: simplify task exit
    handling (bsc#1103421).

  - s390: use expoline thunks for all branches generated by
    the BPF JIT (bsc#1103421).

  - samples/bpf: adjust rlimit RLIMIT_MEMLOCK for xdp1
    (bsc#1083647).

  - sched/debug: Reverse the order of printing faults
    (bnc#1101669 optimise numa balancing for fast migrate).

  - sched/fair: Fix bandwidth timer clock drift condition
    (Git-fixes).

  - sched/fair: Fix vruntime_normalized() for remote
    non-migration wakeup (git-fixes).

  - sched/numa: Avoid task migration for small NUMA
    improvement (bnc#1101669 optimise numa balancing for
    fast migrate).

  - sched/numa: Do not move imbalanced load purely on the
    basis of an idle CPU (bnc#1101669 optimise numa
    balancing for fast migrate).

  - sched/numa: Evaluate move once per node (bnc#1101669
    optimise numa balancing for fast migrate).

  - sched/numa: Evaluate move once per node (bnc#1101669
    optimise numa balancing for fast migrate).

  - sched/numa: Modify migrate_swap() to accept additional
    parameters (bnc#1101669 optimise numa balancing for fast
    migrate).

  - sched/numa: Move task_numa_placement() closer to
    numa_migrate_preferred() (bnc#1101669 optimise numa
    balancing for fast migrate).

  - sched/numa: Pass destination CPU as a parameter to
    migrate_task_rq (bnc#1101669 optimise numa balancing for
    fast migrate).

  - sched/numa: Pass destination CPU as a parameter to
    migrate_task_rq kabi (bnc#1101669 optimise numa
    balancing for fast migrate).

  - sched/numa: Remove numa_has_capacity() (bnc#1101669
    optimise numa balancing for fast migrate).

  - sched/numa: Remove redundant field (bnc#1101669 optimise
    numa balancing for fast migrate).

  - sched/numa: Remove redundant field -kabi (bnc#1101669
    optimise numa balancing for fast migrate).

  - sched/numa: remove unused code from update_numa_stats()
    (bnc#1101669 optimise numa balancing for fast migrate).

  - sched/numa: remove unused nr_running field (bnc#1101669
    optimise numa balancing for fast migrate).

  - sched/numa: Remove unused task_capacity from 'struct
    numa_stats' (bnc#1101669 optimise numa balancing for
    fast migrate).

  - sched/numa: Remove unused task_capacity from 'struct
    numa_stats' (bnc#1101669 optimise numa balancing for
    fast migrate).

  - sched/numa: Reset scan rate whenever task moves across
    nodes (bnc#1101669 optimise numa balancing for fast
    migrate).

  - sched/numa: Set preferred_node based on best_cpu
    (bnc#1101669 optimise numa balancing for fast migrate).

  - sched/numa: Simplify load_too_imbalanced() (bnc#1101669
    optimise numa balancing for fast migrate).

  - sched/numa: Skip nodes that are at 'hoplimit'
    (bnc#1101669 optimise numa balancing for fast migrate).

  - sched/numa: Stop comparing tasks for NUMA placement
    after selecting an idle core (bnc#1101669 optimise numa
    balancing for fast migrate).

  - sched/numa: Stop multiple tasks from moving to the CPU
    at the same time (bnc#1101669 optimise numa balancing
    for fast migrate).

  - sched/numa: Stop multiple tasks from moving to the CPU
    at the same time kabi (bnc#1101669 optimise numa
    balancing for fast migrate).

  - sched/numa: Update the scan period without holding the
    numa_group lock (bnc#1101669 optimise numa balancing for
    fast migrate).

  - sched/numa: Use group_weights to identify if migration
    degrades locality (bnc#1101669 optimise numa balancing
    for fast migrate).

  - sched/numa: Use task faults only if numa_group is not
    yet set up (bnc#1101669 optimise numa balancing for fast
    migrate).

  - scripts/git_sort/git_sort.py: Add fixes branch from
    mkp/scsi.git.

  - scripts/git_sort/git_sort.py: add libnvdimm-for-next
    branch

  - scripts/git_sort/git_sort.py: add mkp 4.20/scsi-queue

  - scripts: modpost: check memory allocation results
    (bsc#1051510).

  - scsi: cxlflash: Abstract hardware dependent assignments
    ().

  - scsi: cxlflash: Acquire semaphore before invoking ioctl
    services ().

  - scsi: cxlflash: Adapter context init can return error
    ().

  - scsi: cxlflash: Adapter context support for OCXL ().

  - scsi: cxlflash: Add argument identifier names ().

  - scsi: cxlflash: Add include guards to backend.h ().

  - scsi: cxlflash: Avoid clobbering context control
    register value ().

  - scsi: cxlflash: Enable OCXL operations ().

  - scsi: cxlflash: Explicitly cache number of interrupts
    per context ().

  - scsi: cxlflash: Handle spurious interrupts ().

  - scsi: cxlflash: Hardware AFU for OCXL ().

  - scsi: cxlflash: Introduce object handle fop ().

  - scsi: cxlflash: Introduce OCXL backend ().

  - scsi: cxlflash: Introduce OCXL context state machine ().

  - scsi: cxlflash: Isolate external module dependencies ().

  - scsi: cxlflash: Limit the debug logs in the IO path ().

  - scsi: cxlflash: MMIO map the AFU ().

  - scsi: cxlflash: Preserve number of interrupts for master
    contexts ().

  - scsi: cxlflash: Read host AFU configuration ().

  - scsi: cxlflash: Read host function configuration ().

  - scsi: cxlflash: Register for translation errors ().

  - scsi: cxlflash: Remove commmands from pending list on
    timeout ().

  - scsi: cxlflash: Remove embedded CXL work structures ().

  - scsi: cxlflash: Setup AFU acTag range ().

  - scsi: cxlflash: Setup AFU PASID ().

  - scsi: cxlflash: Setup function acTag range ().

  - scsi: cxlflash: Setup function OCXL link ().

  - scsi: cxlflash: Setup LISNs for master contexts ().

  - scsi: cxlflash: Setup LISNs for user contexts ().

  - scsi: cxlflash: Setup OCXL transaction layer ().

  - scsi: cxlflash: Staging to support future accelerators
    ().

  - scsi: cxlflash: Support adapter context discovery ().

  - scsi: cxlflash: Support adapter context mmap and release
    ().

  - scsi: cxlflash: Support adapter context polling ().

  - scsi: cxlflash: Support adapter context reading ().

  - scsi: cxlflash: Support adapter file descriptors for
    OCXL ().

  - scsi: cxlflash: Support AFU interrupt management ().

  - scsi: cxlflash: Support AFU interrupt mapping and
    registration ().

  - scsi: cxlflash: Support AFU reset ().

  - scsi: cxlflash: Support AFU state toggling ().

  - scsi: cxlflash: Support file descriptor mapping ().

  - scsi: cxlflash: Support image reload policy modification
    ().

  - scsi: cxlflash: Support process element lifecycle ().

  - scsi: cxlflash: Support process specific mappings ().

  - scsi: cxlflash: Support reading adapter VPD data ().

  - scsi: cxlflash: Support starting an adapter context ().

  - scsi: cxlflash: Support starting user contexts ().

  - scsi: cxlflash: Synchronize reset and remove ops ().

  - scsi: cxlflash: Use IDR to manage adapter contexts ().

  - scsi: cxlflash: Use local mutex for AFU serialization
    ().

  - scsi: cxlflash: Yield to active send threads ().

  - scsi_debug: call resp_XXX function after setting
    host_scribble (bsc#1069138). 

  - scsi_debug: reset injection flags for every_nth > 0
    (bsc#1069138).

  - scsi: fcoe: hold disc_mutex when traversing rport lists
    (bsc#1077989).

  - scsi: hisi_sas: Add a flag to filter PHY events during
    reset ().

  - scsi: hisi_sas: add memory barrier in task delivery
    function ().

  - scsi: hisi_sas: Add missing PHY spinlock init ().

  - scsi: hisi_sas: Add SATA FIS check for v3 hw ().

  - scsi: hisi_sas: Adjust task reject period during host
    reset ().

  - scsi: hisi_sas: Drop hisi_sas_slot_abort() ().

  - scsi: hisi_sas: Fix the conflict between dev gone and
    host reset ().

  - scsi: hisi_sas: Fix the failure of recovering PHY from
    STP link timeout ().

  - scsi: hisi_sas: Implement handlers of PCIe FLR for v3 hw
    ().

  - scsi: hisi_sas: Only process broadcast change in
    phy_bcast_v3_hw() ().

  - scsi: hisi_sas: Pre-allocate slot DMA buffers ().

  - scsi: hisi_sas: Release all remaining resources in clear
    nexus ha ().

  - scsi: hisi_sas: relocate some common code for v3 hw ().

  - scsi: hisi_sas: tidy channel interrupt handler for v3 hw
    ().

  - scsi: hisi_sas: Tidy hisi_sas_task_prep() ().

  - scsi: hisi_sas: tidy host controller reset function a
    bit ().

  - scsi: hisi_sas: Update a couple of register settings for
    v3 hw ().

  - scsi: hisi_sas: Use dmam_alloc_coherent() ().

  - scsi: hpsa: limit transfer length to 1MB, not 512kB
    (bsc#1102346).

  - scsi: ipr: System hung while dlpar adding primary ipr
    adapter back (bsc#1109336).

  - scsi: libfc: Add lockdep annotations (bsc#1077989).

  - scsi: libfc: fixup lockdep annotations (bsc#1077989).

  - scsi: libfc: fixup 'sleeping function called from
    invalid context' (bsc#1077989).

  - scsi: libfc: hold disc_mutex in fc_disc_stop_rports()
    (bsc#1077989).

  - scsi: lpfc: Correct MDS diag and nvmet configuration
    (bsc#1106636).

  - scsi: mpt3sas: Fix calltrace observed while running IO &
    reset (bsc#1077989).

  - scsi: qla2xxx: Add appropriate debug info for invalid
    RX_ID (bsc#1108870).

  - scsi: qla2xxx: Add logic to detect ABTS hang and
    response completion (bsc#1108870).

  - scsi: qla2xxx: Add longer window for chip reset
    (bsc#1086327,).

  - scsi: qla2xxx: Add mode control for each physical port
    (bsc#1108870).

  - scsi: qla2xxx: Add support for ZIO6 interrupt threshold
    (bsc#1108870).

  - scsi: qla2xxx: Allow FC-NVMe underrun to be handled by
    transport (bsc#1108870).

  - scsi: qla2xxx: Check for Register disconnect
    (bsc#1108870).

  - scsi: qla2xxx: Cleanup for N2N code (bsc#1086327,).

  - scsi: qla2xxx: Decrement login retry count for only
    plogi (bsc#1108870).

  - scsi: qla2xxx: Defer chip reset until target mode is
    enabled (bsc#1108870).

  - scsi: qla2xxx: Fix deadlock between ATIO and HW lock
    (bsc#1108870).

  - scsi: qla2xxx: Fix double increment of switch scan retry
    count (bsc#1108870).

  - scsi: qla2xxx: Fix dropped srb resource (bsc#1108870).

  - scsi: qla2xxx: Fix duplicate switch's Nport ID entries
    (bsc#1108870).

  - scsi: qla2xxx: Fix early srb free on abort
    (bsc#1108870).

  - scsi: qla2xxx: Fix iIDMA error (bsc#1108870).

  - scsi: qla2xxx: Fix incorrect port speed being set for FC
    adapters (bsc#1108870).

  - scsi: qla2xxx: Fix ISP recovery on unload
    (bsc#1086327,).

  - scsi: qla2xxx: Fix issue reported by static checker for
    qla2x00_els_dcmd2_sp_done() (bsc#1086327,).

  - scsi: qla2xxx: Fix login retry count (bsc#1086327,).

  - scsi: qla2xxx: Fix Management Server NPort handle
    reservation logic (bsc#1086327,).

  - scsi: qla2xxx: Fix N2N link re-connect (bsc#1086327,).

  - scsi: qla2xxx: Fix out of order Termination and ABTS
    response (bsc#1108870).

  - scsi: qla2xxx: Fix port speed display on chip reset
    (bsc#1108870).

  - scsi: qla2xxx: Fix premature command free (bsc#1108870).

  - scsi: qla2xxx: Fix process response queue for ISP26XX
    and above (bsc#1108870).

  - scsi: qla2xxx: Fix race between switch cmd completion
    and timeout (bsc#1086327,).

  - scsi: qla2xxx: Fix race condition for resource cleanup
    (bsc#1108870).

  - scsi: qla2xxx: Fix redundant fc_rport registration
    (bsc#1086327,).

  - scsi: qla2xxx: Fix Remote port registration
    (bsc#1108870).

  - scsi: qla2xxx: Fix session state stuck in Get Port DB
    (bsc#1086327,).

  - scsi: qla2xxx: Fix stalled relogin (bsc#1086327,).

  - scsi: qla2xxx: Fix stuck session in PLOGI state
    (bsc#1108870).

  - scsi: qla2xxx: Fix unintended Logout (bsc#1086327,).

  - scsi: qla2xxx: Flush mailbox commands on chip reset
    (bsc#1086327,).

  - scsi: qla2xxx: Force fw cleanup on ADISC error
    (bsc#1108870).

  - scsi: qla2xxx: Increase abort timeout value
    (bsc#1108870).

  - scsi: qla2xxx: Migrate NVME N2N handling into state
    machine (bsc#1086327,).

  - scsi: qla2xxx: Move ABTS code behind qpair
    (bsc#1108870).

  - scsi: qla2xxx: Move {get|rel}_sp to base_qpair struct
    (bsc#1108870).

  - scsi: qla2xxx: Move rport registration out of internal
    work_list (bsc#1108870).

  - scsi: qla2xxx: Prevent sysfs access when chip is down
    (bsc#1086327,).

  - scsi: qla2xxx: Reduce holding sess_lock to prevent CPU
    lock-up (bsc#1108870).

  - scsi: qla2xxx: Reject bsg request if chip is down
    (bsc#1108870).

  - scsi: qla2xxx: Remove all rports if fabric scan retry
    fails (bsc#1108870).

  - scsi: qla2xxx: Remove ASYNC GIDPN switch command
    (bsc#1108870).

  - scsi: qla2xxx: Remove redundant check for fcport
    deletion (bsc#1108870).

  - scsi: qla2xxx: Remove stale ADISC_DONE event
    (bsc#1108870).

  - scsi: qla2xxx: Remove stale debug trace message from
    tcm_qla2xxx (bsc#1108870).

  - scsi: qla2xxx: Save frame payload size from ICB
    (bsc#1086327,).

  - scsi: qla2xxx: Serialize mailbox request (bsc#1108870).

  - scsi: qla2xxx: shutdown chip if reset fail
    (bsc#1108870).

  - scsi: qla2xxx: Silent erroneous message (bsc#1086327,).

  - scsi: qla2xxx: Spinlock recursion in qla_target
    (bsc#1086327,).

  - scsi: qla2xxx: Terminate Plogi/PRLI if WWN is 0
    (bsc#1108870).

  - scsi: qla2xxx: Turn off IOCB timeout timer on IOCB
    completion (bsc#1108870).

  - scsi: qla2xxx: Update driver to version 10.00.00.09-k
    (bsc#1108870).

  - scsi: qla2xxx: Update driver version to 10.00.00.08-k
    (bsc#1086327,).

  - scsi: qla2xxx: Update driver version to 10.00.00.10-k
    (bsc#1108870).

  - scsi: qla2xxx: Update driver version to 10.00.00.11-k
    (bsc#1108870).

  - scsi: qla2xxx: Update rscn_rcvd field to more meaningful
    scan_needed (bsc#1108870).

  - scsi: qla2xxx: Use correct qpair for ABTS/CMD
    (bsc#1108870).

  - security: check for kstrdup() failure in lsm_append()
    (bsc#1051510).

  - selftests/bpf: fix a typo in map in map test
    (bsc#1083647).

  - selftests/bpf/test_maps: exit child process without
    error in ENOMEM case (bsc#1083647).

  - serial: 8250: Do not service RX FIFO if interrupts are
    disabled (bsc#1051510).

  - serial: 8250_dw: Add ACPI support for uart on Broadcom
    SoC (bsc#1051510).

  - serial: 8250_dw: always set baud rate in
    dw8250_set_termios (bsc#1051510).

  - serial: core: mark port as initialized after successful
    IRQ change (bsc#1051510).

  - serial: enable spi in sc16is7xx driver References:
    bsc#1105672

  - serial: make sc16is7xx driver supported References:
    bsc#1105672

  - serial: pxa: Fix an error handling path in
    'serial_pxa_probe()' (bsc#1051510).

  - serial: sh-sci: Stop RX FIFO timer during port shutdown
    (bsc#1051510).

  - serial: xuartps: fix typo in cdns_uart_startup
    (bsc#1051510).

  - series.conf: Sort automatic NUMA balancing related patch

  - slab: __GFP_ZERO is incompatible with a constructor
    (bnc#1107060).

  - smsc75xx: Check for Wake-on-LAN modes (bsc#1051510).

  - smsc95xx: Check for Wake-on-LAN modes (bsc#1051510).

  - spi: cadence: Change usleep_range() to udelay(), for
    atomic context (bsc#1051510).

  - spi: davinci: fix a NULL pointer dereference
    (bsc#1051510).

  - spi-nor: intel-spi: Fix number of protected range
    registers for BYT/LPT ().

  - spi: pxa2xx: Add support for Intel Ice Lake
    (bsc#1051510).

  - spi: spi-fsl-dspi: Fix imprecise abort on VF500 during
    probe (bsc#1051510).

  - sr9800: Check for supported Wake-on-LAN modes
    (bsc#1051510).

  - sr: get/drop reference to device in revalidate and
    check_events (bsc#1109979).

  - staging: bcm2835-audio: Check if workqueue allocation
    failed ().

  - staging: bcm2835-audio: constify snd_pcm_ops structures
    ().

  - staging: bcm2835-audio: Deliver indirect-PCM transfer
    error ().

  - staging: bcm2835-audio: Disconnect and free
    vchi_instance on module_exit() ().

  - staging: bcm2835-audio: Do not leak workqueue if open
    fails ().

  - staging: bcm2835-audio: make snd_pcm_hardware const ().

  - staging: bcm2835-camera: fix timeout handling in
    wait_for_completion_timeout (bsc#1051510).

  - staging: bcm2835-camera: handle
    wait_for_completion_timeout return properly
    (bsc#1051510).

  - staging: comedi: ni_mio_common: fix subdevice flags for
    PFI subdevice (bsc#1051510).

  - staging: lustre: disable preempt while sampling
    processor id (bsc#1051510).

  - staging: lustre: fix bug in osc_enter_cache_try
    (bsc#1051510).

  - staging: lustre: ldlm: free resource when
    ldlm_lock_create() fails (bsc#1051510).

  - staging: lustre: libcfs: fix test for libcfs_ioctl_hdr
    minimum size (bsc#1051510).

  - staging: lustre: libcfs: Prevent harmless read underflow
    (bsc#1051510).

  - staging: lustre: llite: correct removexattr detection
    (bsc#1051510).

  - staging: lustre: llite: initialize xattr->xe_namelen
    (bsc#1051510).

  - staging: lustre: lmv: correctly iput lmo_root
    (bsc#1051510).

  - staging: lustre: lov: use correct env in
    lov_io_data_version_end() (bsc#1051510).

  - staging: lustre: o2iblnd: Fix crash in
    kiblnd_handle_early_rxs() (bsc#1051510).

  - staging: lustre: o2iblnd: Fix FastReg map/unmap for MLX5
    (bsc#1051510).

  - staging: lustre: o2iblnd: fix race at
    kiblnd_connect_peer (bsc#1051510).

  - staging: lustre: obdclass: return -EFAULT if
    copy_from_user() fails (bsc#1051510).

  - staging: lustre: obd_mount: use correct niduuid suffix
    (bsc#1051510).

  - staging: lustre: ptlrpc: kfree used instead of kvfree
    (bsc#1051510).

  - staging: lustre: remove invariant in cl_io_read_ahead()
    (bsc#1051510).

  - staging: lustre: statahead: remove incorrect test on
    agl_list_empty() (bsc#1051510).

  - staging: lustre: Use 'kvfree()' for memory allocated by
    'kvzalloc()' (bsc#1051510).

  - staging: rts5208: fix missing error check on call to
    rtsx_write_register (bsc#1051510).

  - staging: vc04_services: bcm2835-audio: Add blank line
    after declaration ().

  - staging: vc04_services: bcm2835-audio: add SPDX
    identifiers ().

  - staging: vc04_services: bcm2835-audio: Change to
    unsigned int * ().

  - staging: vc04_services: bcm2835-audio Format multiline
    comment ().

  - staging: vc04_services: bcm2835-audio: remove redundant
    license text ().

  - staging: vc04_services: Fix platform_no_drv_owner.cocci
    warnings ().

  - staging: vc04_services: please do not use multiple blank
    lines ().

  - stmmac: fix DMA channel hang in half-duplex mode
    (networking-stable-18_07_19).

  - string: drop __must_check from strscpy() and restore
    strscpy() usages in cgroup (bsc#1051510).

  - strparser: Remove early eaten to fix full tcp receive
    buffer stall (networking-stable-18_07_19).

  - sunxi-rsb: Include OF based modalias in device uevent
    (bsc#1051510).

  - sys: do not hold uts_sem while accessing userspace
    memory (bnc#1106995).

  - target_core_rbd: break up free_device callback
    (bsc#1105524).

  - target_core_rbd: use RCU in free_device (bsc#1105524).

  - tcp: add max_quickacks param to tcp_incr_quickack and
    tcp_enter_quickack_mode (netfilter-stable-18_08_01).

  - tcp: add one more quick ack after after ECN events
    (netfilter-stable-18_08_01).

  - tcp_bbr: fix bw probing to raise in-flight data for very
    small BDPs (netfilter-stable-18_08_01).

  - tcp: do not aggressively quick ack after ECN events
    (netfilter-stable-18_08_01).

  - tcp: do not cancel delay-AcK on DCTCP special ACK
    (netfilter-stable-18_07_27).

  - tcp: do not delay ACK in DCTCP upon CE status change
    (netfilter-stable-18_07_27).

  - tcp: do not force quickack when receiving out-of-order
    packets (netfilter-stable-18_08_01).

  - tcp: fix dctcp delayed ACK schedule
    (netfilter-stable-18_07_27).

  - tcp: fix Fast Open key endianness
    (networking-stable-18_07_19).

  - tcp: helpers to send special DCTCP ack
    (netfilter-stable-18_07_27).

  - tcp: prevent bogus FRTO undos with non-SACK flows
    (networking-stable-18_07_19).

  - tcp: refactor tcp_ecn_check_ce to remove sk type cast
    (netfilter-stable-18_08_01).

  - tg3: Add higher cpu clock for 5762
    (netfilter-stable-18_07_23).

  - thermal_hwmon: Pass the originating device down to
    hwmon_device_register_with_info (bsc#1103363).

  - thermal_hwmon: Sanitize attribute name passed to hwmon
    (bsc#1103363).

  - thermal: thermal_hwmon: Convert to
    hwmon_device_register_with_info() (bsc#1103363).

  - ti: ethernet: cpdma: Use correct format for genpool_*
    (bsc#1051510).

  - tools/power turbostat: fix -S on UP systems
    (bsc#1051510).

  - tools/power turbostat: Read extended processor family
    from CPUID (bsc#1051510).

  - tools: usb: ffs-test: Fix build on big endian systems
    (bsc#1051510).

  - tpm: cmd_ready command can be issued only after granting
    locality (bsc#1082555).

  - tpm: fix race condition in tpm_common_write()
    (bsc#1082555).

  - tpm: fix use after free in tpm2_load_context()
    (bsc#1082555).

  - tpm: Introduce flag TPM_TRANSMIT_RAW (bsc#1082555).

  - tpm: separate cmd_ready/go_idle from runtime_pm
    (bsc#1082555).

  - tpm: tpm_crb: relinquish locality on error path
    (bsc#1082555).

  - tpm: vtpm_proxy: Implement request_locality function
    (bsc#1082555).

  - tracepoint: Do not warn on ENOMEM (bsc#1051510).

  - tty: fix termios input-speed encoding (bsc#1051510).

  - tty: fix termios input-speed encoding when using BOTHER
    (bsc#1051510).

  - tty: serial: 8250: Revert NXP SC16C2552 workaround
    (bsc#1051510).

  - uart: fix race between uart_put_char() and
    uart_shutdown() (bsc#1051510).

  - ubifs: Check data node size before truncate
    (bsc#1051510).

  - ubifs: Fix directory size calculation for symlinks
    (bsc#1106230).

  - ubifs: Fix memory leak in lprobs self-check
    (bsc#1051510).

  - ubifs: Fix synced_i_size calculation for xattr inodes
    (bsc#1051510).

  - ubifs: xattr: Do not operate on deleted inodes
    (bsc#1051510).

  - udlfb: set optimal write delay (bsc#1051510).

  - udl-kms: avoid division (bsc#1051510).

  - udl-kms: change down_interruptible to down
    (bsc#1051510).

  - udl-kms: fix crash due to uninitialized memory
    (bsc#1051510).

  - udl-kms: handle allocation failure (bsc#1051510).

  - uio, lib: Fix CONFIG_ARCH_HAS_UACCESS_MCSAFE compilation
    (bsc#1098782).

  - uio: potential double frees if __uio_register_device()
    fails (bsc#1051510).

  - Update config files, make CRYPTO_CRCT10DIF_PCLMUL
    built-in (bsc#1105603).

  - Update
    patches.drivers/0016-arm64-vgic-v2-Fix-proxying-of-cpuif
    -access.patch (bsc#1106901, bsc#1107265).

  - Update
    patches.fixes/4.4.139-043-powerpc-mm-hash-Add-missing-is
    ync-prior-to-ke.patch (bnc#1012382, bsc#1094244).

  - Update patch tag of dmi fix (bsc#1105597) Also moved to
    the sorted section.

  - Update patch tags of recent security fixes (bsc#1106426)

  - uprobes: Use synchronize_rcu() not synchronize_sched()
    (bsc#1051510).

  - uprobes/x86: Remove incorrect WARN_ON() in
    uprobe_init_insn() (bsc#1051510).

  - usb: cdc-wdm: do not enable interrupts in USB-giveback
    (bsc#1051510).

  - usb: Do not die twice if PCI xhci host is not responding
    in resume (bsc#1051510).

  - usb: dwc2: fix isoc split in transfer with no data
    (bsc#1051510).

  - usb: dwc2: gadget: Fix issue in dwc2_gadget_start_isoc()
    (bsc#1051510).

  - usb: dwc3: change stream event enable bit back to 13
    (bsc#1051510).

  - usb: dwc3: pci: add support for Intel IceLake
    (bsc#1051510).

  - usb: gadget: composite: fix delayed_status race
    condition when set_interface (bsc#1051510).

  - usb: gadget: dwc2: fix memory leak in gadget_init()
    (bsc#1051510).

  - usb: gadget: r8a66597: Fix a possible
    sleep-in-atomic-context bugs in r8a66597_queue()
    (bsc#1051510).

  - usb: gadget: r8a66597: Fix two possible
    sleep-in-atomic-context bugs in init_controller()
    (bsc#1051510).

  - usb: gadget: udc: renesas_usb3: fix maxpacket size of
    ep0 (bsc#1051510).

  - usb: net2280: Fix erroneous synchronization change
    (bsc#1051510).

  - usb: option: add support for DW5821e (bsc#1051510).

  - usb/phy: fix PPC64 build errors in phy-fsl-usb.c
    (bsc#1051510).

  - usb: serial: io_ti: fix array underflow in completion
    handler (bsc#1051510).

  - usb: serial: kobil_sct: fix modem-status error handling
    (bsc#1051510).

  - usb: serial: pl2303: add a new device id for ATEN
    (bsc#1051510).

  - usb: serial: sierra: fix potential deadlock at close
    (bsc#1051510).

  - usb: serial: ti_usb_3410_5052: fix array underflow in
    completion handler (bsc#1051510).

  - usb: xhci: increase CRS timeout value (bsc#1051510).

  - userns: move user access out of the mutex (bsc#1051510).

  - vfio/pci: Virtualize Maximum Payload Size (bsc#1051510).

  - vfio/pci: Virtualize Maximum Read Request Size
    (bsc#1051510).

  - vfio/type1: Fix task tracking for QEMU vCPU hotplug
    (bsc#1051510).

  - vfs: do not test owner for NFS in set_posix_acl()
    (bsc#1103405).

  - vhost: correctly check the iova range when waking
    virtqueue (bsc#1051510).

  - vhost: do not try to access device IOTLB when not
    initialized (bsc#1051510).

  - vhost_net: validate sock before trying to put its fd
    (networking-stable-18_07_19).

  - vhost: reset metadata cache when initializing new IOTLB
    (netfilter-stable-18_08_17).

  - vhost: use mutex_lock_nested() in vhost_dev_lock_vqs()
    (bsc#1051510).

  - video: fbdev: pxafb: clear allocated memory for video
    modes (bsc#1051510).

  - video: goldfishfb: fix memory leak on driver remove
    (bsc#1051510).

  - vmci: type promotion bug in qp_host_get_user_memory()
    (bsc#1105355).

  - vmw_balloon: do not use 2MB without batching
    (bsc#1051510).

  - vmw_balloon: fix inflation of 64-bit GFNs (bsc#1051510).

  - vmw_balloon: fix VMCI use when balloon built into kernel
    (bsc#1051510).

  - vmw_balloon: remove inflation rate limiting
    (bsc#1051510).

  - vmw_balloon: VMCI_DOORBELL_SET does not check status
    (bsc#1051510).

  - VSOCK: fix loopback on big-endian systems
    (networking-stable-18_07_19).

  - vsock: split dwork to avoid reinitializations
    (netfilter-stable-18_08_17).

  - vxlan: add new fdb alloc and create helpers
    (netfilter-stable-18_07_27).

  - vxlan: fix default fdb entry netlink notify ordering
    during netdev create (netfilter-stable-18_07_27).

  - vxlan: make netlink notify in vxlan_fdb_destroy optional
    (netfilter-stable-18_07_27).

  - wan/fsl_ucc_hdlc: use IS_ERR_VALUE() to check return
    value of qe_muram_alloc (bsc#1051510).

  - watchdog: Mark watchdog touch functions as notrace
    (git-fixes).

  - wlcore: Add missing PM call for
    wlcore_cmd_wait_for_event_or_timeout() (bsc#1051510).

  - wlcore: Set rx_status boottime_ns field on rx
    (bsc#1051510).

  - Workaround kABI breakage by __must_check drop of
    strscpy() (bsc#1051510).

  - x86/apic: Fix restoring boot IRQ mode in reboot and
    kexec/kdump (bsc#1110006).

  - x86/apic: Split disable_IO_APIC() into two functions to
    fix CONFIG_KEXEC_JUMP=y (bsc#1110006).

  - x86/apic: Split out restore_boot_irq_mode() from
    disable_IO_APIC() (bsc#1110006).

  - x86/apic/vector: Fix off by one in error path
    (bsc#1110006).

  - x86/asm/memcpy_mcsafe: Add labels for __memcpy_mcsafe()
    write fault handling (bsc#1098782).

  - x86/asm/memcpy_mcsafe: Add write-protection-fault
    handling (bsc#1098782).

  - x86/asm/memcpy_mcsafe: Define copy_to_iter_mcsafe()
    (bsc#1098782).

  - x86/asm/memcpy_mcsafe: Fix copy_to_user_mcsafe()
    exception handling (bsc#1098782).

  - x86/asm/memcpy_mcsafe: Provide original
    memcpy_mcsafe_unrolled (bsc#1098782).

  - x86/asm/memcpy_mcsafe: Remove loop unrolling
    (bsc#1098782).

  - x86/asm/memcpy_mcsafe: Return bytes remaining
    (bsc#1098782).

  - x86/boot: Fix kexec booting failure in the SEV bit
    detection code (bsc#1110301).

  - x86/build/64: Force the linker to use 2MB page size
    (bsc#1109603).

  - x86/CPU/AMD: Derive CPU topology from CPUID function 0xB
    when available ().

  - x86/CPU: Modify detect_extended_topology() to return
    result ().

  - x86/dumpstack: Save first regs set for the executive
    summary (bsc#1110006).

  - x86/dumpstack: Unify show_regs() (bsc#1110006).

  - x86/entry/64: Remove %ebx handling from error_entry/exit
    (bnc#1102715).

  - x86/entry/64: Wipe KASAN stack shadow before
    rewind_stack_do_exit() (bsc#1110006).

  - x86/espfix/64: Fix espfix double-fault handling on
    5-level systems (bsc#1110006).

  - x86/events/intel/ds: Fix bts_interrupt_threshold
    alignment (git-fixes c1961a4631da).

  - x86/idt: Load idt early in start_secondary
    (bsc#1110006).

  - x86/init: fix build with CONFIG_SWAP=n (bnc#1106121).

  - x86: irq_remapping: Move irq remapping mode enum ().

  - x86/kasan/64: Teach KASAN about the cpu_entry_area
    (kasan).

  - x86/kexec: Avoid double free_page() upon do_kexec_load()
    failure (bsc#1110006).

  - x86/kvm: fix LAPIC timer drift when guest uses periodic
    mode (bsc#1106240).

  - x86/mce: Fix set_mce_nospec() to avoid #GP fault
    (bsc#1107783).

  - x86/mce: Improve error message when kernel cannot
    recover (bsc#1110006).

  - x86/mce: Improve error message when kernel cannot
    recover (bsc#1110301).

  - x86/mcelog: Get rid of RCU remnants (git-fixes
    5de97c9f6d85).

  - x86/memory_failure: Introduce {set, clear}_mce_nospec()
    (bsc#1107783).

  -
    x86-memory_failure-Introduce-set-clear-_mce_nospec.patch
    : Fixup compilation breakage on s390 and arm due to
    missing clear_mce_nospec().

  - x86/mm: Add TLB purge to free pmd/pte page interfaces
    (bsc#1110006).

  - x86/mm: Disable ioremap free page handling on x86-PAE
    (bsc#1110006).

  - x86/mm: Drop TS_COMPAT on 64-bit exec() syscall
    (bsc#1110006).

  - x86/mm: Expand static page table for fixmap space
    (bsc#1110006).

  - x86/mm: Fix ELF_ET_DYN_BASE for 5-level paging
    (bsc#1110006).

  - x86/mm: implement free pmd/pte page interfaces
    (bsc#1110006).

  - x86/mm/kasan: Do not use vmemmap_populate() to
    initialize shadow (kasan).

  - x86/mm/memory_hotplug: determine block size based on the
    end of boot memory (bsc#1108243).

  - x86/mm/pat: Prepare {reserve, free}_memtype() for
    'decoy' addresses (bsc#1107783).

  - x86/mm/tlb: Always use lazy TLB mode (bnc#1105467 Reduce
    IPIs and atomic ops with improved lazy TLB).

  - x86/mm/tlb: Leave lazy TLB mode at page table free time
    (bnc#1105467 Reduce IPIs and atomic ops with improved
    lazy TLB).

  - x86/mm/tlb: Make lazy TLB mode lazier (bnc#1105467
    Reduce IPIs and atomic ops with improved lazy TLB).

  - x86/mm/tlb: Only send page table free TLB flush to lazy
    TLB CPUs (bnc#1105467 Reduce IPIs and atomic ops with
    improved lazy TLB).

  - x86/mm/tlb: Restructure switch_mm_irqs_off()
    (bnc#1105467 Reduce IPIs and atomic ops with improved
    lazy TLB).

  - x86/mm/tlb: Skip atomic operations for 'init_mm' in
    switch_mm_irqs_off() (bnc#1105467 Reduce IPIs and atomic
    ops with improved lazy TLB).

  - x86/mpx: Do not allow MPX if we have mappings above
    47-bit (bsc#1110006).

  - x86: msr-index.h: Correct SNB_C1/C3_AUTO_UNDEMOTE
    defines (bsc#1110006).

  - x86: msr-index.h: Correct SNB_C1/C3_AUTO_UNDEMOTE
    defines (bsc#1110301).

  - x86/paravirt: Fix spectre-v2 mitigations for paravirt
    guests (bnc#1065600).

  - x86/pci: Make broadcom_postcore_init() check
    acpi_disabled (bsc#1110006).

  - x86/pkeys: Do not special case protection key 0
    (bsc#1110006).

  - x86/pkeys: Override pkey when moving away from PROT_EXEC
    (bsc#1110006).

  - x86/platform/UV: Add adjustable set memory block size
    function (bsc#1108243).

  - x86/platform/UV: Add kernel parameter to set memory
    block size (bsc#1108243).

  - x86/platform/UV: Mark memblock related init code and
    data correctly (bsc#1108243).

  - x86/platform/UV: Use new set memory block size function
    (bsc#1108243).

  - x86/process: Do not mix user/kernel regs in 64bit
    __show_regs() (bsc#1110006).

  - x86/process: Re-export start_thread() (bsc#1110006).

  - x86/spectre: Add missing family 6 check to microcode
    check (git-fixes a5b296636453).

  - x86/speculation/l1tf: Fix off-by-one error when warning
    that system has too much RAM (bnc#1105536).

  - x86/speculation/l1tf: Increase l1tf memory limit for
    Nehalem+ (bnc#1105536).

  - x86/speculation/l1tf: Suggest what to do on systems with
    too much RAM (bnc#1105536).

  - x86/speculation: Use ARCH_CAPABILITIES to skip L1D flush
    on vmentry (bsc#1106369).

  - x86/vdso: Fix lsl operand order (bsc#1110006).

  - x86/vdso: Fix lsl operand order (bsc#1110301).

  - x86/vdso: Fix vDSO build if a retpoline is emitted
    (git-fixes 76b043848fd2).

  - x86/xen: Add call of speculative_store_bypass_ht_init()
    to PV paths (bnc#1065600).

  - x86/xen/efi: Initialize only the EFI struct members used
    by Xen (bnc#1107945).

  - xen: avoid crash in disable_hotplug_cpu (bsc#1106594).

  - xen/blkback: do not keep persistent grants too long
    (bsc#1085042).

  - xen/blkback: move persistent grants flags to bool
    (bsc#1085042).

  - xen/blkback: remove unused pers_gnts_lock from struct
    (bsc#1085042).

  - xen/blkfront: cleanup stale persistent grants
    (bsc#1085042).

  - xen/blkfront: reorder tests in xlblk_init()
    (bsc#1085042).

  - xenbus: track caller request id (bnc#1065600).

  - xen: issue warning message when out of grant maptrack
    entries (bsc#1105795).

  - xen-netfront-dont-bug-in-case-of-too-many-frags.patch:
    (bnc#1104824).

  - xen-netfront: fix queue name setting (bnc#1065600).

  - xen-netfront: fix warn message as irq device name has
    '/' (bnc#1065600).

  - xen: xenbus_dev_frontend: Fix XS_TRANSACTION_END
    handling (bnc#1065600).

  - xen: xenbus_dev_frontend: Really return response string
    (bnc#1065600).

  - xfs: add a new xfs_iext_lookup_extent_before helper
    (bsc#1095344).

  - xfs: add asserts for the mmap lock in
    xfs_{insert,collapse}_file_space (bsc#1095344).

  - xfs: add a xfs_bmap_fork_to_state helper (bsc#1095344).

  - xfs: add a xfs_iext_update_extent helper (bsc#1095344).

  - xfs: add comments documenting the rebalance algorithm
    (bsc#1095344).

  - xfs: add some comments to
    xfs_iext_insert/xfs_iext_insert_node (bsc#1095344).

  - xfs: allow unaligned extent records in
    xfs_bmbt_disk_set_all (bsc#1095344).

  - xfs, dax: introduce xfs_dax_aops (bsc#1104888).

  - xfs: do not create overlapping extents in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: do not rely on extent indices in
    xfs_bmap_collapse_extents (bsc#1095344).

  - xfs: do not rely on extent indices in
    xfs_bmap_insert_extents (bsc#1095344).

  - xfs: do not set XFS_BTCUR_BPRV_WASDEL in xfs_bunmapi
    (bsc#1095344).

  - xfs: fix memory leak in xfs_iext_free_last_leaf
    (bsc#1095344).

  - xfs: fix number of records handling in
    xfs_iext_split_leaf (bsc#1095344).

  - xfs: Fix per-inode DAX flag inheritance (Git-fixes
    bsc#1109511).

  - xfs: fix type usage (bsc#1095344).

  - xfs: handle zero entries case in xfs_iext_rebalance_leaf
    (bsc#1095344).

  - xfs: inline xfs_shift_file_space into callers
    (bsc#1095344).

  - xfs: introduce the xfs_iext_cursor abstraction
    (bsc#1095344).

  - xfs: iterate backwards in xfs_reflink_cancel_cow_blocks
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

  - xfs: pass an on-disk extent to xfs_bmbt_validate_extent
    (bsc#1095344).

  - xfs: pass a struct xfs_bmbt_irec to xfs_bmbt_lookup_eq
    (bsc#1095344).

  - xfs: pass a struct xfs_bmbt_irec to xfs_bmbt_update
    (bsc#1095344).

  - xfs: pass struct xfs_bmbt_irec to
    xfs_bmbt_validate_extent (bsc#1095344).

  - xfs: preserve i_rdev when recycling a reclaimable inode
    (bsc#1095344).

  - xfs: refactor delalloc accounting in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: refactor dir2 leaf readahead shadow buffer
    cleverness (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_delay_real
    (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_hole_delay
    (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_hole_real
    (bsc#1095344).

  - xfs: refactor xfs_bmap_add_extent_unwritten_real
    (bsc#1095344).

  - xfs: refactor xfs_del_extent_real (bsc#1095344).

  - xfs: remove a duplicate assignment in
    xfs_bmap_add_extent_delay_real (bsc#1095344).

  - xfs: remove all xfs_bmbt_set_* helpers except for
    xfs_bmbt_set_all (bsc#1095344).

  - xfs: remove a superflous assignment in
    xfs_iext_remove_node (bsc#1095344).

  - xfs: Remove dead code from inode recover function
    (bsc#1105396).

  - xfs: remove if_rdev (bsc#1095344).

  - xfs: remove post-bmap tracing in
    xfs_bmap_local_to_extents (bsc#1095344).

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

  - xfs: repair malformed inode items during log recovery
    (bsc#1105396).

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

  - xfs: simplify the xfs_getbmap interface (bsc#1095344).

  - xfs: simplify xfs_reflink_convert_cow (bsc#1095344).

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

  - xfs: trivial indentation fixup for xfs_iext_remove_node
    (bsc#1095344).

  - xfs: update got in xfs_bmap_shift_update_extent
    (bsc#1095344).

  - xfs: use a b+tree for the in-core extent list
    (bsc#1095344).

  - xfs: use correct state defines in
    xfs_bmap_del_extent_{cow,delay} (bsc#1095344).

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

  - xhci: Fix perceived dead host due to runtime suspend
    race with event handler (bsc#1051510).

  - xhci: Fix use after free for URB cancellation on a
    reallocated endpoint (bsc#1051510).

  - zram: fix null dereference of handle (bsc#1105355)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064232"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102517"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108093"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109269"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.19.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.19.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
