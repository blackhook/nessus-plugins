#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1698.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141559);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-24490", "CVE-2020-25212", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1698)");
  script_summary(english:"Check for the openSUSE-2020-1698 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-12351: Fixed a type confusion while processing
    AMP packets aka 'BleedingTooth' aka 'BadKarma'
    (bsc#1177724).

  - CVE-2020-24490: Fixed a heap buffer overflow when
    processing extended advertising report events aka
    'BleedingTooth' aka 'BadVibes' (bsc#1177726).

  - CVE-2020-12352: Fixed an information leak when
    processing certain AMP packets aka 'BleedingTooth' aka
    'BadChoice' (bsc#1177725).

  - CVE-2020-25212: A TOCTOU mismatch in the NFS client code
    in the Linux kernel could be used by local attackers to
    corrupt memory or possibly have unspecified other impact
    because a size check is in fs/nfs/nfs4proc.c instead of
    fs/nfs/nfs4xdr.c, aka CID-b4487b935452 (bnc#1176381).

  - CVE-2020-25645: Traffic between two Geneve endpoints may
    be unencrypted when IPsec is configured to encrypt
    traffic for the specific UDP port used by the GENEVE
    tunnel allowing anyone between the two endpoints to read
    the traffic unencrypted. The main threat from this
    vulnerability is to data confidentiality (bnc#1177511).

  - CVE-2020-25643: Memory corruption and a read overflow is
    caused by improper input validation in the
    ppp_cp_parse_cr function which can cause the system to
    crash or cause a denial of service. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system availability (bnc#1177206).

  - CVE-2020-25641: A zero-length biovec request issued by
    the block subsystem could cause the kernel to enter an
    infinite loop, causing a denial of service. This flaw
    allowed a local attacker with basic privileges to issue
    requests to a block device, resulting in a denial of
    service. The highest threat from this vulnerability is
    to system availability (bnc#1177121).

The following non-security bugs were fixed :

  - 9p: Fix memory leak in v9fs_mount (git-fixes).

  - ACPI: EC: Reference count query handlers under lock
    (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for MPMAN
    Converter9 2-in-1 (git-fixes).

  - ASoC: img-i2s-out: Fix runtime PM imbalance on error
    (git-fixes).

  - ASoC: kirkwood: fix IRQ error handling (git-fixes).

  - ASoC: wm8994: Ensure the device is resumed in
    wm89xx_mic_detect functions (git-fixes).

  - ASoC: wm8994: Skip setting of the WM8994_MICBIAS
    register for WM1811 (git-fixes).

  - Bluetooth: Fix refcount use-after-free issue
    (git-fixes).

  - Bluetooth: Handle Inquiry Cancel error after Inquiry
    Complete (git-fixes).

  - Bluetooth: L2CAP: handle l2cap config request during
    open state (git-fixes).

  - Bluetooth: guard against controllers sending zero'd
    events (git-fixes).

  - Bluetooth: prefetch channel before killing sock
    (git-fixes).

  - Btrfs: fix crash during unmount due to race with delayed
    inode workers (bsc#1176019).

  - Input: i8042 - add nopnp quirk for Acer Aspire 5 A515
    (bsc#954532).

  - Input: trackpoint - enable Synaptics trackpoints
    (git-fixes).

  - Move upstreamed intel-vbtn patch into sorted section

  - NFS: Do not move layouts to plh_return_segs list while
    in use (git-fixes).

  - NFS: Do not return layout segments that are in use
    (git-fixes).

  - NFS: Fix flexfiles read failover (git-fixes).

  - NFSv4.2: fix client's attribute cache management for
    copy_file_range (git-fixes).

  - PCI/IOV: Mark VFs as not implementing PCI_COMMAND_MEMORY
    (bsc#1176979).

  - PCI: Avoid double hpmemsize MMIO window assignment
    (git-fixes).

  - PCI: tegra194: Fix runtime PM imbalance on error
    (git-fixes).

  - PCI: tegra: Fix runtime PM imbalance on error
    (git-fixes).

  - Platform: OLPC: Fix memleak in olpc_ec_probe
    (git-fixes).

  - RDMA/hfi1: Correct an interlock issue for TID RDMA WRITE
    request (bsc#1175621).

  - Refresh
    patches.suse/fnic-to-not-call-scsi_done-for-unhandled-co
    mmands.patch (bsc#1168468, bsc#1171675).

  - SUNRPC: Revert 241b1f419f0e ('SUNRPC: Remove
    xdr_buf_trim()') (git-fixes).

  - USB: EHCI: ehci-mv: fix error handling in
    mv_ehci_probe() (git-fixes).

  - USB: EHCI: ehci-mv: fix less than zero comparison of an
    unsigned int (git-fixes).

  - USB: gadget: f_ncm: Fix NDP16 datagram validation
    (git-fixes).

  - Update patches.suse/target-add-rbd-backend.patch: ().
    (simplify block to byte calculations and use consistent
    error paths)

  - Update config files. Enable ACPI_PCI_SLOT and
    HOTPLUG_PCI_ACPI (bsc#1177194).

  - airo: Fix read overflows sending packets (git-fixes).

  - ar5523: Add USB ID of SMCWUSBT-G2 wireless adapter
    (git-fixes).

  - arm64: Enable PCI write-combine resources under sysfs
    (bsc#1175807).

  - ata: ahci: mvebu: Make SATA PHY optional for Armada 3720
    (git-fixes).

  - ath10k: fix array out-of-bounds access (git-fixes).

  - ath10k: fix memory leak for tpc_stats_final (git-fixes).

  - ath10k: use kzalloc to read for
    ath10k_sdio_hif_diag_read (git-fixes).

  - brcmfmac: Fix double freeing in the fmac usb data path
    (git-fixes).

  - btrfs: block-group: do not set the wrong READA flag for
    btrfs_read_block_groups() (bsc#1176019).

  - btrfs: block-group: fix free-space bitmap threshold
    (bsc#1176019).

  - btrfs: block-group: refactor how we delete one block
    group item (bsc#1176019).

  - btrfs: block-group: refactor how we insert a block group
    item (bsc#1176019).

  - btrfs: block-group: refactor how we read one block group
    item (bsc#1176019).

  - btrfs: block-group: rename write_one_cache_group()
    (bsc#1176019).

  - btrfs: check the right error variable in
    btrfs_del_dir_entries_in_log (bsc#1177687).

  - btrfs: do not set the full sync flag on the inode during
    page release (bsc#1177687).

  - btrfs: do not take an extra root ref at allocation time
    (bsc#1176019).

  - btrfs: drop logs when we've aborted a transaction
    (bsc#1176019).

  - btrfs: fix a race between scrub and block group
    removal/allocation (bsc#1176019).

  - btrfs: fix race between page release and a fast fsync
    (bsc#1177687).

  - btrfs: free block groups after free'ing fs trees
    (bsc#1176019).

  - btrfs: hold a ref on the root on the dead roots list
    (bsc#1176019).

  - btrfs: kill the subvol_srcu (bsc#1176019).

  - btrfs: make btrfs_cleanup_fs_roots use the radix tree
    lock (bsc#1176019).

  - btrfs: make inodes hold a ref on their roots
    (bsc#1176019).

  - btrfs: make the extent buffer leak check per fs info
    (bsc#1176019).

  - btrfs: move ino_cache_inode dropping out of
    btrfs_free_fs_root (bsc#1176019).

  - btrfs: move the block group freeze/unfreeze helpers into
    block-group.c (bsc#1176019).

  - btrfs: move the root freeing stuff into btrfs_put_root
    (bsc#1176019).

  - btrfs: only commit delayed items at fsync if we are
    logging a directory (bsc#1177687).

  - btrfs: only commit the delayed inode when doing a full
    fsync (bsc#1177687).

  - btrfs: reduce contention on log trees when logging
    checksums (bsc#1177687).

  - btrfs: release old extent maps during page release
    (bsc#1177687).

  - btrfs: remove no longer necessary chunk mutex locking
    cases (bsc#1176019).

  - btrfs: remove no longer needed use of log_writers for
    the log root tree (bsc#1177687).

  - btrfs: rename member 'trimming' of block group to a more
    generic name (bsc#1176019).

  - btrfs: scrub, only lookup for csums if we are dealing
    with a data extent (bsc#1176019).

  - btrfs: stop incremening log_batch for the log root tree
    when syncing log (bsc#1177687).

  - bus: hisi_lpc: Fixup IO ports addresses to avoid
    use-after-free in host removal (git-fixes).

  - clk/ti/adpll: allocate room for terminating null
    (git-fixes).

  - clk: samsung: exynos4: mark 'chipid' clock as
    CLK_IGNORE_UNUSED (git-fixes).

  - clk: socfpga: stratix10: fix the divider for the
    emac_ptp_free_clk (git-fixes).

  - clk: tegra: Always program PLL_E when enabled
    (git-fixes).

  - clocksource/drivers/h8300_timer8: Fix wrong return value
    in h8300_8timer_init() (git-fixes).

  - clocksource/drivers/timer-gx6605s: Fixup counter reload
    (git-fixes).

  - cpuidle: Poll for a minimum of 30ns and poll for a tick
    if lower c-states are disabled (bnc#1176588).

  - create Storage / NVMe subsection

  - crypto: algif_aead - Do not set MAY_BACKLOG on the async
    path (git-fixes).

  - crypto: algif_skcipher - EBUSY on aio should be an error
    (git-fixes).

  - crypto: bcm - Verify GCM/CCM key length in setkey
    (git-fixes).

  - crypto: dh - SP800-56A rev 3 local public key validation
    (bsc#1175718).

  - crypto: dh - check validity of Z before export
    (bsc#1175718).

  - crypto: ecc - SP800-56A rev 3 local public key
    validation (bsc#1175718).

  - crypto: ecdh - check validity of Z before export
    (bsc#1175718).

  - crypto: ixp4xx - Fix the size used in a
    'dma_free_coherent()' call (git-fixes).

  - crypto: mediatek - Fix wrong return value in
    mtk_desc_ring_alloc() (git-fixes).

  - crypto: omap-sham - fix digcnt register handling with
    export/import (git-fixes).

  - crypto: picoxcell - Fix potential race condition bug
    (git-fixes).

  - crypto: qat - check cipher length for aead
    AES-CBC-HMAC-SHA (git-fixes).

  - cypto: mediatek - fix leaks in mtk_desc_ring_alloc
    (git-fixes).

  - dma-fence: Serialise signal enabling
    (dma_fence_enable_sw_signaling) (git-fixes).

  - dmaengine: mediatek: hsdma_probe: fixed a memory leak
    when devm_request_irq fails (git-fixes).

  - dmaengine: stm32-dma: use vchan_terminate_vdesc() in
    .terminate_all (git-fixes).

  - dmaengine: stm32-mdma: use vchan_terminate_vdesc() in
    .terminate_all (git-fixes).

  - dmaengine: tegra-apb: Prevent race conditions on
    channel's freeing (git-fixes).

  - dmaengine: zynqmp_dma: fix burst length configuration
    (git-fixes).

  - drivers: char: tlclk.c: Avoid data race between init and
    interrupt handler (git-fixes).

  - drm/amdgpu: restore proper ref count in
    amdgpu_display_crtc_set_config (git-fixes).

  - drm/radeon: revert 'Prefer lower feedback dividers'
    (bsc#1177384).

  - drop Storage / bsc#1171688 subsection No effect on
    expanded tree.

  - e1000: Do not perform reset in reset_task if we are
    already down (git-fixes).

  - ftrace: Move RCU is watching check after recursion check
    (git-fixes).

  - fuse: do not ignore errors from fuse_writepages_fill()
    (bsc#1177193).

  - gpio: mockup: fix resource leak in error path
    (git-fixes).

  - gpio: rcar: Fix runtime PM imbalance on error
    (git-fixes).

  - gpio: siox: explicitly support only threaded irqs
    (git-fixes).

  - gpio: sprd: Clear interrupt when setting the type as
    edge (git-fixes).

  - gpio: tc35894: fix up tc35894 interrupt configuration
    (git-fixes).

  - hwmon: (applesmc) check status earlier (git-fixes).

  - hwmon: (mlxreg-fan) Fix double 'Mellanox' (git-fixes).

  - hwmon: (pmbus/max34440) Fix status register reads for
    MAX344(51,60,61) (git-fixes).

  - i2c: aspeed: Mask IRQ status to relevant bits
    (git-fixes).

  - i2c: core: Call i2c_acpi_install_space_handler() before
    i2c_acpi_register_devices() (git-fixes).

  - i2c: cpm: Fix i2c_ram structure (git-fixes).

  - i2c: i801: Exclude device from suspend direct complete
    optimization (git-fixes).

  - i2c: meson: fix clock setting overwrite (git-fixes).

  - i2c: meson: fixup rate calculation with filter delay
    (git-fixes).

  - i2c: owl: Clear NACK and BUS error bits (git-fixes).

  - i2c: tegra: Prevent interrupt triggering after transfer
    timeout (git-fixes).

  - i2c: tegra: Restore pinmux on system resume (git-fixes).

  - ieee802154/adf7242: check status of adf7242_read_reg
    (git-fixes).

  - ieee802154: fix one possible memleak in
    ca8210_dev_com_init (git-fixes).

  - iio: adc: qcom-spmi-adc5: fix driver name (git-fixes).

  - ima: extend boot_aggregate with kernel measurements
    (bsc#1177617).

  - iommu/amd: Fix IOMMU AVIC not properly update the is_run
    bit in IRTE (bsc#1177297).

  - iommu/amd: Fix potential @entry null deref
    (bsc#1177283).

  - iommu/amd: Re-factor guest virtual APIC (de-)activation
    code (bsc#1177284).

  - iommu/amd: Restore IRTE.RemapEn bit for
    amd_iommu_activate_guest_mode (bsc#1177285).

  - iommu/exynos: add missing put_device() call in
    exynos_iommu_of_xlate() (bsc#1177286).

  - iommu/vt-d: Correctly calculate agaw in domain_init()
    (bsc#1176400).

  - kABI: Fix kABI for 12856e7acde4 PCI/IOV: Mark VFs as not
    implementing PCI_COMMAND_MEMORY (bsc#1176979).

  - kabi fix for NFS: Fix flexfiles read failover
    (git-fixes).

  - kabi/severities: ignore kABI for target_core_rbd Match
    behaviour for all other Ceph specific modules.

  - kernel-binary.spec.in: Exclude .config.old from
    kernel-devel - use tar excludes for
    .kernel-binary.spec.buildenv

  - kernel-binary.spec.in: Package the obj_install_dir as
    explicit filelist.

  - leds: mlxreg: Fix possible buffer overflow (git-fixes).

  - lib/mpi: Add mpi_sub_ui() (bsc#1175718).

  -
    libceph-add-support-for-CMPEXT-compare-extent-reques.pat
    ch: (bsc#1177090).

  - locking/rwsem: Disable reader optimistic spinning
    (bnc#1176588).

  - mac80211: do not allow bigger VHT MPDUs than the
    hardware supports (git-fixes).

  - mac80211: skip mpath lookup also for control port tx
    (git-fixes).

  - mac802154: tx: fix use-after-free (git-fixes).

  - macsec: avoid use-after-free in macsec_handle_frame()
    (git-fixes).

  - media: Revert 'media: exynos4-is: Add missed check for
    pinctrl_lookup_state()' (git-fixes).

  - media: camss: Fix a reference count leak (git-fixes).

  - media: m5mols: Check function pointer in
    m5mols_sensor_power (git-fixes).

  - media: mc-device.c: fix memleak in
    media_device_register_entity (git-fixes).

  - media: mx2_emmaprp: Fix memleak in emmaprp_probe
    (git-fixes).

  - media: omap3isp: Fix memleak in isp_probe (git-fixes).

  - media: ov5640: Correct Bit Div register in clock tree
    diagram (git-fixes).

  - media: platform: fcp: Fix a reference count leak
    (git-fixes).

  - media: rc: do not access device via sysfs after
    rc_unregister_device() (git-fixes).

  - media: rc: uevent sysfs file races with
    rc_unregister_device() (git-fixes).

  - media: rcar-csi2: Allocate v4l2_async_subdev dynamically
    (git-fixes).

  - media: rcar-vin: Fix a reference count leak (git-fixes).

  - media: rockchip/rga: Fix a reference count leak
    (git-fixes).

  - media: s5p-mfc: Fix a reference count leak (git-fixes).

  - media: smiapp: Fix error handling at NVM reading
    (git-fixes).

  - media: staging/intel-ipu3: css: Correctly reset some
    memory (git-fixes).

  - media: stm32-dcmi: Fix a reference count leak
    (git-fixes).

  - media: tc358743: cleanup tc358743_cec_isr (git-fixes).

  - media: tc358743: initialize variable (git-fixes).

  - media: ti-vpe: Fix a missing check and reference count
    leak (git-fixes).

  - media: ti-vpe: cal: Restrict DMA to avoid memory
    corruption (git-fixes).

  - media: tuner-simple: fix regression in
    simple_set_radio_freq (git-fixes).

  - media: usbtv: Fix refcounting mixup (git-fixes).

  - media: uvcvideo: Set media controller entity functions
    (git-fixes).

  - media: uvcvideo: Silence shift-out-of-bounds warning
    (git-fixes).

  - media: v4l2-async: Document asd allocation requirements
    (git-fixes).

  - mfd: mfd-core: Protect against NULL call-back function
    pointer (git-fixes).

  - mm, compaction: fully assume capture is not NULL in
    compact_zone_order() (git fixes (mm/compaction),
    bsc#1177681).

  - mm, compaction: make capture control handling safe wrt
    interrupts (git fixes (mm/compaction), bsc#1177681).

  - mm, slab/slub: move and improve cache_from_obj()
    (mm/slub bsc#1165692).

  - mm, slab/slub: improve error reporting and overhead of
    cache_from_obj() (mm/slub bsc#1165692).

  - mm, slub: extend checks guarded by slub_debug static key
    (mm/slub bsc#1165692).

  - mm, slub: extend slub_debug syntax for multiple blocks
    (mm/slub bsc#1165692).

  - mm, slub: introduce kmem_cache_debug_flags() (mm/slub
    bsc#1165692).

  - mm, slub: introduce static key for slub_debug() (mm/slub
    bsc#1165692).

  - mm, slub: make reclaim_account attribute read-only
    (mm/slub bsc#1165692).

  - mm, slub: make remaining slub_debug related attributes
    read-only (mm/slub bsc#1165692).

  - mm, slub: make some slub_debug related attributes
    read-only (mm/slub bsc#1165692).

  - mm, slub: remove runtime allocation order changes
    (mm/slub bsc#1165692).

  - mm, slub: restore initial kmem_cache flags (mm/slub
    bsc#1165692).

  - mm/debug.c: always print flags in dump_page() (git fixes
    (mm/debug)).

  - mm/memcontrol.c: lost css_put in
    memcg_expand_shrinker_maps() (bsc#1177694).

  - mm/migrate.c: also overwrite error when it is bigger
    than zero (git fixes (mm/move_pages), bsc#1177683).

  - mm/pagealloc.c: call touch_nmi_watchdog() on max order
    boundaries in deferred init (git fixes (mm/init),
    bsc#1177697).

  - mm: call cond_resched() from deferred_init_memmap() (git
    fixes (mm/init), bsc#1177697).

  - mm: initialize deferred pages with interrupts enabled
    (git fixes (mm/init), bsc#1177697).

  - mm: move_pages: report the number of non-attempted pages
    (git fixes (mm/move_pages), bsc#1177683).

  - mm: move_pages: return valid node id in status if the
    page is already on the target node (git fixes
    (mm/move_pages), bsc#1177683).

  - mmc: core: Rework wp-gpio handling (git-fixes).

  - mmc: core: do not set limits.discard_granularity as 0
    (git-fixes).

  - mmc: sdhci-acpi: AMDI0040: Set
    SDHCI_QUIRK2_PRESET_VALUE_BROKEN (git-fixes).

  - mmc: sdhci: Add LTR support for some Intel BYT based
    controllers (git-fixes).

  - mmc: sdhci: Workaround broken command queuing on Intel
    GLK based IRBIS models (git-fixes).

  - mt76: add missing locking around ampdu action
    (git-fixes).

  - mt76: clear skb pointers from rx aggregation reorder
    buffer during cleanup (git-fixes).

  - mt76: do not use devm API for led classdev (git-fixes).

  - mt76: fix LED link time failure (git-fixes).

  - mt76: fix handling full tx queues in
    mt76_dma_tx_queue_skb_raw (git-fixes).

  - mtd: cfi_cmdset_0002: do not free cfi->cfiq in error
    path of cfi_amdstd_setup() (git-fixes).

  - mtd: rawnand: gpmi: Fix runtime PM imbalance on error
    (git-fixes).

  - mtd: rawnand: omap_elm: Fix runtime PM imbalance on
    error (git-fixes).

  - net: phy: realtek: fix rtl8211e rx/tx delay config
    (git-fixes).

  - nfs: Fix security label length not being reset
    (bsc#1176381).

  - nfs: ensure correct writeback errors are returned on
    close() (git-fixes).

  - nfs: nfs_file_write() should check for writeback errors
    (git-fixes).

  - nfsd4: fix NULL dereference in nfsd/clients display code
    (git-fixes).

  - nvme-multipath: retry commands for dying queues
    (bsc#1171688).

  - pNFS/flexfiles: Ensure we initialise the mirror bsizes
    correctly on read (git-fixes).

  - phy: ti: am654: Fix a leak in serdes_am654_probe()
    (git-fixes).

  - pinctrl: bcm: fix kconfig dependency warning when
    !GPIOLIB (git-fixes).

  - pinctrl: mvebu: Fix i2c sda definition for 98DX3236
    (git-fixes).

  - platform/x86: fix kconfig dependency warning for
    FUJITSU_LAPTOP (git-fixes).

  - platform/x86: fix kconfig dependency warning for
    LG_LAPTOP (git-fixes).

  - platform/x86: intel-vbtn: Switch to an allow-list for
    SW_TABLET_MODE reporting (bsc#1175599).

  - platform/x86: intel_pmc_core: do not create a static
    struct device (git-fixes).

  - platform/x86: thinkpad_acpi: initialize tp_nvram_state
    variable (git-fixes).

  - platform/x86: thinkpad_acpi: re-initialize ACPI buffer
    size when reuse (git-fixes).

  - power: supply: max17040: Correct voltage reading
    (git-fixes).

  - powerpc/dma: Fix dma_map_ops::get_required_mask
    (bsc#1065729).

  - qla2xxx: Return EBUSY on fcport deletion (bsc#1171688).

  - r8169: fix data corruption issue on RTL8402
    (bsc#1174098).

  - rbd-add-rbd_img_fill_cmp_and_write_from_bvecs.patch:
    (bsc#1177090).

  - rbd-add-support-for-COMPARE_AND_WRITE-CMPEXT.patch:
    (bsc#1177090).

  - regulator: axp20x: fix LDO2/4 description (git-fixes).

  - regulator: resolve supply after creating regulator
    (git-fixes).

  - rename Other drivers / Intel IOMMU subsection to IOMMU

  - rtc: ds1374: fix possible race condition (git-fixes).

  - rtc: sa1100: fix possible race condition (git-fixes).

  - s390/pci: Mark all VFs as not implementing
    PCI_COMMAND_MEMORY (bsc#1176979).

  - sched/fair: Ignore cache hotness for SMT migration
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched/fair: Use dst group while checking imbalance for
    NUMA balancer (bnc#1155798 (CPU scheduler functional and
    performance backports)).

  - sched/numa: Avoid creating large imbalances at task
    creation time (bnc#1176588).

  - sched/numa: Check numa balancing information only when
    enabled (bnc#1176588).

  - sched/numa: Use runnable_avg to classify node
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - scsi: iscsi: iscsi_tcp: Avoid holding spinlock while
    calling getpeername() (bsc#1177258).

  - scsi: qla2xxx: Add IOCB resource tracking (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Add SLER and PI control support
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Add rport fields in debugfs (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Allow dev_loss_tmo setting for FC-NVMe
    devices (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Correct the check for sscanf() return
    value (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix I/O errors during LIP reset tests
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix I/O failures during remote port
    toggle testing (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix MPI reset needed message (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix buffer-buffer credit extraction error
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix crash on session cleanup with unload
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    qla_dbg.c (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    tcm_qla2xxx.c (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    qla_os.c (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix memory size truncation (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix point-to-point (N2N) device discovery
    issue (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix reset of MPI firmware (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Honor status qualifier in FCP_RSP per
    spec (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make tgt_port_database available in
    initiator mode (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Performance tweak (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Reduce duplicate code in reporting speed
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Remove unneeded variable 'rval'
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Setup debugfs entries for remote ports
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Update version to 10.02.00.102-k
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Update version to 10.02.00.103-k
    (bsc#1171688 bsc#1174003).

  - serial: 8250: 8250_omap: Terminate DMA before pushing
    data on RX timeout (git-fixes).

  - serial: 8250_omap: Fix sleeping function called from
    invalid context during probe (git-fixes).

  - serial: 8250_port: Do not service RX FIFO if throttled
    (git-fixes).

  - serial: uartps: Wait for tx_empty in console setup
    (git-fixes).

  - spi: dw-pci: free previously allocated IRQs if
    desc->setup() fails (git-fixes).

  - spi: fsl-espi: Only process interrupts for expected
    events (git-fixes).

  - spi: omap2-mcspi: Improve performance waiting for CHSTAT
    (git-fixes).

  - spi: sprd: Release DMA channel also on probe deferral
    (git-fixes).

  - spi: stm32: Rate-limit the 'Communication suspended'
    message (git-fixes).

  - staging:r8188eu: avoid skb_clone for amsdu to msdu
    conversion (git-fixes).

  - svcrdma: Fix page leak in svc_rdma_recv_read_chunk()
    (git-fixes).

  -
    target-compare-and-write-backend-driver-sense-handli.pat
    ch: (bsc#1177719).

  - target-rbd-add-WRITE-SAME-support.patch: (bsc#1177090).

  -
    target-rbd-add-emulate_legacy_capacity-dev-attribute.pat
    ch: (bsc#1177109).

  -
    target-rbd-conditionally-fix-off-by-one-bug-in-get_b.pat
    ch: (bsc#1177109).

  -
    target-rbd-detect-stripe_unit-SCSI-block-size-misali.pat
    ch: (bsc#1177090).

  -
    target-rbd-fix-unmap-discard-block-size-conversion.patch
    : (bsc#1177271).

  -
    target-rbd-fix-unmap-handling-with-unmap_zeroes_data.pat
    ch: (bsc#1177271).

  - target-rbd-support-COMPARE_AND_WRITE.patch:
    (bsc#1177090).

  - thermal: rcar_thermal: Handle probe error gracefully
    (git-fixes).

  - usb: dwc3: Increase timeout for CmdAct cleared by device
    controller (git-fixes).

  - vfio/pci: Decouple PCI_COMMAND_MEMORY bit checks from
    is_virtfn (bsc#1176979).

  - virtio-net: do not disable guest csum when disable LRO
    (git-fixes).

  - vmxnet3: fix cksum offload issues for non-udp tunnels
    (git-fixes).

  - wlcore: fix runtime pm imbalance in wl1271_tx_work
    (git-fixes).

  - wlcore: fix runtime pm imbalance in
    wlcore_regdomain_config (git-fixes).

  - x86/unwind/orc: Fix inactive tasks with stack pointer in
    %sp on GCC 10 compiled kernels (bsc#1176907).

  - xen/events: do not use chip_data for legacy IRQs
    (bsc#1065600).

  - xprtrdma: fix incorrect header size calculations
    (git-fixes).

  - yam: fix possible memory leak in yam_init_driver
    (git-fixes)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=802154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954532"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.47.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.47.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.47.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.47.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-debuginfo / kernel-debug-debugsource / etc");
}
