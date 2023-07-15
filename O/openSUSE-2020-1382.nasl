#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1382.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140443);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/29");

  script_cve_id("CVE-2020-14314", "CVE-2020-14386");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1382)");
  script_summary(english:"Check for the openSUSE-2020-1382 patch");

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

  - CVE-2020-14314: Fixed potential negative array index in
    do_split() in ext4 (bsc#1173798).

  - CVE-2020-14386: Fixed an overflow in af_packet, which
    could lead to local privilege escalation (bsc#1176069).

The following non-security bugs were fixed :

  - ACPICA: Do not increment operation_region reference
    counts for field units (git-fixes).

  - ALSA: hda/realtek: Add model alc298-samsung-headphone
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Galaxy Flex
    Book (git-fixes).

  - ALSA: hda: avoid reset of sdo_limit (git-fixes).

  - ALSA: isa: fix spelling mistakes in the comments
    (git-fixes).

  - ALSA: usb-audio: Add capture support for Saffire 6 (USB
    1.1) (git-fixes).

  - ALSA: usb-audio: Update documentation comment for MS2109
    quirk (git-fixes).

  - ALSA: usb-audio: ignore broken processing/extension unit
    (git-fixes).

  - ASoC: intel: Fix memleak in sst_media_open (git-fixes).

  - ASoC: msm8916-wcd-analog: fix register Interrupt offset
    (git-fixes).

  - ASoC: q6afe-dai: mark all widgets registers as
    SND_SOC_NOPM (git-fixes).

  - ASoC: q6routing: add dummy register read/write function
    (git-fixes).

  - ASoC: wm8994: Avoid attempts to read unreadable
    registers (git-fixes).

  - Bluetooth: add a mutex lock to avoid UAF in do_enale_set
    (git-fixes).

  - Drivers: hv: vmbus: Only notify Hyper-V for die events
    that are oops (bsc#1175128).

  - HID: input: Fix devices that return multiple bytes in
    battery report (git-fixes).

  - Input: psmouse - add a newline when printing 'proto' by
    sysfs (git-fixes).

  - KVM: PPC: Book3S PR: Remove uninitialized_var() usage
    (bsc#1065729).

  - KVM: Reinstall old memslots if arch preparation fails
    (bsc#1133021).

  - KVM: arm64: Stop clobbering x0 for HVC_SOFT_RESTART
    (bsc#1133021).

  - KVM: x86: Fix APIC page invalidation race (bsc#1133021).

  - PCI: hv: Fix a timing issue which causes kdump to fail
    occasionally (bsc#1172871, git-fixes).

  - RDMA/mlx5: Add missing srcu_read_lock in ODP implicit
    flow (jsc#SLE-8446).

  - RDMA/mlx5: Fix typo in enum name (git-fixes).

  - Revert 'scsi: qla2xxx: Disable T10-DIF feature with
    FC-NVMe during probe' (bsc#1171688 bsc#1174003).

  - Revert 'scsi: qla2xxx: Fix crash on
    qla2x00_mailbox_command' (bsc#1171688 bsc#1174003).

  - bdc: Fix bug causing crash after multiple disconnects
    (git-fixes).

  - bfq: fix blkio cgroup leakage v4 (bsc#1175775).

  - block: Fix the type of 'sts' in bsg_queue_rq()
    (git-fixes).

  - bnxt_en: fix NULL dereference in case SR-IOV
    configuration fails (networking-stable-20_07_17).

  - bonding: fix active-backup failover for current ARP
    slave (bsc#1174771).

  - brcmfmac: To fix Bss Info flag definition Bug
    (git-fixes).

  - brcmfmac: keep SDIO watchdog running when
    console_interval is non-zero (git-fixes).

  - brcmfmac: set state of hanger slot to FREE when flushing
    PSQ (git-fixes).

  - btrfs: add helper to get the end offset of a file extent
    item (bsc#1175546).

  - btrfs: factor out inode items copy loop from
    btrfs_log_inode() (bsc#1175546).

  - btrfs: fix memory leaks after failure to lookup
    checksums during inode logging (bsc#1175550).

  - btrfs: fix missing file extent item for hole after
    ranged fsync (bsc#1175546).

  - btrfs: make full fsyncs always operate on the entire
    file again (bsc#1175546).

  - btrfs: make ranged full fsyncs more efficient
    (bsc#1175546).

  - btrfs: remove useless check for copy_items() return
    value (bsc#1175546).

  - btrfs: treat RWF_(,D)SYNC writes as sync for CRCs
    (bsc#1175493).

  - config/x86_64: Make CONFIG_PINCTRL_AMD=y (bsc#1174800)
    The pinctrl driver has to be initialized before hid-i2c
    and others. For assuring it, change it built-in, since
    we can't put the module ordering. This change follows
    the SLE15-SP2 kernel behavior.

  - cpumap: Use non-locked version
    __ptr_ring_consume_batched (git-fixes).

  - crypto: aesni - Fix build with LLVM_IAS=1 (git-fixes).

  - crypto: aesni - add compatibility with IAS (git-fixes).

  - dlm: Fix kobject memleak (bsc#1175768).

  - drm/amd/display: Fix EDID parsing after resume from
    suspend (git-fixes).

  - drm/amd/display: fix pow() crashing when given base 0
    (git-fixes).

  - drm/amd/powerplay: fix compile error with ARCH=arc
    (git-fixes).

  - drm/amdgpu/display bail early in dm_pp_get_static_clocks
    (git-fixes).

  - drm/amdgpu: avoid dereferencing a NULL pointer
    (git-fixes).

  - drm/debugfs: fix plain echo to connector 'force'
    attribute (git-fixes).

  - drm/etnaviv: fix ref count leak via pm_runtime_get_sync
    (git-fixes).

  - drm/msm: ratelimit crtc event overflow error
    (git-fixes).

  - drm/nouveau/kms/nv50-: Fix disabling dithering
    (git-fixes).

  - drm/nouveau: fix multiple instances of reference count
    leaks (git-fixes).

  - drm/nouveau: fix reference count leak in
    nouveau_debugfs_strap_peek (git-fixes).

  - drm/radeon: Fix reference count leaks caused by
    pm_runtime_get_sync (git-fixes).

  - drm/radeon: disable AGP by default (git-fixes).

  - drm/tilcdc: fix leak & null ref in
    panel_connector_get_modes (git-fixes).

  - drm/ttm/nouveau: do not call tt destroy callback on
    alloc failure (git-fixes bsc#1175232).

  - drm: msm: a6xx: fix gpu failure after system resume
    (git-fixes).

  - dyndbg: fix a BUG_ON in ddebug_describe_flags
    (git-fixes).

  - enetc: Fix tx rings bitmap iteration range, irq handling
    (networking-stable-20_06_28).

  - ext2: fix missing percpu_counter_inc (bsc#1175774).

  - ext4: check journal inode extents more carefully
    (bsc#1173485).

  - ext4: do not BUG on inconsistent journal feature
    (bsc#1171634).

  - ext4: do not allow overlapping system zones
    (bsc#1173485).

  - ext4: fix checking of directory entry validity for
    inline directories (bsc#1175771).

  - ext4: handle error of ext4_setup_system_zone() on
    remount (bsc#1173485).

  - genetlink: remove genl_bind
    (networking-stable-20_07_17).

  - gpu: host1x: debug: Fix multiple channels emitting
    messages simultaneously (git-fixes).

  - i2c: i801: Add support for Intel Comet Lake PCH-V
    (jsc#SLE-13411).

  - i2c: i801: Add support for Intel Emmitsburg PCH
    (jsc#SLE-13411).

  - i2c: i801: Add support for Intel Tiger Lake PCH-H
    (jsc#SLE-13411).

  - ibmveth: Fix use of ibmveth in a bridge (bsc#1174387
    ltc#187506).

  - ibmvnic fix NULL tx_pools and rx_tools issue at do_reset
    (bsc#1175873 ltc#187922).

  - ice: Clear and free XLT entries on reset (jsc#SLE-7926).

  - ice: Graceful error handling in HW table calloc failure
    (jsc#SLE-7926).

  - igc: Fix PTP initialization (bsc#1160634).

  - ip6_gre: fix null-ptr-deref in ip6gre_init_net()
    (git-fixes).

  - ip6_gre: fix use-after-free in ip6gre_tunnel_lookup()
    (networking-stable-20_06_28).

  - ip_tunnel: fix use-after-free in ip_tunnel_lookup()
    (networking-stable-20_06_28).

  - ipv4: fill fl4_icmp_(type,code) in ping_v4_sendmsg
    (networking-stable-20_07_17).

  - ipv6: Fix use of anycast address with loopback
    (networking-stable-20_07_17).

  - ipv6: fib6_select_path can not use out path for nexthop
    objects (networking-stable-20_07_17).

  - ipvs: fix the connection sync failed in some cases
    (bsc#1174699).

  - iwlegacy: Check the return value of
    pcie_capability_read_*() (git-fixes).

  - jbd2: add the missing unlock_buffer() in the error path
    of jbd2_write_superblock() (bsc#1175772).

  - kABI: genetlink: remove genl_bind (kabi).

  - kabi/severities: ignore KABI for NVMe, except nvme-fc
    (bsc#1174777) Exported symbols under drivers/nvme/host/
    are only used by the nvme subsystem itself, except for
    the nvme-fc symbols.

  - kabi/severities: ignore qla2xxx as all symbols are
    internal

  - kernel/relay.c: fix memleak on destroy relay channel
    (git-fixes).

  - kernfs: do not call fsnotify() with name without a
    parent (bsc#1175770).

  - l2tp: remove skb_dst_set() from l2tp_xmit_skb()
    (networking-stable-20_07_17).

  - llc: make sure applications use ARPHRD_ETHER
    (networking-stable-20_07_17).

  - md-cluster: Fix potential error pointer dereference in
    resize_bitmaps() (git-fixes).

  - md/raid5: Fix Force reconstruct-write io stuck in
    degraded raid5 (git-fixes).

  - media: budget-core: Improve exception handling in
    budget_register() (git-fixes).

  - media: camss: fix memory leaks on error handling paths
    in probe (git-fixes).

  - media: rockchip: rga: Introduce color fmt macros and
    refactor CSC mode logic (git-fixes).

  - media: rockchip: rga: Only set output CSC mode for RGB
    input (git-fixes).

  - media: vpss: clean up resources in init (git-fixes).

  - mfd: intel-lpss: Add Intel Tiger Lake PCH-H PCI IDs
    (jsc#SLE-13411).

  - mld: fix memory leak in ipv6_mc_destroy_dev()
    (networking-stable-20_06_28).

  - mlxsw: pci: Fix use-after-free in case of failed devlink
    reload (networking-stable-20_07_17).

  - mlxsw: spectrum_router: Remove inappropriate usage of
    WARN_ON() (networking-stable-20_07_17).

  - mm, vmstat: reduce zone->lock holding time by
    /proc/pagetypeinfo (bsc#1175691).

  - mm/vunmap: add cond_resched() in vunmap_pmd_range
    (bsc#1175654 ltc#184617).

  - mm: filemap: clear idle flag for writes (bsc#1175769).

  - mmc: sdhci-cadence: do not use hardware tuning for SD
    mode (git-fixes).

  - mmc: sdhci-pci-o2micro: Bug fix for O2 host controller
    Seabird1 (git-fixes).

  - mvpp2: ethtool rxtx stats fix
    (networking-stable-20_06_28).

  - net/mlx5: DR, Change push vlan action sequence
    (jsc#SLE-8464).

  - net/mlx5: Fix eeprom support for SFP module
    (networking-stable-20_07_17).

  - net/mlx5e: Fix 50G per lane indication
    (networking-stable-20_07_17).

  - net: Added pointer check for dst->ops->neigh_lookup in
    dst_neigh_lookup_skb (networking-stable-20_07_17).

  - net: Do not clear the sock TX queue in sk_set_socket()
    (networking-stable-20_06_28).

  - net: Fix the arp error in some cases
    (networking-stable-20_06_28).

  - net: bridge: enfore alignment for ethernet address
    (networking-stable-20_06_28).

  - net: core: reduce recursion limit value
    (networking-stable-20_06_28).

  - net: dsa: microchip: set the correct number of ports
    (networking-stable-20_07_17).

  - net: ena: Change WARN_ON expression in
    ena_del_napi_in_range() (bsc#1154492).

  - net: ena: Make missed_tx stat incremental (git-fixes).

  - net: ena: Prevent reset after device destruction
    (git-fixes).

  - net: fix memleak in register_netdevice()
    (networking-stable-20_06_28).

  - net: increment xmit_recursion level in dev_direct_xmit()
    (networking-stable-20_06_28).

  - net: mvneta: fix use of state->speed
    (networking-stable-20_07_17).

  - net: qrtr: Fix an out of bounds read
    qrtr_endpoint_post() (networking-stable-20_07_17).

  - net: usb: ax88179_178a: fix packet alignment padding
    (networking-stable-20_06_28).

  - net: usb: qmi_wwan: add support for Quectel EG95 LTE
    modem (networking-stable-20_07_17).

  - net_sched: fix a memory leak in atm_tc_init()
    (networking-stable-20_07_17).

  - nvme-multipath: do not fall back to __nvme_find_path()
    for non-optimized paths (bsc#1172108).

  - nvme-multipath: fix logic for non-optimized paths
    (bsc#1172108).

  - nvme-multipath: round-robin: eliminate 'fallback'
    variable (bsc#1172108).

  - nvme-multipath: set bdi capabilities once (bsc#1159058).

  - nvme-pci: Re-order nvme_pci_free_ctrl (bsc#1159058).

  - nvme-rdma: Add warning on state change failure at
    (bsc#1159058).

  - nvme-tcp: Add warning on state change failure at
    (bsc#1159058).

  - nvme-tcp: fix possible crash in write_zeroes processing
    (bsc#1159058).

  - nvme: Fix controller creation races with teardown flow
    (bsc#1159058).

  - nvme: Fix ctrl use-after-free during sysfs deletion
    (bsc#1159058).

  - nvme: Make nvme_uninit_ctrl symmetric to nvme_init_ctrl
    (bsc#1159058).

  - nvme: Remove unused return code from
    nvme_delete_ctrl_sync (bsc#1159058).

  - nvme: add a Identify Namespace Identification Descriptor
    list quirk (git-fixes).

  - nvme: always search for namespace head (bsc#1159058).

  - nvme: avoid an Identify Controller command for each
    namespace (bsc#1159058).

  - nvme: check namespace head shared property
    (bsc#1159058).

  - nvme: clean up nvme_scan_work (bsc#1159058).

  - nvme: cleanup namespace identifier reporting in
    (bsc#1159058).

  - nvme: consolidate chunk_sectors settings (bsc#1159058).

  - nvme: consolodate io settings (bsc#1159058).

  - nvme: expose hostid via sysfs for fabrics controllers
    (bsc#1159058).

  - nvme: expose hostnqn via sysfs for fabrics controllers
    (bsc#1159058).

  - nvme: factor out a nvme_ns_remove_by_nsid helper
    (bsc#1159058).

  - nvme: fix a crash in nvme_mpath_add_disk (git-fixes,
    bsc#1159058).

  - nvme: fix identify error status silent ignore
    (git-fixes, bsc#1159058).

  - nvme: fix possible hang when ns scanning fails during
    error (bsc#1159058).

  - nvme: kABI fixes for nvme_ctrl (bsc#1159058).

  - nvme: multipath: round-robin: fix single non-optimized
    path case (bsc#1172108).

  - nvme: prevent double free in nvme_alloc_ns() error
    handling (bsc#1159058).

  - nvme: provide num dword helper (bsc#1159058).

  - nvme: refactor nvme_identify_ns_descs error handling
    (bsc#1159058).

  - nvme: refine the Qemu Identify CNS quirk (bsc#1159058).

  - nvme: release ida resources (bsc#1159058).

  - nvme: release namespace head reference on error
    (bsc#1159058).

  - nvme: remove the magic 1024 constant in
    nvme_scan_ns_list (bsc#1159058).

  - nvme: remove unused parameter (bsc#1159058).

  - nvme: rename __nvme_find_ns_head to nvme_find_ns_head
    (bsc#1159058).

  - nvme: revalidate after verifying identifiers
    (bsc#1159058).

  - nvme: revalidate namespace stream parameters
    (bsc#1159058).

  - nvme: unlink head after removing last namespace
    (bsc#1159058).

  - openvswitch: take into account de-fragmentation/gso_size
    in execute_check_pkt_len (networking-stable-20_06_28).

  - platform/x86: ISST: Add new PCI device ids (git-fixes).

  - platform/x86: asus-nb-wmi: add support for ASUS ROG
    Zephyrus G14 and G15 (git-fixes).

  - powerpc/64s: Do not init FSCR_DSCR in __init_FSCR()
    (bsc#1065729).

  - powerpc/fadump: Fix build error with
    CONFIG_PRESERVE_FA_DUMP=y (bsc#1156395).

  - powerpc/iommu: Allow bypass-only for DMA (bsc#1156395).

  - powerpc/perf: Fix missing is_sier_aviable() during build
    (bsc#1065729).

  - powerpc/pseries/hotplug-cpu: wait indefinitely for vCPU
    death (bsc#1085030 ltC#165630).

  - powerpc/pseries: Do not initiate shutdown when system is
    running on UPS (bsc#1175440 ltc#187574).

  - pseries: Fix 64 bit logical memory block panic
    (bsc#1065729).

  - rocker: fix incorrect error handling in dma_rings_init
    (networking-stable-20_06_28).

  - rtc: goldfish: Enable interrupt in set_alarm() when
    necessary (git-fixes).

  - sch_cake: do not call diffserv parsing code when it is
    not needed (networking-stable-20_06_28).

  - sch_cake: do not try to reallocate or unshare skb
    unconditionally (networking-stable-20_06_28).

  - sched: consistently handle layer3 header accesses in the
    presence of VLANs (networking-stable-20_07_17).

  - scsi/fc: kABI fixes for new ELS_RPD definition
    (bsc#1171688 bsc#1174003).

  - scsi: Fix trivial spelling (bsc#1171688 bsc#1174003).

  - scsi: dh: Add Fujitsu device to devinfo and dh lists
    (bsc#1174026).

  - scsi: qla2xxx: Add more BUILD_BUG_ON() statements
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Address a set of sparse warnings
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Allow ql2xextended_error_logging special
    value 1 to be set anytime (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Cast explicitly to uint16_t / uint32_t
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Change in PUREX to handle FPIN ELS
    requests (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Change two hardcoded constants into
    offsetof() / sizeof() expressions (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Change (RD,WRT)_REG_*() function names
    from upper case into lower case (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Check if FW supports MQ before enabling
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Check the size of struct fcp_hdr at
    compile time (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix MPI failure AEN (8200) handling
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix WARN_ON in qla_nvme_register_hba
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix a Coverity complaint in
    qla2100_fw_dump() (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix a condition in
    qla2x00_find_all_fabric_devs() (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix endianness annotations in header
    files (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix endianness annotations in source
    files (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix failure message in qlt_disable_vha()
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix issue with adapter's stopping state
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix login timeout (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix NULL pointer access during disconnect
    from subsystem (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix spelling of a variable name
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix the code that reads from mailbox
    registers (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix warning after FC target reset
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Flush I/O on zone disable (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Flush all sessions on zone disable
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Increase the size of struct
    qla_fcp_prio_cfg to FCP_PRIO_CFG_SIZE (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Indicate correct supported speeds for
    Mezz card (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Initialize 'n' before using it
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Introduce a function for computing the
    debug message prefix (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Keep initiator ports after RSCN
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make __qla2x00_alloc_iocbs() initialize
    32 bits of request_t.handle (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make a gap in struct qla2xxx_offld_chain
    explicit (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qla2x00_restart_isp() easier to read
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qla82xx_flash_wait_write_finish()
    easier to read (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qla_set_ini_mode() return void
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qlafx00_process_aen() return void
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Reduce noisy debug message (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Remove a superfluous cast (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Remove an unused function (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Remove return value from qla_nvme_ls()
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Remove the __packed annotation from
    struct fcp_hdr and fcp_hdr_le (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: SAN congestion management implementation
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Simplify the functions for dumping
    firmware (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Sort BUILD_BUG_ON() statements
    alphabetically (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Split qla2x00_configure_local_loop()
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use ARRAY_SIZE() instead of open-coding
    it (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use MBX_TOV_SECONDS for mailbox command
    timeout values (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use make_handle() instead of open-coding
    it (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use register names instead of register
    offsets (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use true, false for ha->fw_dumped
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use true, false for need_mpi_reset
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: make 1-bit bit-fields unsigned int
    (bsc#1171688 bsc#1174003).

  - scsi: smartpqi: Identify physical devices without
    issuing INQUIRY (bsc#1172418).

  - scsi: smartpqi: Use scnprintf() for avoiding potential
    buffer overflow (bsc#1172418).

  - scsi: smartpqi: add RAID bypass counter (bsc#1172418).

  - scsi: smartpqi: add id support for SmartRAID 3152-8i
    (bsc#1172418).

  - scsi: smartpqi: avoid crashing kernel for controller
    issues (bsc#1172418).

  - scsi: smartpqi: bump version to 1.2.16-010
    (bsc#1172418).

  - scsi: smartpqi: support device deletion via sysfs
    (bsc#1172418).

  - scsi: smartpqi: update logical volume size after
    expansion (bsc#1172418).

  - scsi: target/iblock: fix WRITE SAME zeroing
    (bsc#1169790).

  - sctp: Do not advertise IPv4 addresses if ipv6only is set
    on the socket (networking-stable-20_06_28).

  - selftests/livepatch: fix mem leaks in
    test-klp-shadow-vars (bsc#1071995).

  - selftests/livepatch: more verification in
    test-klp-shadow-vars (bsc#1071995).

  - selftests/livepatch: rework test-klp-shadow-vars
    (bsc#1071995).

  - selftests/livepatch: simplify test-klp-callbacks busy
    target tests (bsc#1071995).

  - serial: 8250: change lock order in
    serial8250_do_startup() (git-fixes).

  - serial: pl011: Do not leak amba_ports entry on driver
    register error (git-fixes).

  - serial: pl011: Fix oops on -EPROBE_DEFER (git-fixes).

  - soc/tegra: pmc: Enable PMIC wake event on Tegra194
    (bsc#1175834).

  - soc: qcom: rpmh-rsc: Set suppress_bind_attrs flag
    (git-fixes).

  - spi: pxa2xx: Add support for Intel Tiger Lake PCH-H
    (jsc#SLE-13411).

  - spi: spidev: Align buffers for DMA (git-fixes).

  - spi: stm32: fixes suspend/resume management (git-fixes).

  - tcp: do not ignore ECN CWR on pure ACK
    (networking-stable-20_06_28).

  - tcp: fix SO_RCVLOWAT possible hangs under high mem
    pressure (networking-stable-20_07_17).

  - tcp: grow window for OOO packets only for SACK flows
    (networking-stable-20_06_28).

  - tcp: make sure listeners do not initialize
    congestion-control state (networking-stable-20_07_17).

  - tcp: md5: add missing memory barriers in
    tcp_md5_do_add()/tcp_md5_hash_key()
    (networking-stable-20_07_17).

  - tcp: md5: do not send silly options in SYNCOOKIES
    (networking-stable-20_07_17).

  - tcp: md5: refine tcp_md5_do_add()/tcp_md5_hash_key()
    barriers (networking-stable-20_07_17).

  - tcp_cubic: fix spurious HYSTART_DELAY exit upon drop in
    min RTT (networking-stable-20_06_28).

  - tracepoint: Mark __tracepoint_string's __used
    (git-fixes).

  - tracing: Use trace_sched_process_free() instead of
    exit() for pid tracing (git-fixes).

  - usb: bdc: Halt controller on suspend (git-fixes).

  - usb: gadget: net2280: fix memory leak on probe error
    handling paths (git-fixes).

  - usb: mtu3: clear dual mode of u3port when disable device
    (git-fixes).

  - video: fbdev: neofb: fix memory leak in
    neo_scan_monitor() (git-fixes).

  - video: fbdev: savage: fix memory leak on error handling
    path in probe (git-fixes).

  - vlan: consolidate VLAN parsing code and limit max
    parsing depth (networking-stable-20_07_17).

  - vmxnet3: use correct tcp hdr length when packet is
    encapsulated (bsc#1175199).

  - x86/bugs/multihit: Fix mitigation reporting when VMX is
    not in use (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176069"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/09");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.41.1.lp152.8.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.41.1.lp152.8.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.41.1") ) flag++;

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
