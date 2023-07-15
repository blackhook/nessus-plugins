#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-764.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111416);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-9385");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-764)");
  script_summary(english:"Check for the openSUSE-2018-764 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 42.3 was updated to 4.4.140 to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-13053: The alarm_timer_nsleep function had an
    integer overflow via a large relative timeout because
    ktime_add_safe was not used (bnc#1099924).

  - CVE-2018-9385: Prevent overread of the 'driver_override'
    buffer (bsc#1100491).

  - CVE-2018-13405: The inode_init_owner function allowed
    local users to create files with an unintended group
    ownership allowing attackers to escalate privileges by
    making a plain file executable and SGID (bnc#1100416).

  - CVE-2018-13406: An integer overflow in the
    uvesafb_setcmap function could have result in local
    attackers being able to crash the kernel or potentially
    elevate privileges because kmalloc_array is not used
    (bnc#1100418).

The following non-security bugs were fixed :

  - 1wire: family module autoload fails because of
    upper/lower case mismatch (bnc#1012382).

  - ALSA: hda - Clean up ALC299 init code (bsc#1099810).

  - ALSA: hda - Enable power_save_node for CX20722
    (bsc#1099810).

  - ALSA: hda - Fix a wrong FIXUP for alc289 on Dell
    machines (bsc#1099810).

  - ALSA: hda - Fix incorrect usage of IS_REACHABLE()
    (bsc#1099810).

  - ALSA: hda - Fix pincfg at resume on Lenovo T470 dock
    (bsc#1099810).

  - ALSA: hda - Handle kzalloc() failure in
    snd_hda_attach_pcm_stream() (bnc#1012382).

  - ALSA: hda - Use acpi_dev_present() (bsc#1099810).

  - ALSA: hda - add a new condition to check if it is
    thinkpad (bsc#1099810).

  - ALSA: hda - silence uninitialized variable warning in
    activate_amp_in() (bsc#1099810).

  - ALSA: hda/patch_sigmatel: Add AmigaOne X1000 pinconfigs
    (bsc#1099810).

  - ALSA: hda/realtek - Add a quirk for FSC ESPRIMO U9210
    (bsc#1099810).

  - ALSA: hda/realtek - Add headset mode support for Dell
    laptop (bsc#1099810).

  - ALSA: hda/realtek - Add support headset mode for DELL
    WYSE (bsc#1099810).

  - ALSA: hda/realtek - Clevo P950ER ALC1220 Fixup
    (bsc#1099810).

  - ALSA: hda/realtek - Enable Thinkpad Dock device for
    ALC298 platform (bsc#1099810).

  - ALSA: hda/realtek - Enable mic-mute hotkey for several
    Lenovo AIOs (bsc#1099810).

  - ALSA: hda/realtek - Fix Dell headset Mic can't record
    (bsc#1099810).

  - ALSA: hda/realtek - Fix pop noise on Lenovo P50 and co
    (bsc#1099810).

  - ALSA: hda/realtek - Fix the problem of two front mics on
    more machines (bsc#1099810).

  - ALSA: hda/realtek - Fixup for HP x360 laptops with BO
    speakers (bsc#1099810).

  - ALSA: hda/realtek - Fixup mute led on HP Spectre x360
    (bsc#1099810).

  - ALSA: hda/realtek - Make dock sound work on ThinkPad
    L570 (bsc#1099810).

  - ALSA: hda/realtek - Refactor
    alc269_fixup_hp_mute_led_mic*() (bsc#1099810).

  - ALSA: hda/realtek - Reorder ALC269 ASUS quirk entries
    (bsc#1099810).

  - ALSA: hda/realtek - Support headset mode for
    ALC215/ALC285/ALC289 (bsc#1099810).

  - ALSA: hda/realtek - Update ALC255 depop optimize
    (bsc#1099810).

  - ALSA: hda/realtek - adjust the location of one mic
    (bsc#1099810).

  - ALSA: hda/realtek - change the location for one of two
    front mics (bsc#1099810).

  - ALSA: hda/realtek - set PINCFG_HEADSET_MIC to
    parse_flags (bsc#1099810).

  - ALSA: hda/realtek - update ALC215 depop optimize
    (bsc#1099810).

  - ALSA: hda/realtek - update ALC225 depop optimize
    (bsc#1099810).

  - ALSA: hda/realtek: Fix mic and headset jack sense on
    Asus X705UD (bsc#1099810).

  - ALSA: hda/realtek: Limit mic boost on T480
    (bsc#1099810).

  - ALSA: hda: Fix forget to free resource in error handling
    code path in hda_codec_driver_probe (bsc#1099810).

  - ALSA: hda: add dock and led support for HP EliteBook 830
    G5 (bsc#1099810).

  - ALSA: hda: add dock and led support for HP ProBook 640
    G4 (bsc#1099810).

  - ALSA: hda: fix some klockwork scan warnings
    (bsc#1099810).

  - ARM: 8764/1: kgdb: fix NUMREGBYTES so that gdb_regs[] is
    the correct size (bnc#1012382).

  - ARM: dts: imx6q: Use correct SDMA script for SPI5 core
    (bnc#1012382).

  - ASoC: cirrus: i2s: Fix LRCLK configuration
    (bnc#1012382).

  - ASoC: cirrus: i2s: Fix (TX|RX)LinCtrlData setup
    (bnc#1012382).

  - ASoC: dapm: delete dapm_kcontrol_data paths list before
    freeing it (bnc#1012382).

  - Bluetooth: Fix connection if directed advertising and
    privacy is used (bnc#1012382).

  - Bluetooth: hci_qca: Avoid missing rampatch failure with
    userspace fw loader (bnc#1012382).

  - Btrfs: fix clone vs chattr NODATASUM race (bnc#1012382).

  - Btrfs: fix unexpected cow in run_delalloc_nocow
    (bnc#1012382).

  - Btrfs: make raid6 rebuild retry more (bnc#1012382).

  - Btrfs: scrub: Do not use inode pages for device replace
    (bnc#1012382).

  - Correct the arguments to verbose() (bsc#1098425)

  - Fix kABI breakage of iio_buffer in 4.4.139
    (stable-4.4.139).

  - HID: debug: check length before copy_to_user()
    (bnc#1012382).

  - HID: hiddev: fix potential Spectre v1 (bnc#1012382).

  - HID: i2c-hid: Fix 'incomplete report' noise
    (bnc#1012382).

  - Hang/soft lockup in d_invalidate with simultaneous calls
    (bsc#1094248, bsc@1097140).

  - IB/qib: Fix DMA api warning with debug kernel
    (bnc#1012382).

  - Input: elan_i2c - add ELAN0618 (Lenovo v330 15IKB) ACPI
    ID (bnc#1012382).

  - Input: elan_i2c_smbus - fix more potential stack-based
    buffer overflows (bnc#1012382).

  - Input: elantech - enable middle button of touchpads on
    ThinkPad P52 (bnc#1012382).

  - Input: elantech - fix V4 report decoding for module with
    middle key (bnc#1012382).

  - MIPS: BCM47XX: Enable 74K Core ExternalSync for PCIe
    erratum (bnc#1012382).

  - MIPS: io: Add barrier after register read in inX()
    (bnc#1012382).

  - NFSv4: Fix possible 1-byte stack overflow in
    nfs_idmap_read_and_verify_message (bnc#1012382).

  - PCI: pciehp: Clear Presence Detect and Data Link Layer
    Status Changed on resume (bnc#1012382).

  - RDMA/mlx4: Discard unknown SQP work requests
    (bnc#1012382).

  - Refresh with upstream commit:62290a5c194b since the typo
    fix has been merged in upstream. (bsc#1085185)

  - Remove broken patches for dac9063 watchdog (bsc#1100843)

  - Revert 'Btrfs: fix scrub to repair raid6 corruption'
    (bnc#1012382).

  - Revert 'kvm: nVMX: Enforce cpl=0 for VMX instructions
    (bsc#1099183).' This turned out to be superfluous for
    4.4.x kernels.

  - Revert 'scsi: lpfc: Fix 16gb hbas failing cq create
    (bsc#1089525).' This reverts commit
    b054499f7615e2ffa7571ac0d05c7d5c9a8c0327.

  - UBIFS: Fix potential integer overflow in allocation
    (bnc#1012382).

  - USB: serial: cp210x: add CESINEL device ids
    (bnc#1012382).

  - USB: serial: cp210x: add Silicon Labs IDs for Windows
    Update (bnc#1012382).

  - Update
    patches.fixes/nvme-expand-nvmf_check_if_ready-checks.pat
    ch (bsc#1098527).

  - ath10k: fix rfc1042 header retrieval in QCA4019 with eth
    decap mode (bnc#1012382).

  - atm: zatm: fix memcmp casting (bnc#1012382).

  - backlight: as3711_bl: Fix Device Tree node lookup
    (bnc#1012382).

  - backlight: max8925_bl: Fix Device Tree node lookup
    (bnc#1012382).

  - backlight: tps65217_bl: Fix Device Tree node lookup
    (bnc#1012382).

  - bcache: Add __printf annotation to __bch_check_keys()
    (bsc#1064232).

  - bcache: Annotate switch fall-through (bsc#1064232).

  - bcache: Fix a compiler warning in bcache_device_init()
    (bsc#1064232).

  - bcache: Fix indentation (bsc#1064232).

  - bcache: Fix kernel-doc warnings (bsc#1064232).

  - bcache: Fix, improve efficiency of closure_sync()
    (bsc#1076110).

  - bcache: Reduce the number of sparse complaints about
    lock imbalances (bsc#1064232).

  - bcache: Remove an unused variable (bsc#1064232).

  - bcache: Suppress more warnings about set-but-not-used
    variables (bsc#1064232).

  - bcache: Use PTR_ERR_OR_ZERO() (bsc#1076110).

  - bcache: add CACHE_SET_IO_DISABLE to struct cache_set
    flags (bsc#1064232).

  - bcache: add backing_request_endio() for bi_end_io
    (bsc#1064232).

  - bcache: add io_disable to struct cached_dev
    (bsc#1064232).

  - bcache: add journal statistic (bsc#1076110).

  - bcache: add stop_when_cache_set_failed option to backing
    device (bsc#1064232).

  - bcache: add wait_for_kthread_stop() in
    bch_allocator_thread() (bsc#1064232).

  - bcache: closures: move control bits one bit right
    (bsc#1076110).

  - bcache: correct flash only vols (check all uuids)
    (bsc#1064232).

  - bcache: count backing device I/O error for writeback I/O
    (bsc#1064232).

  - bcache: fix cached_dev->count usage for
    bch_cache_set_error() (bsc#1064232).

  - bcache: fix crashes in duplicate cache device register
    (bsc#1076110).

  - bcache: fix error return value in memory shrink
    (bsc#1064232).

  - bcache: fix high CPU occupancy during journal
    (bsc#1076110).

  - bcache: fix inaccurate io state for detached bcache
    devices (bsc#1064232).

  - bcache: fix incorrect sysfs output value of strip size
    (bsc#1064232).

  - bcache: fix misleading error message in
    bch_count_io_errors() (bsc#1064232).

  - bcache: fix using of loop variable in memory shrink
    (bsc#1064232).

  - bcache: fix writeback target calc on large devices
    (bsc#1076110).

  - bcache: fix wrong return value in bch_debug_init()
    (bsc#1076110).

  - bcache: mark closure_sync() __sched (bsc#1076110).

  - bcache: move closure debug file into debug directory
    (bsc#1064232).

  - bcache: reduce cache_set devices iteration by
    devices_max_used (bsc#1064232).

  - bcache: ret IOERR when read meets metadata error
    (bsc#1076110).

  - bcache: return 0 from bch_debug_init() if
    CONFIG_DEBUG_FS=n (bsc#1064232).

  - bcache: set CACHE_SET_IO_DISABLE in
    bch_cached_dev_error() (bsc#1064232).

  - bcache: set dc->io_disable to true in
    conditional_stop_bcache_device() (bsc#1064232).

  - bcache: set error_limit correctly (bsc#1064232).

  - bcache: set writeback_rate_update_seconds in range [1,
    60] seconds (bsc#1064232).

  - bcache: stop bcache device when backing device is
    offline (bsc#1064232).

  - bcache: stop dc->writeback_rate_update properly
    (bsc#1064232).

  - bcache: stop writeback thread after detaching
    (bsc#1076110).

  - bcache: store disk name in struct cache and struct
    cached_dev (bsc#1064232).

  - bcache: use pr_info() to inform duplicated
    CACHE_SET_IO_DISABLE set (bsc#1064232).

  - block: Fix transfer when chunk sectors exceeds max
    (bnc#1012382).

  - bonding: re-evaluate force_primary when the primary
    slave name changes (bnc#1012382).

  - bpf: properly enforce index mask to prevent
    out-of-bounds speculation (bsc#1098425).

  - branch-check: fix long->int truncation when profiling
    branches (bnc#1012382).

  - cdc_ncm: avoid padding beyond end of skb (bnc#1012382).

  - ceph: fix dentry leak in splice_dentry() (bsc#1098236).

  - ceph: fix use-after-free in ceph_statfs() (bsc#1098236).

  - ceph: fix wrong check for the case of updating link
    count (bsc#1098236).

  - ceph: prevent i_version from going back (bsc#1098236).

  - ceph: support file lock on directory (bsc#1098236).

  - cifs: Check for timeout on Negotiate stage
    (bsc#1091171).

  - cifs: Fix infinite loop when using hard mount option
    (bnc#1012382).

  - cpufreq: Fix new policy initialization during limits
    updates via sysfs (bnc#1012382).

  - cpuidle: powernv: Fix promotion from snooze if next
    state disabled (bnc#1012382).

  - dm thin: handle running out of data space vs concurrent
    discard (bnc#1012382).

  - dm: convert DM printk macros to pr_ level macros
    (bsc#1099918).

  - dm: fix printk() rate limiting code (bsc#1099918).

  - drbd: fix access after free (bnc#1012382).

  - driver core: Do not ignore class_dir_create_and_add()
    failure (bnc#1012382).

  - e1000e: Ignore TSYNCRXCTL when getting I219 clock
    attributes (bsc#1075876).

  - ext4: add more inode number paranoia checks
    (bnc#1012382).

  - ext4: add more mount time checks of the superblock
    (bnc#1012382).

  - ext4: always check block group bounds in
    ext4_init_block_bitmap() (bnc#1012382).

  - ext4: check superblock mapped prior to committing
    (bnc#1012382).

  - ext4: clear i_data in ext4_inode_info when removing
    inline data (bnc#1012382).

  - ext4: fix fencepost error in check for inode count
    overflow during resize (bnc#1012382).

  - ext4: fix unsupported feature message formatting
    (bsc#1098435).

  - ext4: include the illegal physical block in the bad map
    ext4_error msg (bnc#1012382).

  - ext4: make sure bitmaps and the inode table do not
    overlap with bg descriptors (bnc#1012382).

  - ext4: only look at the bg_flags field if it is valid
    (bnc#1012382).

  - ext4: update mtime in ext4_punch_hole even if no blocks
    are released (bnc#1012382).

  - ext4: verify the depth of extent tree in
    ext4_find_extent() (bnc#1012382).

  - fs/binfmt_misc.c: do not allow offset overflow
    (bsc#1099279).

  - fuse: atomic_o_trunc should truncate pagecache
    (bnc#1012382).

  - fuse: do not keep dead fuse_conn at fuse_fill_super()
    (bnc#1012382).

  - fuse: fix control dir setup and teardown (bnc#1012382).

  - hv_netvsc: avoid repeated updates of packet filter
    (bsc#1097492).

  - hv_netvsc: defer queue selection to VF (bsc#1097492).

  - hv_netvsc: enable multicast if necessary (bsc#1097492).

  - hv_netvsc: filter multicast/broadcast (bsc#1097492).

  - hv_netvsc: fix filter flags (bsc#1097492).

  - hv_netvsc: fix locking during VF setup (bsc#1097492).

  - hv_netvsc: fix locking for rx_mode (bsc#1097492).

  - hv_netvsc: propagate rx filters to VF (bsc#1097492).

  - i2c: rcar: fix resume by always initializing registers
    before transfer (bnc#1012382).

  - iio:buffer: make length types match kfifo types
    (bnc#1012382).

  - iommu/vt-d: Fix race condition in add_unmap()
    (bsc#1096790, bsc#1097034).

  - ipmi:bt: Set the timeout before doing a capabilities
    check (bnc#1012382).

  - ipv4: Fix error return value in fib_convert_metrics()
    (bnc#1012382).

  - ipvs: fix buffer overflow with sync daemon and service
    (bnc#1012382).

  - iwlmvm: tdls: Check TDLS channel switch support
    (bsc#1099810).

  - iwlwifi: fix non_shared_ant for 9000 devices
    (bsc#1099810).

  - jbd2: do not mark block as modified if the handle is out
    of credits (bnc#1012382).

  - kabi/severities: add 'drivers/md/bcache/* PASS' since no
    one uses symboles expoted by bcache.

  - kmod: fix wait on recursive loop (bsc#1099792).

  - kmod: reduce atomic operations on kmod_concurrent and
    simplify (bsc#1099792).

  - kmod: throttle kmod thread limit (bsc#1099792).

  - kprobes/x86: Do not modify singlestep buffer while
    resuming (bnc#1012382).

  - kvm: nVMX: Enforce cpl=0 for VMX instructions
    (bsc#1099183).

  - lib/vsprintf: Remove atomic-unsafe support for %pCr
    (bnc#1012382).

  - libata: Drop SanDisk SD7UB3Q*G1001 NOLPM quirk
    (bnc#1012382).

  - libata: zpodd: make arrays cdb static, reduces object
    code size (bnc#1012382).

  - libata: zpodd: small read overflow in eject_tray()
    (bnc#1012382).

  - linvdimm, pmem: Preserve read-only setting for pmem
    devices (bnc#1012382).

  - m68k/mm: Adjust VM area to be unmapped by gap size for
    __iounmap() (bnc#1012382).

  - mac80211: Fix condition validating WMM IE
    (bsc#1099810,bsc#1099732).

  - media: cx231xx: Add support for AverMedia DVD EZMaker 7
    (bnc#1012382).

  - media: cx25840: Use subdev host data for PLL override
    (bnc#1012382).

  - media: dvb_frontend: fix locking issues at
    dvb_frontend_get_event() (bnc#1012382).

  - media: smiapp: fix timeout checking in smiapp_read_nvm
    (bsc#1099918).

  - media: v4l2-compat-ioctl32: prevent go past max size
    (bnc#1012382).

  - mfd: intel-lpss: Program REMAP register in PIO mode
    (bnc#1012382).

  - mips: ftrace: fix static function graph tracing
    (bnc#1012382).

  - mm: hugetlb: yield when prepping struct pages
    (bnc#1012382).

  - mtd: cfi_cmdset_0002: Avoid walking all chips when
    unlocking (bnc#1012382).

  - mtd: cfi_cmdset_0002: Change definition naming to retry
    write operation (bnc#1012382).

  - mtd: cfi_cmdset_0002: Change erase functions to check
    chip good only (bnc#1012382).

  - mtd: cfi_cmdset_0002: Change erase functions to retry
    for error (bnc#1012382).

  - mtd: cfi_cmdset_0002: Change write buffer to check
    correct value (bnc#1012382).

  - mtd: cfi_cmdset_0002: Fix unlocking requests crossing a
    chip boudary (bnc#1012382).

  - mtd: cfi_cmdset_0002: Use right chip in do_ppb_xxlock()
    (bnc#1012382).

  - mtd: cfi_cmdset_0002: fix SEGV unlocking multiple chips
    (bnc#1012382).

  - mtd: cmdlinepart: Update comment for introduction of
    OFFSET_CONTINUOUS (bsc#1099918).

  - mtd: partitions: add helper for deleting partition
    (bsc#1099918).

  - mtd: partitions: remove sysfs files when deleting all
    master's partitions (bsc#1099918).

  - mtd: rawnand: mxc: set spare area size register
    explicitly (bnc#1012382).

  - n_tty: Access echo_* variables carefully (bnc#1012382).

  - n_tty: Fix stall at n_tty_receive_char_special()
    (bnc#1012382).

  - net/sonic: Use dma_mapping_error() (bnc#1012382).

  - net: qmi_wwan: Add Netgear Aircard 779S (bnc#1012382).

  - netfilter: ebtables: handle string from userspace with
    care (bnc#1012382).

  - netfilter: nf_log: do not hold nf_log_mutex during user
    access (bnc#1012382).

  - netfilter: nf_tables: use WARN_ON_ONCE instead of BUG_ON
    in nft_do_chain() (bnc#1012382).

  - nfsd: restrict rd_maxcount to svc_max_payload in
    nfsd_encode_readdir (bnc#1012382).

  - nvme-fabrics: allow duplicate connections to the
    discovery controller (bsc#1098527).

  - nvme-fabrics: allow internal passthrough command on
    deleting controllers (bsc#1098527).

  - nvme-fabrics: centralize discovery controller defaults
    (bsc#1098527).

  - nvme-fabrics: fix and refine state checks in
    __nvmf_check_ready (bsc#1098527).

  - nvme-fabrics: refactor queue ready check (bsc#1098527).

  - nvme-fc: change controllers first connect to use
    reconnect path (bsc#1098527).

  - nvme-fc: fix nulling of queue data on reconnect
    (bsc#1098527).

  - nvme-fc: remove reinit_request routine (bsc#1098527).

  - nvme-fc: remove setting DNR on exception conditions
    (bsc#1098527).

  - nvme-pci: initialize queue memory before interrupts
    (bnc#1012382).

  - nvme: allow duplicate controller if prior controller
    being deleted (bsc#1098527).

  - nvme: move init of keep_alive work item to controller
    initialization (bsc#1098527).

  - nvme: reimplement nvmf_check_if_ready() to avoid kabi
    breakage (bsc#1098527).

  - nvmet-fc: increase LS buffer count per fc port
    (bsc#1098527).

  - nvmet: switch loopback target state to connecting when
    resetting (bsc#1098527).

  - of: unittest: for strings, account for trailing \0 in
    property length field (bnc#1012382).

  - ovl: fix random return value on mount (bsc#1099993).

  - ovl: fix uid/gid when creating over whiteout
    (bsc#1099993).

  - ovl: override creds with the ones from the superblock
    mounter (bsc#1099993).

  - perf intel-pt: Fix 'Unexpected indirect branch' error
    (bnc#1012382).

  - perf intel-pt: Fix MTC timing after overflow
    (bnc#1012382).

  - perf intel-pt: Fix decoding to accept CBR between FUP
    and corresponding TIP (bnc#1012382).

  - perf intel-pt: Fix packet decoding of CYC packets
    (bnc#1012382).

  - perf intel-pt: Fix sync_switch INTEL_PT_SS_NOT_TRACING
    (bnc#1012382).

  - perf tools: Fix symbol and object code resolution for
    vdso32 and vdsox32 (bnc#1012382).

  - platform/x86: thinkpad_acpi: Adding new hotkey ID for
    Lenovo thinkpad (bsc#1099810).

  - powerpc/64s: Exception macro for stack frame and initial
    register save (bsc#1094244).

  - powerpc/64s: Fix mce accounting for powernv
    (bsc#1094244).

  - powerpc/fadump: Unregister fadump on kexec down path
    (bnc#1012382).

  - powerpc/mm/hash: Add missing isync prior to kernel stack
    SLB switch (bnc#1012382).

  - powerpc/ptrace: Fix enforcement of DAWR constraints
    (bnc#1012382).

  - powerpc/ptrace: Fix setting 512B aligned breakpoints
    with PTRACE_SET_DEBUGREG (bnc#1012382).

  - powerpc: Machine check interrupt is a non-maskable
    interrupt (bsc#1094244).

  - procfs: add tunable for fd/fdinfo dentry retention
    (bsc#10866542).

  - qla2xxx: Fix NULL pointer derefrence for fcport search
    (bsc#1085657).

  - qla2xxx: Fix inconsistent DMA mem alloc/free
    (bsc#1085657).

  - qla2xxx: Fix kernel crash due to late workqueue
    allocation (bsc#1085657).

  - regulator: Do not return or expect -errno from
    of_map_mode() (bsc#1099042).

  - restore cond_resched() in shrink_dcache_parent()
    (bsc#1098599).

  - rmdir(),rename(): do shrink_dcache_parent() only on
    success (bsc#1100340).

  - s390/dasd: configurable IFCC handling (bsc#1097808).

  - s390: Correct register corruption in critical section
    cleanup (bnc#1012382).

  - sbitmap: check for valid bitmap in sbitmap_for_each
    (bsc#1090435).

  - sched/sysctl: Check user input value of
    sysctl_sched_time_avg (bsc#1100089).

  - scsi: ipr: Format HCAM overlay ID 0x41 (bsc#1097961).

  - scsi: ipr: new IOASC update (bsc#1097961).

  - scsi: lpfc: Change IO submit return to EBUSY if remote
    port is recovering (bsc#1092207).

  - scsi: lpfc: Driver NVME load fails when CPU cnt > WQ
    resource cnt (bsc#1092207).

  - scsi: lpfc: Fix 16gb hbas failing cq create
    (bsc#1089525).

  - scsi: lpfc: Fix 16gb hbas failing cq create
    (bsc#1095453).

  - scsi: lpfc: Fix MDS diagnostics failure (Rx lower than
    Tx) (bsc#1095453).

  - scsi: lpfc: Fix crash in blk_mq layer when executing
    modprobe -r lpfc (bsc#1095453).

  - scsi: lpfc: Fix port initialization failure
    (bsc#1095453).

  - scsi: lpfc: Fix up log messages and stats counters in IO
    submit code path (bsc#1092207).

  - scsi: lpfc: Handle new link fault code returned by
    adapter firmware (bsc#1092207).

  - scsi: lpfc: correct oversubscription of nvme io requests
    for an adapter (bsc#1095453).

  - scsi: lpfc: update driver version to 11.4.0.7-3
    (bsc#1092207).

  - scsi: lpfc: update driver version to 11.4.0.7-4
    (bsc#1095453).

  - scsi: qedi: Fix truncation of CHAP name and secret
    (bsc#1097931)

  - scsi: qla2xxx: Fix setting lower transfer speed if GPSC
    fails (bnc#1012382).

  - scsi: qla2xxx: Spinlock recursion in qla_target
    (bsc#1097501)

  - scsi: sg: mitigate read/write abuse (bsc#1101296).

  - scsi: zfcp: fix misleading REC trigger trace where
    erp_action setup failed (LTC#168765 bnc#1012382
    bnc#1099713).

  - scsi: zfcp: fix misleading REC trigger trace where
    erp_action setup failed (bnc#1099713, LTC#168765).

  - scsi: zfcp: fix missing REC trigger trace for all
    objects in ERP_FAILED (LTC#168765 bnc#1012382
    bnc#1099713).

  - scsi: zfcp: fix missing REC trigger trace for all
    objects in ERP_FAILED (bnc#1099713, LTC#168765).

  - scsi: zfcp: fix missing REC trigger trace on enqueue
    without ERP thread (LTC#168765 bnc#1012382 bnc#1099713).

  - scsi: zfcp: fix missing REC trigger trace on enqueue
    without ERP thread (bnc#1099713, LTC#168765).

  - scsi: zfcp: fix missing REC trigger trace on
    terminate_rport_io early return (LTC#168765 bnc#1012382
    bnc#1099713).

  - scsi: zfcp: fix missing REC trigger trace on
    terminate_rport_io early return (bnc#1099713,
    LTC#168765).

  - scsi: zfcp: fix missing REC trigger trace on
    terminate_rport_io for ERP_FAILED (LTC#168765
    bnc#1012382 bnc#1099713).

  - scsi: zfcp: fix missing REC trigger trace on
    terminate_rport_io for ERP_FAILED (bnc#1099713,
    LTC#168765).

  - scsi: zfcp: fix missing SCSI trace for result of
    eh_host_reset_handler (LTC#168765 bnc#1012382
    bnc#1099713).

  - scsi: zfcp: fix missing SCSI trace for result of
    eh_host_reset_handler (bnc#1099713, LTC#168765).

  - scsi: zfcp: fix missing SCSI trace for retry of abort /
    scsi_eh TMF (LTC#168765 bnc#1012382 bnc#1099713).

  - scsi: zfcp: fix missing SCSI trace for retry of abort /
    scsi_eh TMF (bnc#1099713, LTC#168765).

  - serial: sh-sci: Use spin_(try)lock_irqsave instead of
    open coding version (bnc#1012382).

  - signal/xtensa: Consistenly use SIGBUS in
    do_unaligned_user (bnc#1012382).

  - spi: Fix scatterlist elements size in spi_map_buf
    (bnc#1012382).

  - staging: android: ion: Return an ERR_PTR in
    ion_map_kernel (bnc#1012382).

  - staging: comedi: quatech_daqp_cs: fix no-op loop
    daqp_ao_insn_write() (bnc#1012382).

  - tcp: do not overshoot window_clamp in
    tcp_rcv_space_adjust() (bnc#1012382).

  - tcp: verify the checksum of the first data segment in a
    new connection (bnc#1012382).

  - thinkpad_acpi: Add support for HKEY version 0x200
    (bsc#1099810).

  - time: Make sure jiffies_to_msecs() preserves non-zero
    time periods (bnc#1012382).

  - tracing: Fix missing return symbol in function_graph
    output (bnc#1012382).

  - ubi: fastmap: Cancel work upon detach (bnc#1012382).

  - ubi: fastmap: Correctly handle interrupted erasures in
    EBA (bnc#1012382).

  - udf: Detect incorrect directory size (bnc#1012382).

  - usb: cdc_acm: Add quirk for Uniden UBC125 scanner
    (bnc#1012382).

  - usb: do not reset if a low-speed or full-speed device
    timed out (bnc#1012382).

  - usb: musb: fix remote wakeup racing with suspend
    (bnc#1012382).

  - video/fbdev/stifb: Return -ENOMEM after a failed
    kzalloc() in stifb_init_fb() (bsc#1090888 bsc#1099966).

  - video: uvesafb: Fix integer overflow in allocation
    (bnc#1012382).

  - w1: mxc_w1: Enable clock before calling clk_get_rate()
    on it (bnc#1012382).

  - wait: add wait_event_killable_timeout() (bsc#1099792).

  - watchdog: da9063: Fix setting/changing timeout
    (bsc#1100843).

  - watchdog: da9063: Fix timeout handling during probe
    (bsc#1100843).

  - watchdog: da9063: Fix updating timeout value
    (bsc#1100843).

  - x86/cpu/amd: Derive L3 shared_cpu_map from
    cpu_llc_shared_mask (bsc#1094643).

  - x86/mce: Fix incorrect 'Machine check from unknown
    source' message (bnc#1012382).

  - x86/mce: Improve error message when kernel cannot
    recover (git-fixes b2f9d678e28c).

  - x86/pti: do not report XenPV as vulnerable
    (bsc#1097551).

  - xen: Remove unnecessary BUG_ON from __unbind_from_irq()
    (bnc#1012382).

  - xfrm6: avoid potential infinite loop in
    _decode_session6() (bnc#1012382).

  - xfrm: Ignore socket policies when rebuilding hash tables
    (bnc#1012382).

  - xfrm: skip policies marked as dead while rehashing
    (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101296"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.140-62.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.140-62.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.140-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.140-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-debuginfo-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-4.4.140-62.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-debuginfo-4.4.140-62.2") ) flag++;

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
