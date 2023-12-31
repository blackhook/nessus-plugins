#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-656.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110658);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13305", "CVE-2017-17741", "CVE-2017-18241", "CVE-2017-18249", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-1094", "CVE-2018-12233", "CVE-2018-3639", "CVE-2018-3665", "CVE-2018-5848");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-656) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-656 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 was updated to 4.4.138 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-3639: Systems with microprocessors utilizing
    speculative execution and speculative execution of
    memory reads before the addresses of all prior memory
    writes are known may allow unauthorized disclosure of
    information to an attacker with local user access via a
    side-channel analysis, aka Speculative Store Bypass
    (SSB), Variant 4 (bsc#1085308 bsc#1087082) This update
    improves the previous Spectre Variant 4 fixes and also
    mitigates them on the ARM architecture.

  - CVE-2018-3665: The FPU state and registers of x86 CPUs
    were saved and restored in a lazy fashion, which opened
    its disclosure by speculative side channel attacks. This
    has been fixed by replacing the lazy save/restore by
    eager saving and restoring (bnc#1087086)

  - CVE-2018-5848: In the function wmi_set_ie(), the length
    validation code did not handle unsigned integer overflow
    properly. As a result, a large value of the 'ie_len'
    argument can cause a buffer overflow (bnc#1097356).

  - CVE-2017-18249: The add_free_nid function in
    fs/f2fs/node.c did not properly track an allocated nid,
    which allowed local users to cause a denial of service
    (race condition) or possibly have unspecified other
    impact via concurrent threads (bnc#1087036).

  - CVE-2017-18241: fs/f2fs/segment.c kernel allowed local
    users to cause a denial of service (NULL pointer
    dereference and panic) by using a noflush_merge option
    that triggers a NULL value for a flush_cmd_control data
    structure (bnc#1086400).

  - CVE-2017-17741: The KVM implementation allowed attackers
    to obtain potentially sensitive information from kernel
    memory, aka a write_mmio stack-based out-of-bounds read,
    related to arch/x86/kvm/x86.c and
    include/trace/events/kvm.h (bnc#1073311 1091815).

  - CVE-2017-13305: A information disclosure vulnerability
    in the encrypted-keys. (bnc#1094353).

  - CVE-2018-1093: The ext4_valid_block_bitmap function in
    fs/ext4/balloc.c allowed attackers to cause a denial of
    service (out-of-bounds read and system crash) via a
    crafted ext4 image because balloc.c and ialloc.c do not
    validate bitmap block numbers (bnc#1087095).

  - CVE-2018-1094: The ext4_fill_super function in
    fs/ext4/super.c did not always initialize the crc32c
    checksum driver, which allowed attackers to cause a
    denial of service (ext4_xattr_inode_hash NULL pointer
    dereference and system crash) via a crafted ext4 image
    (bnc#1087007 1092903).

  - CVE-2018-1092: The ext4_iget function in fs/ext4/inode.c
    mishandled the case of a root directory with a zero
    i_links_count, which allowed attackers to cause a denial
    of service (ext4_process_freed_data NULL pointer
    dereference and OOPS) via a crafted ext4 image
    (bnc#1087012).

  - CVE-2018-12233: In the ea_get function in
    fs/jfs/xattr.c, a memory corruption bug in JFS could be
    triggered by calling setxattr twice with two different
    extended attribute names on the same file. This
    vulnerability can be triggered by an unprivileged user
    with the ability to create files and execute programs. A
    kmalloc call is incorrect, leading to slab-out-of-bounds
    in jfs_xattr. (bsc#1097234)

The following non-security bugs were fixed :

  - 8139too: Use disable_irq_nosync() in
    rtl8139_poll_controller() (bnc#1012382).

  - acpi: acpi_pad: Fix memory leak in power saving threads
    (bnc#1012382).

  - acpica: acpi: acpica: fix acpi operand cache leak in
    nseval.c (bnc#1012382).

  - acpica: Events: add a return on failure from
    acpi_hw_register_read (bnc#1012382).

  - acpi: processor_perflib: Do not send _PPC change
    notification if not ready (bnc#1012382).

  - affs_lookup(): close a race with affs_remove_link()
    (bnc#1012382).

  - aio: fix io_destroy(2) vs. lookup_ioctx() race
    (bnc#1012382).

  - alsa: control: fix a redundant-copy issue (bnc#1012382).

  - alsa: hda: Add Lenovo C50 All in one to the power_save
    blacklist (bnc#1012382).

  - alsa: hda - Use IS_REACHABLE() for dependency on input
    (bnc#1012382 bsc#1031717).

  - alsa: timer: Call notifier in the same spinlock
    (bnc#1012382 bsc#973378).

  - alsa: timer: Fix pause event notification (bnc#1012382
    bsc#973378).

  - alsa: timer: Fix pause event notification (bsc#973378).

  - alsa: usb: mixer: volume quirk for CM102-A+/102S+
    (bnc#1012382).

  - alsa: vmaster: Propagate slave error (bnc#1012382).

  - arc: Fix malformed ARC_EMUL_UNALIGNED default
    (bnc#1012382).

  - arm64: Add ARCH_WORKAROUND_2 probing (bsc#1085308).

  - arm64: Add per-cpu infrastructure to call
    ARCH_WORKAROUND_2 (bsc#1085308).

  - arm64: Add 'ssbd' command-line option (bsc#1085308).

  - arm64: Add this_cpu_ptr() assembler macro for use in
    entry.S (bsc#1085308).

  - arm64: Add work around for Arm Cortex-A55 Erratum
    1024718 (bnc#1012382).

  - arm64: alternatives: Add dynamic patching feature
    (bsc#1085308).

  - arm64: assembler: introduce ldr_this_cpu (bsc#1085308).

  - arm64: Call ARCH_WORKAROUND_2 on transitions between EL0
    and EL1 (bsc#1085308).

  - arm64: do not call C code with el0's fp register
    (bsc#1085308).

  - arm64: fix endianness annotation for
    __apply_alternatives()/get_alt_insn() (bsc#1085308).

  - arm64: introduce mov_q macro to move a constant into a
    64-bit register (bnc#1012382 bsc#1068032).

  - arm64: lse: Add early clobbers to some input/output asm
    operands (bnc#1012382).

  - arm64: spinlock: Fix theoretical trylock() A-B-A with
    LSE atomics (bnc#1012382).

  - arm64: ssbd: Add global mitigation state accessor
    (bsc#1085308).

  - arm64: ssbd: Add prctl interface for per-thread
    mitigation (bsc#1085308).

  - arm64: ssbd: Introduce thread flag to control userspace
    mitigation (bsc#1085308).

  - arm64: ssbd: Restore mitigation status on CPU resume
    (bsc#1085308).

  - arm64: ssbd: Skip apply_ssbd if not using dynamic
    mitigation (bsc#1085308).

  - arm: 8748/1: mm: Define vdso_start, vdso_end as array
    (bnc#1012382).

  - arm: 8769/1: kprobes: Fix to use get_kprobe_ctlblk after
    irq-disabed (bnc#1012382).

  - arm: 8770/1: kprobes: Prohibit probing on
    optimized_callback (bnc#1012382).

  - arm: 8771/1: kprobes: Prohibit kprobes on do_undefinstr
    (bnc#1012382).

  - arm: 8772/1: kprobes: Prohibit kprobes on get_user
    functions (bnc#1012382).

  - arm/arm64: smccc: Add SMCCC-specific return codes
    (bsc#1085308).

  - arm: dts: socfpga: fix GIC PPI warning (bnc#1012382).

  - arm: OMAP1: clock: Fix debugfs_create_*() usage
    (bnc#1012382).

  - arm: OMAP2+: timer: fix a kmemleak caused in
    omap_get_timer_dt (bnc#1012382).

  - arm: OMAP3: Fix prm wake interrupt for resume
    (bnc#1012382).

  - arm: OMAP: Fix dmtimer init for omap1 (bnc#1012382).

  - asm-generic: provide generic_pmdp_establish()
    (bnc#1012382).

  - ASoC: au1x: Fix timeout tests in au1xac97c_ac97_read()
    (bnc#1012382 bsc#1031717).

  - ASoC: Intel: sst: remove redundant variable dma_dev_name
    (bnc#1012382).

  - ASoC: samsung: i2s: Ensure the RCLK rate is properly
    determined (bnc#1012382).

  - ASoC: topology: create TLV data for dapm widgets
    (bnc#1012382).

  - ath10k: Fix kernel panic while using worker
    (ath10k_sta_rc_update_wk) (bnc#1012382).

  - audit: move calcs after alloc and check when logging set
    loginuid (bnc#1012382).

  - audit: return on memory error to avoid NULL pointer
    dereference (bnc#1012382).

  - autofs: change autofs4_expire_wait()/do_expire_wait() to
    take struct path (bsc#1086716).

  - autofs: change autofs4_wait() to take struct path
    (bsc#1086716).

  - autofs: use path_has_submounts() to fix unreliable
    have_submount() checks (bsc#1086716).

  - autofs: use path_is_mountpoint() to fix unreliable
    d_mountpoint() checks (bsc#1086716).

  - batman-adv: fix header size check in batadv_dbg_arp()
    (bnc#1012382).

  - batman-adv: fix multicast-via-unicast transmission with
    AP isolation (bnc#1012382).

  - batman-adv: fix packet checksum in receive path
    (bnc#1012382).

  - batman-adv: fix packet loss for broadcasted DHCP packets
    to a server (bnc#1012382).

  - batman-adv: invalidate checksum on fragment reassembly
    (bnc#1012382).

  - bcache: fix for allocator and register thread race
    (bnc#1012382).

  - bcache: fix for data collapse after re-attaching an
    attached device (bnc#1012382).

  - bcache: fix kcrashes with fio in RAID5 backend dev
    (bnc#1012382).

  - bcache: properly set task state in
    bch_writeback_thread() (bnc#1012382).

  - bcache: quit dc->writeback_thread when
    BCACHE_DEV_DETACHING is set (bnc#1012382).

  - bcache: return attach error when no cache set exist
    (bnc#1012382).

  - blacklist.conf: blacklist fc218544fbc8 This commit
    requires major changes from 4.17, namely commit
    b9e281c2b388 ('libceph: introduce BVECS data type')

  - blacklist.conf: No need for 0aa48468d009 ('KVM/VMX:
    Expose SSBD properly to guests') since KF(SSBD) in our
    case does the expected.

  - block: cancel workqueue entries on blk_mq_freeze_queue()
    (bsc#1090435).

  - bluetooth: Apply QCA Rome patches for some ATH3012
    models (bsc#1082504, bsc#1095147).

  - bluetooth: btusb: Add device ID for RTL8822BE
    (bnc#1012382).

  - bluetooth: btusb: Add USB ID 7392:a611 for Edimax
    EW-7611ULB (bnc#1012382).

  - bnxt_en: Check valid VNIC ID in bnxt_hwrm_vnic_set_tpa()
    (bnc#1012382).

  - bonding: do not allow rlb updates to invalid mac
    (bnc#1012382).

  - bpf: fix selftests/bpf test_kmod.sh failure when
    CONFIG_BPF_JIT_ALWAYS_ON=y (bnc#1012382).

  - bridge: check iface upper dev when setting master via
    ioctl (bnc#1012382).

  - btrfs: bail out on error during replay_dir_deletes
    (bnc#1012382).

  - btrfs: fix copy_items() return value when logging an
    inode (bnc#1012382).

  - btrfs: fix crash when trying to resume balance without
    the resume flag (bnc#1012382).

  - btrfs: fix lockdep splat in
    btrfs_alloc_subvolume_writers (bnc#1012382).

  - btrfs: fix NULL pointer dereference in log_dir_items
    (bnc#1012382).

  - btrfs: Fix out of bounds access in btrfs_search_slot
    (bnc#1012382).

  - btrfs: Fix possible softlock on single core machines
    (bnc#1012382).

  - btrfs: fix reading stale metadata blocks after degraded
    raid1 mounts (bnc#1012382).

  - btrfs: fix scrub to repair raid6 corruption
    (bnc#1012382).

  - btrfs: fix xattr loss after power failure (bnc#1012382).

  - btrfs: send, fix issuing write op when processing hole
    in no data mode (bnc#1012382).

  - btrfs: set plug for fsync (bnc#1012382).

  - btrfs: tests/qgroup: Fix wrong tree backref level
    (bnc#1012382).

  - cdrom: do not call check_disk_change() inside
    cdrom_open() (bnc#1012382).

  - ceph: delete unreachable code in ceph_check_caps()
    (bsc#1096214).

  - ceph: fix race of queuing delayed caps (bsc#1096214).

  - ceph: fix st_nlink stat for directories (bsc#1093904).

  - cfg80211: further limit wiphy names to 64 bytes
    (bnc#1012382 git-fixes).

  - cfg80211: further limit wiphy names to 64 bytes
    (git-fixes).

  - cfg80211: limit wiphy names to 128 bytes (bnc#1012382).

  - cifs: silence compiler warnings showing up with
    gcc-8.0.0 (bnc#1012382 bsc#1090734).

  - clk: Do not show the incorrect clock phase
    (bnc#1012382).

  - clk: rockchip: Prevent calculating mmc phase if clock
    rate is zero (bnc#1012382).

  - clk: samsung: exynos3250: Fix PLL rates (bnc#1012382).

  - clk: samsung: exynos5250: Fix PLL rates (bnc#1012382).

  - clk: samsung: exynos5260: Fix PLL rates (bnc#1012382).

  - clk: samsung: exynos5433: Fix PLL rates (bnc#1012382).

  - clk: samsung: s3c2410: Fix PLL rates (bnc#1012382).

  - clocksource/drivers/fsl_ftm_timer: Fix error return
    checking (bnc#1012382).

  - config: arm64: enable Spectre-v4 per-thread mitigation

  - cpufreq: cppc_cpufreq: Fix cppc_cpufreq_init() failure
    path (bnc#1012382).

  - cpufreq: CPPC: Initialize shared perf capabilities of
    CPUs (bnc#1012382).

  - cpufreq: intel_pstate: Enable HWP by default
    (FATE#319178 bnc#1012382).

  - cpuidle: coupled: remove unused define
    cpuidle_coupled_lock (bnc#1012382).

  - crypto: sunxi-ss - Add MODULE_ALIAS to sun4i-ss
    (bnc#1012382).

  - cxgb4: Setup FW queues before registering netdev
    (bsc#1022743 FATE#322540).

  - dccp: fix tasklet usage (bnc#1012382).

  - dlm: fix a clerical error when set SCTP_NODELAY
    (bsc#1091594).

  - dlm: make sctp_connect_to_sock() return in specified
    time (bsc#1080542).

  - dlm: remove O_NONBLOCK flag in sctp_connect_to_sock
    (bsc#1080542).

  - dmaengine: ensure dmaengine helpers check valid callback
    (bnc#1012382).

  - dmaengine: pl330: fix a race condition in case of
    threaded irqs (bnc#1012382).

  - dmaengine: rcar-dmac: fix max_chunk_size for R-Car Gen3
    (bnc#1012382).

  - dmaengine: usb-dmac: fix endless loop in
    usb_dmac_chan_terminate_all() (bnc#1012382).

  - dm thin: fix documentation relative to low water mark
    threshold (bnc#1012382).

  - do d_instantiate/unlock_new_inode combinations safely
    (bnc#1012382).

  - dp83640: Ensure against premature access to PHY
    registers after reset (bnc#1012382).

  - drm/exynos: fix comparison to bitshift when dealing with
    a mask (bnc#1012382).

  - drm/i915: Disable LVDS on Radiant P845 (bnc#1012382).

  - drm/rockchip: Respect page offset for PRIME mmap calls
    (bnc#1012382).

  - e1000e: allocate ring descriptors with
    dma_zalloc_coherent (bnc#1012382).

  - e1000e: Fix check_for_link return value with autoneg off
    (bnc#1012382 bsc#1075428).

  - efi: Avoid potential crashes, fix the 'struct
    efi_pci_io_protocol_32' definition for mixed mode
    (bnc#1012382).

  - enic: enable rq before updating rq descriptors
    (bnc#1012382).

  - ext2: fix a block leak (bnc#1012382).

  - fbdev: Fixing arbitrary kernel leak in case
    FBIOGETCMAP_SPARC in sbusfb_ioctl_helper()
    (bnc#1012382).

  - firewire-ohci: work around oversized DMA reads on
    JMicron controllers (bnc#1012382).

  - firmware: dmi_scan: Fix handling of empty DMI strings
    (bnc#1012382).

  - Fix excessive newline in /proc/*/status (bsc#1094823).

  - fix io_destroy()/aio_complete() race (bnc#1012382).

  - Force log to disk before reading the AGF during a fstrim
    (bnc#1012382).

  - fscache: Fix hanging wait on page discarded by writeback
    (bnc#1012382).

  - fs/proc/proc_sysctl.c: fix potential page fault while
    unregistering sysctl table (bnc#1012382).

  - futex: futex_wake_op, do not fail on invalid op
    (git-fixes).

  - futex: futex_wake_op, fix sign_extend32 sign bits
    (bnc#1012382).

  - futex: Remove duplicated code and fix undefined
    behaviour (bnc#1012382).

  - futex: Remove unnecessary warning from get_futex_key
    (bnc#1012382).

  - gfs2: Fix fallocate chunk size (bnc#1012382).

  - gianfar: Fix Rx byte accounting for ndev stats
    (bnc#1012382).

  - gpio: rcar: Add Runtime PM handling for interrupts
    (bnc#1012382).

  - hfsplus: stop workqueue when fill_super() failed
    (bnc#1012382).

  - hid: roccat: prevent an out of bounds read in
    kovaplus_profile_activated() (bnc#1012382).

  - hwmon: (nct6775) Fix writing pwmX_mode (bnc#1012382).

  - hwmon: (pmbus/adm1275) Accept negative page register
    values (bnc#1012382).

  - hwmon: (pmbus/max8688) Accept negative page register
    values (bnc#1012382).

  - hwrng: stm32 - add reset during probe (bnc#1012382).

  - hwtracing: stm: fix build error on some arches
    (bnc#1012382).

  - i2c: mv64xxx: Apply errata delay only in standard mode
    (bnc#1012382).

  - i2c: rcar: check master irqs before slave irqs
    (bnc#1012382).

  - i2c: rcar: do not issue stop when HW does it
    automatically (bnc#1012382).

  - i2c: rcar: init new messages in irq (bnc#1012382).

  - i2c: rcar: make sure clocks are on when doing clock
    calculation (bnc#1012382).

  - i2c: rcar: refactor setup of a msg (bnc#1012382).

  - i2c: rcar: remove spinlock (bnc#1012382).

  - i2c: rcar: remove unused IOERROR state (bnc#1012382).

  - i2c: rcar: revoke START request early (bnc#1012382).

  - i2c: rcar: rework hw init (bnc#1012382).

  - ib/ipoib: Fix for potential no-carrier state
    (bnc#1012382).

  - ibmvnic: Check CRQ command return codes (bsc#1094840).

  - ibmvnic: Create separate initialization routine for
    resets (bsc#1094840).

  - ibmvnic: Fix partial success login retries
    (bsc#1094840).

  - ibmvnic: Handle error case when setting link state
    (bsc#1094840).

  - ibmvnic: Introduce active CRQ state (bsc#1094840).

  - ibmvnic: Introduce hard reset recovery (bsc#1094840).

  - ibmvnic: Mark NAPI flag as disabled when released
    (bsc#1094840).

  - ibmvnic: Only do H_EOI for mobility events
    (bsc#1094356).

  - ibmvnic: Return error code if init interrupted by
    transport event (bsc#1094840).

  - ibmvnic: Set resetting state at earliest possible point
    (bsc#1094840).

  - iio:kfifo_buf: check for uint overflow (bnc#1012382).

  - ima: Fallback to the builtin hash algorithm
    (bnc#1012382).

  - ima: Fix Kconfig to select TPM 2.0 CRB interface
    (bnc#1012382).

  - init: fix false positives in W+X checking (bsc#1096982).

  - input: elan_i2c_smbus - fix corrupted stack
    (bnc#1012382).

  - ipc/shm: fix shmat() nil address after round-down when
    remapping (bnc#1012382).

  - ipmi/powernv: Fix error return code in
    ipmi_powernv_probe() (bnc#1012382).

  - ipmi_ssif: Fix kernel panic at msg_done_handler
    (bnc#1012382 bsc#1088871).

  - ipv4: fix memory leaks in udp_sendmsg, ping_v4_sendmsg
    (bnc#1012382).

  - ipv4: lock mtu in fnhe when received PMTU <
    net.ipv4.route.min_pmtu (bnc#1012382).

  - ipv6: add mtu lock check in __ip6_rt_update_pmtu
    (bsc#1092552).

  - ipv6: omit traffic class when calculating flow hash
    (bsc#1095042).

  - irda: fix overly long udelay() (bnc#1012382).

  - irqchip/gic-v3: Change pr_debug message to pr_devel
    (bnc#1012382).

  - jffs2: Fix use-after-free bug in jffs2_iget()'s error
    handling path (bnc#1012382 git-fixes).

  - kabi: vfs: Restore dentry_operations->d_manage
    (bsc#1086716).

  - kABI: work around BPF SSBD removal (bsc#1087082).

  - kasan: fix memory hotplug during boot (bnc#1012382).

  - kbuild: change CC_OPTIMIZE_FOR_SIZE definition
    (bnc#1012382).

  - kconfig: Do not leak main menus during parsing
    (bnc#1012382).

  - kconfig: Fix automatic menu creation mem leak
    (bnc#1012382).

  - kconfig: Fix expr_free() E_NOT leak (bnc#1012382).

  - kdb: make 'mdr' command repeat (bnc#1012382).

  - kernel: Fix memory leak on EP11 target list processing
    (bnc#1096751, LTC#168596).

  - kernel/relay.c: limit kmalloc size to KMALLOC_MAX_SIZE
    (bnc#1012382).

  - kernel/sys.c: fix potential Spectre v1 issue
    (bnc#1012382).

  - kvm: Fix spelling mistake: 'cop_unsuable' ->
    'cop_unusable' (bnc#1012382).

  - kvm: lapic: stop advertising DIRECTED_EOI when in-kernel
    IOAPIC is in use (bnc#1012382).

  - kvm: PPC: Book3S HV: Fix VRMA initialization with 2MB or
    1GB memory backing (bnc#1012382).

  - kvm: VMX: raise internal error for exception during
    invalid protected mode state (bnc#1012382).

  - kvm: x86: fix KVM_XEN_HVM_CONFIG ioctl (bnc#1012382).

  - kvm: x86: Sync back MSR_IA32_SPEC_CTRL to VCPU data
    structure (bsc#1096242, bsc#1096281).

  - l2tp: revert 'l2tp: fix missing print session offset
    info' (bnc#1012382).

  - libata: blacklist Micron 500IT SSD with MU01 firmware
    (bnc#1012382).

  - libata: Blacklist some Sandisk SSDs for NCQ
    (bnc#1012382).

  - libnvdimm, dax: fix 1GB-aligned namespaces vs physical
    misalignment (FATE#320457, FATE#320460).

  - libnvdimm, namespace: use a safe lookup for dimm device
    name (FATE#321135, FATE#321217, FATE#321256,
    FATE#321391, FATE#321393).

  - libnvdimm, pfn: fix start_pad handling for aligned
    namespaces (FATE#320460).

  - llc: better deal with too small mtu (bnc#1012382).

  - llc: properly handle dev_queue_xmit() return value
    (bnc#1012382).

  - lockd: lost rollback of set_grace_period() in
    lockd_down_net() (bnc#1012382 git-fixes).

  - locking/qspinlock: Ensure node->count is updated before
    initialising node (bnc#1012382).

  - locking/xchg/alpha: Add unconditional memory barrier to
    cmpxchg() (bnc#1012382).

  - locking/xchg/alpha: Fix xchg() and cmpxchg() memory
    ordering bugs (bnc#1012382).

  - loop: handle short DIO reads (bsc#1094177).

  - m68k: set dma and coherent masks for platform FEC
    ethernets (bnc#1012382).

  - mac80211: round IEEE80211_TX_STATUS_HEADROOM up to
    multiple of 4 (bnc#1012382).

  - md raid10: fix NULL deference in
    handle_write_completed() (bnc#1012382 bsc#1056415).

  - md/raid1: fix NULL pointer dereference (bnc#1012382).

  - md: raid5: avoid string overflow warning (bnc#1012382).

  - media: cx23885: Override 888 ImpactVCBe crystal
    frequency (bnc#1012382).

  - media: cx23885: Set subdev host data to clk_freq pointer
    (bnc#1012382).

  - media: cx25821: prevent out-of-bounds read on array card
    (bnc#1012382 bsc#1031717).

  - media: dmxdev: fix error code for invalid ioctls
    (bnc#1012382).

  - media: em28xx: USB bulk packet size fix (bnc#1012382).

  - media: s3c-camif: fix out-of-bounds array access
    (bnc#1012382 bsc#1031717).

  - mmc: sdhci-iproc: fix 32bit writes for TRANSFER_MODE
    register (bnc#1012382).

  - mm: do not allow deferred pages with NEED_PER_CPU_KM
    (bnc#1012382).

  - mm: filemap: avoid unnecessary calls to lock_page when
    waiting for IO to complete during a read (-- VM
    bnc#1012382 bnc#971975 generic performance read).

  - mm: filemap: remove redundant code in do_read_cache_page
    (-- VM bnc#1012382 bnc#971975 generic performance read).

  - mm: fix races between address_space dereference and free
    in page_evicatable (bnc#1012382).

  - mm: fix the NULL mapping case in __isolate_lru_page()
    (bnc#1012382).

  - mm/kmemleak.c: wait for scan completion before disabling
    free (bnc#1012382).

  - mm/ksm: fix interaction with THP (bnc#1012382).

  - mm/mempolicy: add nodes_empty check in
    SYSC_migrate_pages (bnc#1012382).

  - mm/mempolicy.c: avoid use uninitialized preferred_node
    (bnc#1012382).

  - mm/mempolicy: fix the check of nodemask from user
    (bnc#1012382).

  - mm, page_alloc: do not break __GFP_THISNODE by zonelist
    reset (bsc#1079152, VM Functionality).

  - mm: pin address_space before dereferencing it while
    isolating an LRU page (bnc#1012382 bnc#1081500).

  - net: bgmac: Fix endian access in
    bgmac_dma_tx_ring_free() (bnc#1012382).

  - net: ethernet: sun: niu set correct packet size in skb
    (bnc#1012382).

  - netfilter: ebtables: convert BUG_ONs to WARN_ONs
    (bnc#1012382).

  - net: Fix untag for vlan packets without ethernet header
    (bnc#1012382).

  - net: Fix vlan untag for bridge and vlan_dev with
    reorder_hdr off (bnc#1012382).

  - netlabel: If PF_INET6, check sk_buff ip header version
    (bnc#1012382).

  - net/mlx4_en: Verify coalescing parameters are in range
    (bnc#1012382).

  - net/mlx5: Protect from command bit overflow
    (bnc#1012382).

  - net: mvneta: fix enable of all initialized RXQs
    (bnc#1012382).

  - net: qmi_wwan: add BroadMobi BM806U 2020:2033
    (bnc#1012382).

  - net_sched: fq: take care of throttled flows before reuse
    (bnc#1012382).

  - net: support compat 64-bit time in (s,g)etsockopt
    (bnc#1012382).

  - net/tcp/illinois: replace broken algorithm reference
    link (bnc#1012382).

  - net: test tailroom before appending to linear skb
    (bnc#1012382).

  - net-usb: add qmi_wwan if on lte modem wistron neweb
    d18q1 (bnc#1012382).

  - net/usb/qmi_wwan.c: Add USB id for lt4120 modem
    (bnc#1012382).

  - nfc: llcp: Limit size of SDP URI (bnc#1012382).

  - nfit, address-range-scrub: fix scrub in-progress
    reporting (FATE#321135, FATE#321217, FATE#321256,
    FATE#321391, FATE#321393).

  - nfit: fix region registration vs block-data-window
    ranges (FATE#319858).

  - nfs: Do not convert nfs_idmap_cache_timeout to jiffies
    (bnc#1012382 git-fixes).

  - nfsv4: always set NFS_LOCK_LOST when a lock is lost
    (bnc#1012382 bsc#1068951).

  - ntb_transport: Fix bug with max_mw_size parameter
    (bnc#1012382).

  - nvme-pci: Fix EEH failure on ppc (bsc#1093533).

  - nvme-pci: Fix nvme queue cleanup if IRQ setup fails
    (bnc#1012382).

  - ocfs2/acl: use 'ip_xattr_sem' to protect getting
    extended attribute (bnc#1012382).

  - ocfs2/dlm: do not handle migrate lockres if already in
    shutdown (bnc#1012382).

  - ocfs2: return -EROFS to mount.ocfs2 if inode block is
    invalid (bnc#1012382).

  - ocfs2: return error when we attempt to access a dirty bh
    in jbd2 (bnc#1012382 bsc#1070404).

  - openvswitch: Do not swap table in nlattr_set() after
    OVS_ATTR_NESTED is found (bnc#1012382).

  - packet: fix reserve calculation (git-fixes).

  - packet: in packet_snd start writing at link layer
    allocation (bnc#1012382).

  - parisc/pci: Switch LBA PCI bus from Hard Fail to Soft
    Fail mode (bnc#1012382).

  - pci: Add function 1 DMA alias quirk for Marvell 88SE9220
    (bnc#1012382).

  - pci: Add function 1 DMA alias quirk for Marvell 9128
    (bnc#1012382).

  - pci: hv: Fix a __local_bh_enable_ip warning in
    hv_compose_msi_msg() (bnc#1094268).

  - pci: Restore config space on runtime resume despite
    being unbound (bnc#1012382).

  - perf callchain: Fix attr.sample_max_stack setting
    (bnc#1012382).

  - perf/cgroup: Fix child event counting bug (bnc#1012382).

  - perf/core: Fix perf_output_read_group() (bnc#1012382).

  - perf report: Fix memory corruption in --branch-history
    mode --branch-history (bnc#1012382).

  - perf tests: Use arch__compare_symbol_names to compare
    symbols (bnc#1012382).

  - pipe: cap initial pipe capacity according to
    pipe-max-size limit (bnc#1012382 bsc#1045330).

  - powerpc/64s: Clear PCR on boot (bnc#1012382).

  - powerpc: Add missing prototype for arch_irq_work_raise()
    (bnc#1012382).

  - powerpc/bpf/jit: Fix 32-bit JIT for seccomp_data access
    (bnc#1012382).

  - powerpc: Do not preempt_disable() in show_cpuinfo()
    (bnc#1012382 bsc#1066223).

  - powerpc/livepatch: Fix livepatch stack access
    (bsc#1094466).

  - powerpc/modules: Do not try to restore r2 after a
    sibling call (bsc#1094466).

  - powerpc/mpic: Check if cpu_possible() in mpic_physmask()
    (bnc#1012382).

  - powerpc/numa: Ensure nodes initialized for hotplug
    (FATE#322022 bnc#1012382 bsc#1081514).

  - powerpc/numa: Use ibm,max-associativity-domains to
    discover possible nodes (FATE#322022 bnc#1012382
    bsc#1081514).

  - powerpc/perf: Fix kernel address leak via sampling
    registers (bnc#1012382).

  - powerpc/perf: Prevent kernel address leak to userspace
    via BHRB buffer (bnc#1012382).

  - powerpc/powernv: Fix NVRAM sleep in invalid context when
    crashing (bnc#1012382).

  - powerpc/powernv: panic() on OPAL < V3 (bnc#1012382).

  - powerpc/powernv: remove FW_FEATURE_OPALv3 and just use
    FW_FEATURE_OPAL (bnc#1012382).

  - powerpc/powernv: Remove OPALv2 firmware define and
    references (bnc#1012382).

  - proc: fix /proc/*/map_files lookup (bnc#1012382).

  - procfs: fix pthread cross-thread naming if !PR_DUMPABLE
    (bnc#1012382).

  - proc: meminfo: estimate available memory more
    conservatively (-- VM bnc#1012382 functionality
    monitoring space user).

  - proc read mm's (arg,env)_(start,end) with mmap semaphore
    taken (bnc#1012382).

  - qede: Fix ref-cnt usage count (bsc#1019695 FATE#321703
    bsc#1019699 FATE#321702 bsc#1022604 FATE#321747).

  - qed: Fix LL2 race during connection terminate
    (bsc#1019695 FATE#321703 bsc#1019699 FATE#321702
    bsc#1022604 FATE#321747).

  - qed: Fix possibility of list corruption during rmmod
    flows (bsc#1019695 FATE#321703 bsc#1019699 FATE#321702
    bsc#1022604 FATE#321747).

  - qed: LL2 flush isles when connection is closed
    (bsc#1019695 FATE#321703 bsc#1019699 FATE#321702
    bsc#1022604 FATE#321747).

  - qla2xxx: Mask off Scope bits in retry delay
    (bsc#1068054).

  - qmi_wwan: do not steal interfaces from class drivers
    (bnc#1012382).

  - r8152: fix tx packets accounting (bnc#1012382).

  - r8169: fix powering up RTL8168h (bnc#1012382).

  - rdma/mlx5: Avoid memory leak in case of XRCD dealloc
    failure (bnc#1012382).

  - rdma/qedr: Fix doorbell bar mapping for dpi > 1
    (bsc#1022604 FATE#321747).

  - rdma/ucma: Correct option size check using optlen
    (bnc#1012382).

  - rds: IB: Fix NULL pointer issue (bnc#1012382).

  - Refresh
    patches.arch/arm64-bsc1031492-0165-arm64-Add-MIDR-values
    -for-Cavium-cn83XX-SoCs.patch.

  - regulator: of: Add a missing 'of_node_put()' in an error
    handling path of 'of_regulator_match()' (bnc#1012382).

  - regulatory: add NUL to request alpha2 (bnc#1012382).

  - Revert 'arm: dts: imx6qdl-wandboard: Fix audio channel
    swap' (bnc#1012382).

  - Revert 'bs-upload-kernel: do not set %opensuse_bs' This
    reverts commit e89e2b8cbef05df6c874ba70af3cb4c57f82a821.

  - Revert 'ima: limit file hash setting by user to fix and
    log modes' (bnc#1012382).

  - Revert 'ipc/shm: Fix shmat mmap nil-page protection'
    (bnc#1012382).

  - Revert 'regulatory: add NUL to request alpha2' (kabi).

  - Revert 'vti4: Do not override MTU passed on link
    creation via IFLA_MTU' (bnc#1012382).

  - rtc: hctosys: Ensure system time does not overflow
    time_t (bnc#1012382).

  - rtc: snvs: Fix usage of snvs_rtc_enable (bnc#1012382).

  - rtc: tx4939: avoid unintended sign extension on a 24 bit
    shift (bnc#1012382).

  - rtlwifi: rtl8192cu: Remove variable self-assignment in
    rf.c (bnc#1012382).

  - s390: add assembler macros for CPU alternatives
    (bnc#1012382).

  - s390/cio: clear timer when terminating driver I/O
    (bnc#1012382).

  - s390/cio: fix return code after missing interrupt
    (bnc#1012382).

  - s390/cpum_sf: ensure sample frequency of perf event
    attributes is non-zero (bnc#1094532, LTC#168035).

  - s390/cpum_sf: ensure sample frequency of perf event
    attributes is non-zero (LTC#168035 bnc#1012382
    bnc#1094532).

  - s390: extend expoline to BC instructions (bnc#1012382).

  - s390/ftrace: use expoline for indirect branches
    (bnc#1012382).

  - s390/kernel: use expoline for indirect branches
    (bnc#1012382).

  - s390/lib: use expoline for indirect branches
    (bnc#1012382).

  - s390: move expoline assembler macros to a header
    (bnc#1012382).

  - s390: move spectre sysfs attribute code (bnc#1012382).

  - s390/qdio: do not release memory in qdio_setup_irq()
    (bnc#1012382).

  - s390/qdio: fix access to uninitialized qdio_q fields
    (bnc#1094532, LTC#168037).

  - s390/qdio: fix access to uninitialized qdio_q fields
    (LTC#168037 bnc#1012382 bnc#1094532).

  - s390: remove indirect branch from do_softirq_own_stack
    (bnc#1012382).

  - s390: use expoline thunks in the BPF JIT (bnc#1012382).

  - sched/rt: Fix rq->clock_update_flags < RQCF_ACT_SKIP
    warning (bnc#1012382).

  - scripts/git-pre-commit :

  - scsi: aacraid: Correct hba_send to include iu_type
    (bsc#1022607, FATE#321673).

  - scsi: aacraid: fix shutdown crash when init fails
    (bnc#1012382).

  - scsi: aacraid: Insure command thread is not recursively
    stopped (bnc#1012382).

  - scsi: bnx2fc: Fix check in SCSI completion handler for
    timed out request (bnc#1012382).

  - scsi: fas216: fix sense buffer initialization
    (bnc#1012382 bsc#1082979).

  - scsi: libsas: defer ata device eh commands to libata
    (bnc#1012382).

  - scsi: lpfc: Fix frequency of Release WQE CQEs
    (bnc#1012382).

  - scsi: lpfc: Fix issue_lip if link is disabled
    (bnc#1012382 bsc#1080656).

  - scsi: lpfc: Fix soft lockup in lpfc worker thread during
    LIP testing (bnc#1012382 bsc#1080656).

  - scsi: mpt3sas: Do not mark fw_event workqueue as
    WQ_MEM_RECLAIM (bnc#1012382 bsc#1078583).

  - scsi: mptfusion: Add bounds check in
    mptctl_hp_targetinfo() (bnc#1012382).

  - scsi: qla2xxx: Avoid triggering undefined behavior in
    qla2x00_mbx_completion() (bnc#1012382).

  - scsi: qla4xxx: skip error recovery in case of register
    disconnect (bnc#1012382).

  - scsi: scsi_transport_srp: Fix shost to rport translation
    (bnc#1012382).

  - scsi: sd: Keep disk read-only when re-reading partition
    (bnc#1012382).

  - scsi: sg: allocate with __GFP_ZERO in
    sg_build_indirect() (bnc#1012382).

  - scsi: storvsc: Increase cmd_per_lun for higher speed
    devices (bnc#1012382).

  - scsi: sym53c8xx_2: iterator underflow in sym_getsync()
    (bnc#1012382).

  - scsi: ufs: Enable quirk to ignore sending WRITE_SAME
    command (bnc#1012382).

  - scsi: zfcp: fix infinite iteration on ERP ready list
    (bnc#1094532, LTC#168038).

  - scsi: zfcp: fix infinite iteration on ERP ready list
    (LTC#168038 bnc#1012382 bnc#1094532).

  - sctp: delay the authentication for the duplicated
    cookie-echo chunk (bnc#1012382).

  - sctp: fix the issue that the cookie-ack with auth can't
    get processed (bnc#1012382).

  - sctp: handle two v4 addrs comparison in
    sctp_inet6_cmp_addr (bnc#1012382).

  - sctp: use the old asoc when making the cookie-ack chunk
    in dupcook_d (bnc#1012382).

  - selftests: ftrace: Add a testcase for probepoint
    (bnc#1012382).

  - selftests: ftrace: Add a testcase for string type with
    kprobe_event (bnc#1012382).

  - selftests: ftrace: Add probe event argument syntax
    testcase (bnc#1012382).

  - selftests: memfd: add config fragment for fuse
    (bnc#1012382).

  - selftests/net: fixes psock_fanout eBPF test case
    (bnc#1012382).

  - selftests/powerpc: Skip the subpage_prot tests if the
    syscall is unavailable (bnc#1012382).

  - selftests: Print the test we're running to /dev/kmsg
    (bnc#1012382).

  - selinux: KASAN: slab-out-of-bounds in xattr_getsecurity
    (bnc#1012382).

  - serial: arc_uart: Fix out-of-bounds access through DT
    alias (bnc#1012382).

  - serial: fsl_lpuart: Fix out-of-bounds access through DT
    alias (bnc#1012382).

  - serial: imx: Fix out-of-bounds access through serial
    port index (bnc#1012382).

  - serial: mxs-auart: Fix out-of-bounds access through
    serial port index (bnc#1012382).

  - serial: samsung: Fix out-of-bounds access through serial
    port index (bnc#1012382).

  - serial: xuartps: Fix out-of-bounds access through DT
    alias (bnc#1012382).

  - sh: fix debug trap failure to process signals before
    return to user (bnc#1012382).

  - sh: New gcc support (bnc#1012382).

  - signals: avoid unnecessary taking of sighand->siglock
    (-- Scheduler bnc#1012382 bnc#978907 performance
    signals).

  - sit: fix IFLA_MTU ignored on NEWLINK (bnc#1012382).

  - smsc75xx: fix smsc75xx_set_features() (bnc#1012382).

  - sock_diag: fix use-after-free read in __sk_free
    (bnc#1012382).

  - sparc64: Fix build warnings with gcc 7 (bnc#1012382).

  - sparc64: Make atomic_xchg() an inline function rather
    than a macro (bnc#1012382).

  - spi: pxa2xx: Allow 64-bit DMA (bnc#1012382).

  - sr: get/drop reference to device in revalidate and
    check_events (bnc#1012382).

  - staging: rtl8192u: return -ENOMEM on failed allocation
    of priv->oldaddr (bnc#1012382).

  - stm class: Use vmalloc for the master map (bnc#1012382).

  - sunvnet: does not support GSO for sctp (bnc#1012382).

  - swap: divide-by-zero when zero length swap file on ssd
    (bnc#1012382 bsc#1082153).

  - tcp: avoid integer overflows in tcp_rcv_space_adjust()
    (bnc#1012382).

  - tcp: ignore Fast Open on repair mode (bnc#1012382).

  - tcp: purge write queue in tcp_connect_init()
    (bnc#1012382).

  - test_bpf: Fix testing with CONFIG_BPF_JIT_ALWAYS_ON=y on
    other arches (git-fixes).

  - tg3: Fix vunmap() BUG_ON() triggered from
    tg3_free_consistent() (bnc#1012382).

  - tick/broadcast: Use for_each_cpu() specially on UP
    kernels (bnc#1012382).

  - time: Fix CLOCK_MONOTONIC_RAW sub-nanosecond accounting
    (bnc#1012382).

  - tools/libbpf: handle issues with bpf ELF objects
    containing .eh_frames (bnc#1012382).

  - tools lib traceevent: Fix get_field_str() for dynamic
    strings (bnc#1012382).

  - tools lib traceevent: Simplify pointer print logic and
    fix %pF (bnc#1012382).

  - tools/thermal: tmon: fix for segfault (bnc#1012382).

  - tracing: Fix crash when freeing instances with event
    triggers (bnc#1012382).

  - tracing/hrtimer: Fix tracing bugs by taking all clock
    bases and modes into account (bnc#1012382).

  - tracing/x86/xen: Remove zero data size trace events
    trace_xen_mmu_flush_tlb(_all) (bnc#1012382).

  - udf: Provide saner default for invalid uid / gid
    (bnc#1012382).

  - usb: dwc2: Fix dwc2_hsotg_core_init_disconnected()
    (bnc#1012382).

  - usb: dwc2: Fix interval type issue (bnc#1012382).

  - usb: dwc3: Update DWC_usb31 GTXFIFOSIZ reg fields
    (bnc#1012382).

  - usb: gadget: composite: fix incorrect handling of OS
    desc requests (bnc#1012382).

  - usb: gadget: ffs: Execute copy_to_user() with USER_DS
    set (bnc#1012382).

  - usb: gadget: ffs: Let setup() return
    USB_GADGET_DELAYED_STATUS (bnc#1012382).

  - usb: gadget: fsl_udc_core: fix ep valid checks
    (bnc#1012382).

  - usb: gadget: f_uac2: fix bFirstInterface in composite
    gadget (bnc#1012382).

  - usb: gadget: udc: change comparison to bitshift when
    dealing with a mask (bnc#1012382).

  - usbip: usbip_host: delete device from busid_table after
    rebind (bnc#1012382).

  - usbip: usbip_host: fix bad unlock balance during
    stub_probe() (bnc#1012382).

  - usbip: usbip_host: fix NULL-ptr deref and use-after-free
    errors (bnc#1012382).

  - usbip: usbip_host: refine probe and disconnect debug
    msgs to be useful (bnc#1012382).

  - usbip: usbip_host: run rebind from exit when module is
    removed (bnc#1012382).

  - usb: musb: call pm_runtime_(get,put)_sync before reading
    vbus registers (bnc#1012382).

  - usb: musb: fix enumeration after resume (bnc#1012382).

  - USB: OHCI: Fix NULL dereference in HCDs using
    HCD_LOCAL_MEM (bnc#1012382).

  - USB: serial: cp210x: use tcflag_t to fix incompatible
    pointer type (bnc#1012382).

  - vfs: add path_has_submounts() (bsc#1086716).

  - vfs: add path_is_mountpoint() helper (bsc#1086716).

  - vfs: change d_manage() to take a struct path
    (bsc#1086716).

  - virtio-gpu: fix ioctl and expose the fixed status to
    userspace (bnc#1012382).

  - virtio-net: Fix operstate for virtio when no
    VIRTIO_NET_F_STATUS (bnc#1012382).

  - vmscan: do not force-scan file lru if its absolute size
    is small (-- VM bnc#1012382 page performance reclaim).

  - vti4: Do not count header length twice on tunnel setup
    (bnc#1012382).

  - vti4: Do not override MTU passed on link creation via
    IFLA_MTU (bnc#1012382).

  - watchdog: f71808e_wdt: Fix magic close handling
    (bnc#1012382).

  - watchdog: sp5100_tco: Fix watchdog disable bit
    (bnc#1012382).

  - workqueue: use put_device() instead of kfree()
    (bnc#1012382).

  - x86/apic: Set up through-local-APIC mode on the boot CPU
    if 'noapic' specified (bnc#1012382).

  - x86/boot: Fix early command-line parsing when partial
    word matches (bsc#1096140).

  - x86/bugs: IBRS: make runtime disabling fully dynamic
    (bsc#1068032).

  - x86/bugs: spec_ctrl must be cleared from cpu_caps_set
    when being disabled (bsc#1096140).

  - x86/cpufeature: Remove unused and seldomly used
    cpu_has_xx macros (bnc#1012382).

  - x86/devicetree: Fix device IRQ settings in DT
    (bnc#1012382).

  - x86/devicetree: Initialize device tree before using it
    (bnc#1012382).

  - x86: ENABLE_IBRS clobbers %rax which it shouldn't do
    there is probably a place where forcing _IBRS_OFF is
    missed (or is too late) and therefore ENABLE_IBRS is
    sometimes called early during boot while it should not.
    Let's drop the uoptimization for now. (bsc#1098009 and
    bsc#1098012)

  - x86/fpu: Default eagerfpu=on on all CPUs (CVE-2018-3665
    bnc#1012382 bnc#1087086).

  - x86/fpu: Disable AVX when eagerfpu is off (bnc#1012382).

  - x86/fpu: Disable MPX when eagerfpu is off (CVE-2018-3665
    bnc#1012382 bnc#1087086).

  - x86/fpu: Fix early FPU command-line parsing
    (CVE-2018-3665 bnc#1012382 bnc#1087086).

  - x86/kaiser: export symbol kaiser_set_shadow_pgd()
    (bsc#1092813)

  - x86/kexec: Avoid double free_page() upon do_kexec_load()
    failure (bnc#1012382).

  - x86-mce-Make-timer-handling-more-robust.patch: Fix
    metadata

  - x86/pgtable: Do not set huge PUD/PMD on non-leaf entries
    (bnc#1012382).

  - x86/pkeys: Do not special case protection key 0
    (1041740).

  - x86/pkeys: Override pkey when moving away from PROT_EXEC
    (1041740).

  - x86/power: Fix swsusp_arch_resume prototype
    (bnc#1012382).

  - x86: Remove unused function cpu_has_ht_siblings()
    (bnc#1012382).

  - x86/topology: Update the 'cpu cores' field in
    /proc/cpuinfo correctly across CPU hotplug operations
    (bnc#1012382).

  - xen/acpi: off by one in read_acpi_id() (bnc#1012382).

  - xen/grant-table: Use put_page instead of free_page
    (bnc#1012382).

  - xen-netfront: Fix race between device setup and open
    (bnc#1012382).

  - xen/netfront: raise max number of slots in
    xennet_get_responses() (bnc#1076049).

  - xen/pirq: fix error path cleanup when binding MSIs
    (bnc#1012382).

  - xen-swiotlb: fix the check condition for
    xen_swiotlb_free_coherent (bnc#1012382).

  - xen: xenbus: use put_device() instead of kfree()
    (bnc#1012382).

  - xfrm: fix xfrm_do_migrate() with AEAD e.g(AES-GCM)
    (bnc#1012382).

  - xfs: convert XFS_AGFL_SIZE to a helper function
    (bsc#1090955, bsc#1090534).

  - xfs: detect agfl count corruption and reset agfl
    (bnc#1012382 bsc#1090534 bsc#1090955).

  - xfs: detect agfl count corruption and reset agfl
    (bsc#1090955, bsc#1090534).

  - xfs: do not log/recover swapext extent owner changes for
    deleted inodes (bsc#1090955).

  - xfs: fix endianness error when checking log block crc on
    big endian platforms (bsc#1094405, bsc#1036215).

  - xfs: remove racy hasattr check from attr ops
    (bnc#1012382 bsc#1035432).

  - xhci: Fix USB3 NULL pointer dereference at logical
    disconnect (git-fixes).

  - xhci: Fix use-after-free in xhci_free_virt_device
    (git-fixes).

  - xhci: zero usb device slot_id member when disabling and
    freeing a xhci slot (bnc#1012382).

  - zorro: Set up z->dev.dma_mask for the DMA API
    (bnc#1012382).

  - jfs: Fix buffer overrun in ea_get (bsc#1097234,
    CVE-2018-12233)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978907"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-debuginfo-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-4.4.138-59.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-debuginfo-4.4.138-59.1") ) flag++;

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
