#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-885.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111997);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18344", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-885) (Foreshadow)");
  script_summary(english:"Check for the openSUSE-2018-885 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.143 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-18344: The timer_create syscall implementation
    in kernel/time/posix-timers.c didn't properly validate
    the sigevent->sigev_notify field, which leads to
    out-of-bounds access in the show_timer function (called
    when /proc/$PID/timers is read). This allowed userspace
    applications to read arbitrary kernel memory (on a
    kernel built with CONFIG_POSIX_TIMERS and
    CONFIG_CHECKPOINT_RESTORE) (bnc#1102851 bnc#1103580).

  - CVE-2018-10876: A flaw was found in Linux kernel in the
    ext4 filesystem code. A use-after-free is possible in
    ext4_ext_remove_space() function when mounting and
    operating a crafted ext4 image. (bnc#1099811)

  - CVE-2018-10877: Linux kernel ext4 filesystem is
    vulnerable to an out-of-bound access in the
    ext4_ext_drop_refs() function when operating on a
    crafted ext4 filesystem image. (bnc#1099846)

  - CVE-2018-10878: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image. (bnc#1099813)

  - CVE-2018-10879: A flaw was found in the ext4 filesystem.
    A local user can cause a use-after-free in
    ext4_xattr_set_entry function and a denial of service or
    unspecified other impact may occur by renaming a file in
    a crafted ext4 filesystem image. (bnc#1099844)

  - CVE-2018-10880: Linux kernel is vulnerable to a
    stack-out-of-bounds write in the ext4 filesystem code
    when mounting and writing to a crafted ext4 image in
    ext4_update_inline_data(). An attacker could use this to
    cause a system crash and a denial of service.
    (bnc#1099845)

  - CVE-2018-10881: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and a
    system crash by mounting and operating on a crafted ext4
    filesystem image. (bnc#1099864)

  - CVE-2018-10882: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bound write in in
    fs/jbd2/transaction.c code, a denial of service, and a
    system crash by unmounting a crafted ext4 filesystem
    image. (bnc#1099849)

  - CVE-2018-10883: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bounds write in
    jbd2_journal_dirty_metadata(), a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image. (bnc#1099863)

  - CVE-2018-14734: drivers/infiniband/core/ucma.c allowed
    ucma_leave_multicast to access a certain data structure
    after a cleanup step in ucma_process_join, which allowed
    attackers to cause a denial of service (use-after-free)
    (bnc#1103119).

  - CVE-2018-3620: Systems with microprocessors utilizing
    speculative execution and address translations may allow
    unauthorized disclosure of information residing in the
    L1 data cache to an attacker with local user access via
    a terminal page fault and a side-channel analysis
    (bnc#1087081 1089343 ).

  - CVE-2018-3646: Systems with microprocessors utilizing
    speculative execution and address translations may allow
    unauthorized disclosure of information residing in the
    L1 data cache to an attacker with local user access with
    guest OS privilege via a terminal page fault and a
    side-channel analysis (bnc#1089343 1104365).

  - CVE-2018-5390 aka 'SegmentSmack': The Linux kernel could
    be forced to make very expensive calls to
    tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for
    every incoming packet which can lead to a denial of
    service (bnc#1102340).

  - CVE-2018-5391 aka 'FragmentSmack': A flaw in the IP
    packet reassembly could be used by remote attackers to
    consume lots of CPU time (bnc#1103097).

The following non-security bugs were fixed :

  - Add support for 5,25,50, and 100G to 802.3ad bonding
    driver (bsc#1096978)

  - ahci: Disable LPM on Lenovo 50 series laptops with a too
    old BIOS (bnc#1012382).

  - arm64: do not open code page table entry creation
    (bsc#1102197).

  - arm64: kpti: Use early_param for kpti= command-line
    option (bsc#1102188).

  - arm64: Make sure permission updates happen for pmd/pud
    (bsc#1102197).

  - atm: zatm: Fix potential Spectre v1 (bnc#1012382).

  - bcm63xx_enet: correct clock usage (bnc#1012382).

  - bcm63xx_enet: do not write to random DMA channel on
    BCM6345 (bnc#1012382).

  - blkcg: simplify statistic accumulation code
    (bsc#1082979).

  - block: copy ioprio in __bio_clone_fast() (bsc#1082653).

  - block/swim: Fix array bounds check (bsc#1082979).

  - bpf: fix loading of BPF_MAXINSNS sized programs
    (bsc#1012382).

  - bpf, x64: fix memleak when not converging after image
    (bsc#1012382).

  - btrfs: Do not remove block group still has pinned down
    bytes (bsc#1086457).

  - cachefiles: Fix missing clear of the
    CACHEFILES_OBJECT_ACTIVE flag (bsc#1099858).

  - cachefiles: Fix refcounting bug in backing-file read
    monitoring (bsc#1099858).

  - cachefiles: Wait rather than BUG'ing on 'Unexpected
    object collision' (bsc#1099858).

  - cifs: fix bad/NULL ptr dereferencing in
    SMB2_sess_setup() (bsc#1090123).

  - compiler, clang: always inline when
    CONFIG_OPTIMIZE_INLINING is disabled (bnc#1012382).

  - compiler, clang: properly override 'inline' for clang
    (bnc#1012382).

  - compiler, clang: suppress warning for unused static
    inline functions (bnc#1012382).

  - compiler-gcc.h: Add __attribute__((gnu_inline)) to all
    inline declarations (bnc#1012382).

  - cpu/hotplug: Add sysfs state interface (bsc#1089343).

  - cpu/hotplug: Provide knobs to control SMT (bsc#1089343).

  - cpu/hotplug: Split do_cpu_down() (bsc#1089343).

  - crypto: crypto4xx - fix crypto4xx_build_pdr,
    crypto4xx_build_sdr leak (bnc#1012382).

  - crypto: crypto4xx - remove bad list_del (bnc#1012382).

  - dm thin metadata: remove needless work from
    __commit_transaction (bsc#1082979).

  - drm/msm: Fix possible null dereference on failure of
    get_pages() (bsc#1102394).

  - drm: re-enable error handling (bsc#1103884).

  - esp6: fix memleak on error path in esp6_input
    (git-fixes).

  - ext4: check for allocation block validity with block
    group locked (bsc#1104495).

  - ext4: do not update s_last_mounted of a frozen fs
    (bsc#1101841).

  - ext4: factor out helper ext4_sample_last_mounted()
    (bsc#1101841).

  - ext4: fix check to prevent initializing reserved inodes
    (bsc#1104319).

  - ext4: fix false negatives *and* false positives in
    ext4_check_descriptors() (bsc#1103445).

  - ext4: fix inline data updates with checksums enabled
    (bsc#1104494).

  - fscache: Allow cancelled operations to be enqueued
    (bsc#1099858).

  - fscache: Fix reference overput in
    fscache_attach_object() error handling (bsc#1099858).

  - genirq: Make force irq threading setup more robust
    (bsc#1082979).

  - hid: usbhid: add quirk for innomedia INNEX GENESIS/ATARI
    adapter (bnc#1012382).

  - ib/isert: fix T10-pi check mask setting (bsc#1082979).

  - ibmasm: do not write out of bounds in read handler
    (bnc#1012382).

  - ibmvnic: Fix error recovery on login failure
    (bsc#1101789).

  - ibmvnic: Remove code to request error information
    (bsc#1104174).

  - ibmvnic: Revise RX/TX queue error messages
    (bsc#1101331).

  - ibmvnic: Update firmware error reporting with cause
    string (bsc#1104174).

  - iw_cxgb4: correctly enforce the max reg_mr depth
    (bnc#1012382).

  - kabi protect includes in include/linux/inet.h
    (bsc#1095643).

  - kabi protect net/core/utils.c includes (bsc#1095643).

  - kABI: protect struct loop_device (kabi).

  - kABI: reintroduce __static_cpu_has_safe (kabi).

  - Kbuild: fix # escaping in .cmd files for future Make
    (bnc#1012382).

  - keys: DNS: fix parsing multiple options (bnc#1012382).

  - kvm: arm/arm64: Drop resource size check for GICV window
    (bsc#1102215).

  - kvm: arm/arm64: Set dist->spis to NULL after kfree
    (bsc#1102214).

  - libata: do not try to pass through NCQ commands to
    non-NCQ devices (bsc#1082979).

  - loop: add recursion validation to LOOP_CHANGE_FD
    (bnc#1012382).

  - loop: remember whether sysfs_create_group() was done
    (bnc#1012382).

  - mmc: dw_mmc: fix card threshold control configuration
    (bsc#1102203).

  - mm: check VMA flags to avoid invalid PROT_NONE NUMA
    balancing (bsc#1097771).

  - net: cxgb3_main: fix potential Spectre v1 (bnc#1012382).

  - net: dccp: avoid crash in ccid3_hc_rx_send_feedback()
    (bnc#1012382).

  - net: dccp: switch rx_tstamp_last_feedback to monotonic
    clock (bnc#1012382).

  - netfilter: ebtables: reject non-bridge targets
    (bnc#1012382).

  - netfilter: nf_queue: augment nfqa_cfg_policy
    (bnc#1012382).

  - netfilter: x_tables: initialise match/target check
    parameter struct (bnc#1012382).

  - net/mlx5: Fix command interface race in polling mode
    (bnc#1012382).

  - net/mlx5: Fix incorrect raw command length parsing
    (bnc#1012382).

  - net: mvneta: fix the Rx desc DMA address in the Rx path
    (bsc#1102207).

  - net/nfc: Avoid stalls when nfc_alloc_send_skb() returned
    NULL (bnc#1012382).

  - net: off by one in inet6_pton() (bsc#1095643).

  - net: phy: marvell: Use strlcpy() for
    ethtool::get_strings (bsc#1102205).

  - net_sched: blackhole: tell upper qdisc about dropped
    packets (bnc#1012382).

  - net: sungem: fix rx checksum support (bnc#1012382).

  - net/utils: generic inet_pton_with_scope helper
    (bsc#1095643).

  - null_blk: use sector_div instead of do_div
    (bsc#1082979).

  - nvme-rdma: Check remotely invalidated rkey matches our
    expected rkey (bsc#1092001).

  - nvme-rdma: default MR page size to 4k (bsc#1092001).

  - nvme-rdma: do not complete requests before a send work
    request has completed (bsc#1092001).

  - nvme-rdma: do not suppress send completions
    (bsc#1092001).

  - nvme-rdma: Fix command completion race at error recovery
    (bsc#1090435).

  - nvme-rdma: make nvme_rdma_[create|destroy]_queue_ib
    symmetrical (bsc#1092001).

  - nvme-rdma: use inet_pton_with_scope helper
    (bsc#1095643).

  - nvme-rdma: Use mr pool (bsc#1092001).

  - nvme-rdma: wait for local invalidation before completing
    a request (bsc#1092001).

  - ocfs2: subsystem.su_mutex is required while accessing
    the item->ci_parent (bnc#1012382).

  - pci: ibmphp: Fix use-before-set in get_max_bus_speed()
    (bsc#1100132).

  - perf tools: Move syscall number fallbacks from
    perf-sys.h to tools/arch/x86/include/asm/ (bnc#1012382).

  - pm / hibernate: Fix oops at snapshot_write()
    (bnc#1012382).

  - powerpc/64: Initialise thread_info for emergency stacks
    (bsc#1094244, bsc#1100930, bsc#1102683).

  - powerpc/fadump: handle crash memory ranges array index
    overflow (bsc#1103269).

  - powerpc/fadump: merge adjacent memory ranges to reduce
    PT_LOAD segements (bsc#1103269).

  - qed: Limit msix vectors in kdump kernel to the minimum
    required count (bnc#1012382).

  - r8152: napi hangup fix after disconnect (bnc#1012382).

  - rdma/ocrdma: Fix an error code in ocrdma_alloc_pd()
    (bsc#1082979).

  - rdma/ocrdma: Fix error codes in ocrdma_create_srq()
    (bsc#1082979).

  - rdma/ucm: Mark UCM interface as BROKEN (bnc#1012382).

  - rds: avoid unenecessary cong_update in loop transport
    (bnc#1012382).

  - Revert
    'block-cancel-workqueue-entries-on-blk_mq_freeze_queue'
    (bsc#1103717)

  - Revert 'sit: reload iphdr in ipip6_rcv' (bnc#1012382).

  - Revert 'x86/cpufeature: Move some of the scattered
    feature bits to x86_capability' (kabi).

  - Revert 'x86/cpu: Probe CPUID leaf 6 even when
    cpuid_level == 6' (kabi).

  - rtlwifi: rtl8821ae: fix firmware is not ready to run
    (bnc#1012382).

  - s390/qeth: fix error handling in adapter command
    callbacks (bnc#1103745, LTC#169699).

  - sched/smt: Update sched_smt_present at runtime
    (bsc#1089343).

  - scsi: qlogicpti: Fix an error handling path in
    'qpti_sbus_probe()' (bsc#1082979).

  - scsi: sg: fix minor memory leak in error path
    (bsc#1082979).

  - scsi: target: fix crash with iscsi target and dvd
    (bsc#1082979).

  - smsc75xx: Add workaround for gigabit link up hardware
    errata (bsc#1100132).

  - smsc95xx: Configure pause time to 0xffff when tx flow
    control enabled (bsc#1085536).

  - supported.conf: Do not build KMP for openSUSE kernels
    The merge of kselftest-kmp was overseen, and bad for
    openSUSE-42.3

  - tcp: fix Fast Open key endianness (bnc#1012382).

  - tcp: prevent bogus FRTO undos with non-SACK flows
    (bnc#1012382).

  - tools build: fix # escaping in .cmd files for future
    Make (bnc#1012382).

  - uprobes/x86: Remove incorrect WARN_ON() in
    uprobe_init_insn() (bnc#1012382).

  - usb: core: handle hub C_PORT_OVER_CURRENT condition
    (bsc#1100132).

  - usb: quirks: add delay quirks for Corsair Strafe
    (bnc#1012382).

  - usb: serial: ch341: fix type promotion bug in
    ch341_control_in() (bnc#1012382).

  - usb: serial: cp210x: add another USB ID for Qivicon
    ZigBee stick (bnc#1012382).

  - usb: serial: keyspan_pda: fix modem-status error
    handling (bnc#1012382).

  - usb: serial: mos7840: fix status-register error handling
    (bnc#1012382).

  - usb: yurex: fix out-of-bounds uaccess in read handler
    (bnc#1012382).

  - vfio: platform: Fix reset module leak in error path
    (bsc#1102211).

  - vfs: add the sb_start_intwrite_trylock() helper
    (bsc#1101841).

  - vhost_net: validate sock before trying to put its fd
    (bnc#1012382).

  - vmw_balloon: fix inflation with batching (bnc#1012382).

  - x86/alternatives: Add an auxilary section (bnc#1012382).

  - x86/alternatives: Discard dynamic check after init
    (bnc#1012382).

  - x86/apic: Ignore secondary threads if nosmt=force
    (bsc#1089343).

  - x86/asm: Add _ASM_ARG* constants for argument registers
    to <asm/asm.h> (bnc#1012382).

  - x86/boot: Simplify kernel load address alignment check
    (bnc#1012382).

  - x86/CPU/AMD: Do not check CPUID max ext level before
    parsing SMP info (bsc#1089343).

  - x86/cpu/AMD: Evaluate smp_num_siblings early
    (bsc#1089343).

  - x86/CPU/AMD: Move TOPOEXT reenablement before reading
    smp_num_siblings (bsc#1089343). Update config files.

  - x86/cpu/AMD: Remove the pointless detect_ht() call
    (bsc#1089343).

  - x86/cpu/common: Provide detect_ht_early() (bsc#1089343).

  - x86/cpufeature: Add helper macro for mask check macros
    (bnc#1012382).

  - x86/cpufeature: Carve out X86_FEATURE_* (bnc#1012382).

  - x86/cpufeature: Get rid of the non-asm goto variant
    (bnc#1012382).

  - x86/cpufeature: Make sure DISABLED/REQUIRED macros are
    updated (bnc#1012382).

  - x86/cpufeature: Move some of the scattered feature bits
    to x86_capability (bnc#1012382).

  - x86/cpufeature: Replace the old static_cpu_has() with
    safe variant (bnc#1012382).

  - x86/cpufeature: Speed up cpu_feature_enabled()
    (bnc#1012382).

  - x86/cpufeature: Update cpufeaure macros (bnc#1012382).

  - x86/cpu/intel: Evaluate smp_num_siblings early
    (bsc#1089343).

  - x86/cpu: Probe CPUID leaf 6 even when cpuid_level == 6
    (bnc#1012382).

  - x86/cpu: Provide a config option to disable
    static_cpu_has (bnc#1012382).

  - x86/cpu: Remove the pointless CPU printout
    (bsc#1089343).

  - x86/cpu/topology: Provide
    detect_extended_topology_early() (bsc#1089343).

  - x86/fpu: Add an XSTATE_OP() macro (bnc#1012382).

  - x86/fpu: Get rid of xstate_fault() (bnc#1012382).

  - x86/headers: Do not include asm/processor.h in
    asm/atomic.h (bnc#1012382).

  - x86/mm/pkeys: Fix mismerge of protection keys CPUID bits
    (bnc#1012382).

  - x86/mm: Simplify p[g4um]d_page() macros (1087081).

  - x86/smpboot: Do not use smp_num_siblings in
    __max_logical_packages calculation (bsc#1089343).

  - x86/smp: Provide topology_is_primary_thread()
    (bsc#1089343).

  - x86/topology: Add topology_max_smt_threads()
    (bsc#1089343).

  - x86/topology: Provide topology_smt_supported()
    (bsc#1089343).

  - x86/vdso: Use static_cpu_has() (bnc#1012382).

  - xen/grant-table: log the lack of grants (bnc#1085042).

  - xen-netfront: Fix mismatched rtnl_unlock (bnc#1101658).

  - xen-netfront: Update features after registering netdev
    (bnc#1101658).

  - xhci: xhci-mem: off by one in xhci_stream_id_to_ring()
    (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104495"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/20");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.143-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.143-65.1") ) flag++;

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
