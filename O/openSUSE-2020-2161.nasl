#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2161.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(143523);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25669",
    "CVE-2020-25705",
    "CVE-2020-27777",
    "CVE-2020-28915",
    "CVE-2020-28941",
    "CVE-2020-28974",
    "CVE-2020-29369",
    "CVE-2020-29371",
    "CVE-2020-4788"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-2161)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-29369: There was a race condition between
    certain expand functions (expand_downwards and
    expand_upwards) and page-table free operations from an
    munmap call, aka CID-246c320a8cfe (bnc#1173504
    bnc#1179432).

  - CVE-2020-29371: An issue was discovered in
    romfs_dev_read in fs/romfs/storage.c, where
    uninitialized memory could leak to userspace, aka
    CID-bcf85fcedfdd (bnc#1179429).

  - CVE-2020-15436: Use-after-free vulnerability in
    fs/block_dev.c allowed local users to gain privileges or
    cause a denial of service by leveraging improper access
    to a certain error field (bnc#1179141).

  - CVE-2020-25705: A flaw in the way reply ICMP packets are
    limited was found that allowed to quickly scan open UDP
    ports. This flaw allowed an off-path remote user to
    effectively bypassing source port UDP randomization. The
    highest threat from this vulnerability is to
    confidentiality and possibly integrity, because software
    that relies on UDP source port randomization are
    indirectly affected as well. Kernel versions may be
    vulnerable to this issue (bnc#1175721 bnc#1178782).

  - CVE-2020-15437: The Linux kernel was vulnerable to a
    NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init_
    ports() that allowed local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized (bnc#1179140).

  - CVE-2020-27777: Restricted RTAS requests from userspace
    (bsc#1179107). 

  - CVE-2020-28974: A slab-out-of-bounds read in fbcon could
    be used by local attackers to read privileged
    information or potentially crash the kernel, aka
    CID-3c4e0dff2095. This occurs because KD_FONT_OP_COPY in
    drivers/tty/vt/vt.c can be used for manipulations such
    as font height (bnc#1178589).

  - CVE-2020-4788: IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1)
    processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under
    extenuating circumstances. IBM X-Force ID: 189296
    (bnc#1177666).

  - CVE-2020-28941: Local attackers on systems with the
    speakup driver could cause a local denial of service
    attack, aka CID-d41227544427. This occurs because of an
    invalid free when the line discipline is used more than
    once (bnc#1178740).

  - CVE-2020-28915: A buffer over-read (at the framebuffer
    layer) in the fbcon code could be used by local
    attackers to read kernel memory, aka CID-6735b4632def
    (bnc#1178886).

  - CVE-2020-25669: Avoid a use-after-free in teardown paths
    in sunkbd (bsc#1178182).

The following non-security bugs were fixed :

  - 9P: Cast to loff_t before multiplying (git-fixes).

  - ACPI: GED: fix -Wformat (git-fixes).

  - ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).

  - ACPI: button: Add DMI quirk for Medion Akoya E2228T
    (git-fixes).

  - ACPI: dock: fix enum-conversion warning (git-fixes).

  - ACPICA: Add NHLT table signature (bsc#1176200).

  - ALSA: ctl: fix error path at adding user-defined element
    set (git-fixes).

  - ALSA: firewire: Clean up a locking issue in
    copy_resp_to_buf() (git-fixes).

  - ALSA: hda/realtek - Add supported for Lenovo ThinkPad
    Headset Button (git-fixes).

  - ALSA: hda/realtek - Add supported mute Led for HP
    (git-fixes).

  - ALSA: hda/realtek - HP Headset Mic can't detect after
    boot (git-fixes).

  - ALSA: hda/realtek: Add some Clove SSID in the
    ALC293(ALC1220) (git-fixes).

  - ALSA: hda: Reinstate runtime_allow() for all hda
    controllers (git-fixes).

  - ALSA: hda: fix jack detection with Realtek codecs when
    in D3 (git-fixes).

  - ALSA: mixart: Fix mutex deadlock (git-fixes).

  - ALSA: usb-audio: Add delay quirk for all Logitech USB
    devices (git-fixes).

  - ASoC: qcom: lpass-platform: Fix memory leak (git-fixes).

  - Add bug reference to two hv_netvsc patches
    (bsc#1178853).

  - Convert trailing spaces and periods in path components
    (bsc#1179424).

  - Documentation/admin-guide/module-signing.rst: add
    openssl command option example for CodeSign EKU
    (bsc#1177353, bsc#1179076).

  - Drop sysctl files for dropped archs, add ppc64le and arm
    (bsc#1178838). Also correct the page size on ppc64.

  - EDAC/amd64: Cache secondary Chip Select registers
    (bsc#1179001).

  - EDAC/amd64: Find Chip Select memory size using Address
    Mask (bsc#1179001).

  - EDAC/amd64: Gather hardware information early
    (bsc#1179001).

  - EDAC/amd64: Initialize DIMM info for systems with more
    than two channels (bsc#1179001).

  - EDAC/amd64: Make struct amd64_family_type global
    (bsc#1179001).

  - EDAC/amd64: Save max number of controllers to family
    type (bsc#1179001).

  - EDAC/amd64: Support asymmetric dual-rank DIMMs
    (bsc#1179001).

  - Fix wrongly set CONFIG_SOUNDWIRE=y (bsc#1179201)
    CONFIG_SOUNDWIRE was mistakenly set as built-in. Mark it
    as module.

  - HID: logitech-dj: Fix Dinovo Mini when paired with a
    MX5x00 receiver (git-fixes).

  - HID: logitech-dj: Fix an error in
    mse_bluetooth_descriptor (git-fixes).

  - HID: logitech-dj: Handle quad/bluetooth keyboards with a
    builtin trackpad (git-fixes).

  - HID: logitech-hidpp: Add PID for MX Anywhere 2
    (git-fixes).

  - Input: adxl34x - clean up a data type in adxl34x_probe()
    (git-fixes).

  - Input: resistive-adc-touch - fix kconfig dependency on
    IIO_BUFFER (git-fixes).

  - KVM: arm64: ARM_SMCCC_ARCH_WORKAROUND_1 does not return
    SMCCC_RET_NOT_REQUIRED (git-fixes).

  - NFS: only invalidate dentrys that are clearly invalid
    (bsc#1178669 bsc#1170139).

  - NFSv4.x recover from pre-mature loss of openstateid
    (bsc#1176180).

  - NFSv4: Handle NFS4ERR_OLD_STATEID in
    CLOSE/OPEN_DOWNGRADE (bsc#1176180).

  - NFSv4: Wait for stateid updates after
    CLOSE/OPEN_DOWNGRADE (bsc#1176180).

  - RDMA/hns: Fix retry_cnt and rnr_cnt when querying QP
    (jsc#SLE-8449).

  - RDMA/hns: Fix the wrong value of rnr_retry when querying
    qp (jsc#SLE-8449).

  - RDMA/hns: Fix wrong field of SRQ number the device
    supports (jsc#SLE-8449).

  - RDMA/hns: Solve the overflow of the calc_pg_sz()
    (jsc#SLE-8449).

  - RDMA/mlx5: Fix devlink deadlock on net namespace
    deletion (jsc#SLE-8464).

  - RDMA/qedr: Fix return code if accept is called on a
    destroyed qp (jsc#SLE-8215).

  - RDMA/ucma: Add missing locking around
    rdma_leave_multicast() (git-fixes).

  - Revert 'cdc-acm: hardening against malicious devices'
    (git-fixes).

  - Revert 'kernel/reboot.c: convert simple_strtoul to
    kstrtoint' (git-fixes).

  - SUNRPC: Fix general protection fault in
    trace_rpc_xdr_overflow() (git-fixes).

  - SUNRPC: fix copying of multiple pages in
    gss_read_proxy_verf() (bsc#1154353).

  - USB: Add NO_LPM quirk for Kingston flash drive
    (git-fixes).

  - USB: core: Change %pK for __user pointers to %px
    (git-fixes).

  - USB: core: Fix regression in Hercules audio card
    (git-fixes).

  - USB: serial: option: add LE910Cx compositions 0x1203,
    0x1230, 0x1231 (git-fixes).

  - USB: serial: option: add Quectel EC200T module support
    (git-fixes).

  - USB: serial: option: add Telit FN980 composition 0x1055
    (git-fixes).

  - arm64: Run ARCH_WORKAROUND_1 enabling code on all CPUs
    (git-fixes).

  - arm64: Run ARCH_WORKAROUND_2 enabling code on all CPUs
    (git-fixes).

  - arm64: bpf: Fix branch offset in JIT (git-fixes).

  - arm64: dts: allwinner: Pine H64: Enable both RGMII RX/TX
    delay (git-fixes).

  - arm64: dts: allwinner: a64: OrangePi Win: Fix ethernet
    node (git-fixes).

  - arm64: dts: allwinner: a64: Pine64 Plus: Fix ethernet
    node (git-fixes).

  - arm64: dts: allwinner: a64: bananapi-m64: Enable RGMII
    RX/TX delay on PHY (git-fixes).

  - arm64: dts: allwinner: beelink-gs1: Enable both RGMII
    RX/TX delay (git-fixes).

  - arm64: dts: allwinner: h5: OrangePi PC2: Fix ethernet
    node (git-fixes).

  - arm64: dts: allwinner: h5: OrangePi Prime: Fix ethernet
    node (git-fixes).

  - arm64: dts: fsl: DPAA FMan DMA operations are coherent
    (git-fixes).

  - arm64: dts: imx8mm: fix voltage for 1.6GHz CPU operating
    point (git-fixes).

  - arm64: dts: imx8mq: Add missing interrupts to GPC
    (git-fixes).

  - arm64: dts: imx8mq: Fix TMU interrupt property
    (git-fixes).

  - arm64: dts: zynqmp: Remove additional compatible string
    for i2c IPs (git-fixes).

  - arm64: kprobe: add checks for ARMv8.3-PAuth combined
    instructions (git-fixes).

  - arm64: tegra: Add missing timeout clock to Tegra186
    SDMMC nodes (git-fixes).

  - arm64: tegra: Add missing timeout clock to Tegra194
    SDMMC nodes (git-fixes).

  - arm64: tegra: Add missing timeout clock to Tegra210
    SDMMC (git-fixes).

  - arm64: vdso: Add '-Bsymbolic' to ldflags (git-fixes).

  - arm64: vdso: Add --eh-frame-hdr to ldflags (git-fixes).

  - batman-adv: set .owner to THIS_MODULE (git-fixes).

  - bnxt_en: Avoid sending firmware messages when AER error
    is detected (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Check abort error state in bnxt_open_nic()
    (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Fix NULL ptr dereference crash in
    bnxt_fw_reset_task() (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Fix regression in workqueue cleanup logic in
    bnxt_remove_one() (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Invoke cancel_delayed_work_sync() for PFs also
    (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Send HWRM_FUNC_RESET fw command unconditionally
    (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: return proper error codes in bnxt_show_temp
    (git-fixes).

  - bpf: Do not rely on GCC __attribute__((optimize)) to
    disable GCSE (bsc#1155518).

  - bpf: Fix comment for helper
    bpf_current_task_under_cgroup() (bsc#1155518).

  - bpf: Zero-fill re-used per-cpu map element
    (bsc#1155518).

  - btrfs: fix bytes_may_use underflow in prealloc error
    condtition (bsc#1179217).

  - btrfs: fix metadata reservation for fallocate that leads
    to transaction aborts (bsc#1179217).

  - btrfs: fix relocation failure due to race with fallocate
    (bsc#1179217).

  - btrfs: remove item_size member of struct
    btrfs_clone_extent_info (bsc#1179217).

  - btrfs: rename btrfs_insert_clone_extent() to a more
    generic name (bsc#1179217).

  - btrfs: rename btrfs_punch_hole_range() to a more generic
    name (bsc#1179217).

  - btrfs: rename struct btrfs_clone_extent_info to a more
    generic name (bsc#1179217).

  - can: af_can: prevent potential access of uninitialized
    member in can_rcv() (git-fixes).

  - can: af_can: prevent potential access of uninitialized
    member in canfd_rcv() (git-fixes).

  - can: dev: can_restart(): post buffer from the right
    context (git-fixes).

  - can: flexcan: flexcan_setup_stop_mode(): add missing
    'req_bit' to stop mode property comment (git-fixes).

  - can: gs_usb: fix endianess problem with candleLight
    firmware (git-fixes).

  - can: kvaser_usb: kvaser_usb_hydra: Fix KCAN bittiming
    limits (git-fixes).

  - can: m_can: fix nominal bitiming tseg2 min for version
    >= 3.1 (git-fixes).

  - can: m_can: m_can_handle_state_change(): fix state
    change (git-fixes).

  - can: m_can: m_can_stop(): set device to software init
    mode before closing (git-fixes).

  - can: mcba_usb: mcba_usb_start_xmit(): first fill skb,
    then pass to can_put_echo_skb() (git-fixes).

  - can: peak_usb: fix potential integer overflow on shift
    of a int (git-fixes).

  - ceph: add check_session_state() helper and make it
    global (bsc#1179012).

  - ceph: check session state after bumping session->s_seq
    (bsc#1179012).

  - ceph: check the sesion state and return false in case it
    is closed (bsc#1179012).

  - ceph: downgrade warning from mdsmap decode to debug
    (bsc#1178653).

  - ceph: fix race in concurrent __ceph_remove_cap
    invocations (bsc#1178635).

  - cfg80211: initialize wdev data earlier (git-fixes).

  - cfg80211: regulatory: Fix inconsistent format argument
    (git-fixes).

  - cifs: Fix incomplete memory allocation on setxattr path
    (bsc#1179211).

  - cifs: Return the error from crypt_message when enc/dec
    key not found (bsc#1179426).

  - cifs: remove bogus debug code (bsc#1179427).

  - clk: define to_clk_regmap() as inline function
    (git-fixes).

  - cosa: Add missing kfree in error path of cosa_write
    (git-fixes).

  - dax: Fix stack overflow when mounting fsdax pmem device
    (bsc#1171073).

  - dax: fix detection of dax support for non-persistent
    memory block devices (bsc#1171073).

  - devlink: Make sure devlink instance and port are in same
    net namespace (bsc#1154353).

  - docs: ABI: sysfs-c2port: remove a duplicated entry
    (git-fixes).

  - drbd: code cleanup by using sendpage_ok() to check page
    for kernel_sendpage() (bsc#1172873).

  - drivers/net/ethernet: remove incorrectly formatted doc
    (bsc#1177397).

  - efi/efivars: Set generic ops before loading SSDT
    (git-fixes).

  - efi/esrt: Fix reference count leak in
    esre_create_sysfs_entry (git-fixes).

  - efi/libstub/x86: Work around LLVM ELF quirk build
    regression (git-fixes).

  - efi/x86: Align GUIDs to their size in the mixed mode
    runtime wrapper (git-fixes).

  - efi/x86: Do not panic or BUG() on non-critical error
    conditions (git-fixes).

  - efi/x86: Fix the deletion of variables in mixed mode
    (git-fixes).

  - efi/x86: Free efi_pgd with free_pages() (git-fixes).

  - efi/x86: Handle by-ref arguments covering multiple pages
    in mixed mode (git-fixes).

  - efi/x86: Ignore the memory attributes table on i386
    (git-fixes).

  - efi/x86: Map the entire EFI vendor string before copying
    it (git-fixes).

  - efi: EFI_EARLYCON should depend on EFI (git-fixes).

  - efi: add missed destroy_workqueue when efisubsys_init
    fails (git-fixes).

  - efi: efibc: check for efivars write capability
    (git-fixes).

  - efi: provide empty efi_enter_virtual_mode implementation
    (git-fixes).

  - efivarfs: fix memory leak in efivarfs_create()
    (git-fixes).

  - efivarfs: revert 'fix memory leak in efivarfs_create()'
    (git-fixes).

  - fbdev, newport_con: Move FONT_EXTRA_WORDS macros into
    linux/font.h (git-fixes).

  - ftrace: Fix recursion check for NMI test (git-fixes).

  - ftrace: Handle tracing when switching between context
    (git-fixes).

  - futex: Do not enable IRQs unconditionally in
    put_pi_state() (bsc#1149032).

  - futex: Handle transient 'ownerless' rtmutex state
    correctly (bsc#1149032).

  - gpio: pcie-idio-24: Enable PEX8311 interrupts
    (git-fixes).

  - gpio: pcie-idio-24: Fix IRQ Enable Register value
    (git-fixes).

  - gpio: pcie-idio-24: Fix irq mask when masking
    (git-fixes).

  - hv: clocksource: Add notrace attribute to
    read_hv_sched_clock_*() functions (git-fixes).

  - hv_balloon: disable warning when floor reached
    (git-fixes).

  - hv_netvsc: Add XDP support (bsc#1177820).

  - hv_netvsc: Fix XDP refcnt for synthetic and VF NICs
    (bsc#1177820).

  - hv_netvsc: make recording RSS hash depend on feature
    flag (bsc#1177820).

  - hv_netvsc: record hardware hash in skb (bsc#1177820).

  - hwmon: (pwm-fan) Fix RPM calculation (git-fixes).

  - i2c: mediatek: move dma reset before i2c reset
    (git-fixes).

  - i2c: sh_mobile: implement atomic transfers (git-fixes).

  - igc: Fix not considering the TX delay for timestamps
    (bsc#1160634).

  - igc: Fix wrong timestamp latency numbers (bsc#1160634).

  - iio: accel: kxcjk1013: Add support for KIOX010A ACPI DSM
    for setting tablet-mode (git-fixes).

  - iio: accel: kxcjk1013: Replace is_smo8500_device with an
    acpi_type enum (git-fixes).

  - iio: adc: mediatek: fix unset field (git-fixes).

  - iio: light: fix kconfig dependency bug for VCNL4035
    (git-fixes).

  - intel_idle: Customize IceLake server support
    (bsc#1178286).

  - ionic: check port ptr before use (bsc#1167773).

  - iwlwifi: mvm: write queue_sync_state only for sync
    (git-fixes).

  - kABI workaround for HD-audio (git-fixes).

  - kABI: revert use_mm name change (MM Functionality,
    bsc#1178426).

  - kernel-source.spec: Fix build with rpm 4.16
    (boo#1179015).

  - kernel-(binary,source).spec.in: do not create loop
    symlinks (bsc#1179082)

  - kernel/watchdog: fix watchdog_allowed_mask not used
    warning (git-fixes).

  - kernel: better document the use_mm/unuse_mm API contract
    (MM Functionality, bsc#1178426).

  - kgdb: Fix spurious true from in_dbg_master()
    (git-fixes).

  - kthread_worker: prevent queuing delayed work from
    timer_fn when it is being canceled (git-fixes).

  - lan743x: fix 'BUG: invalid wait context' when setting rx
    mode (git-fixes).

  - lan743x: fix issue causing intermittent kernel log
    warnings (git-fixes).

  - lan743x: prevent entire kernel HANG on open, for some
    platforms (git-fixes).

  - lib/crc32test: remove extra local_irq_disable/enable
    (git-fixes).

  - lib/strncpy_from_user.c: Mask out bytes after NUL
    terminator (bsc#1155518).

  - libbpf, hashmap: Fix undefined behavior in hash_bits
    (bsc#1155518).

  - libceph: use sendpage_ok() in ceph_tcp_sendpage()
    (bsc#1172873).

  - libnvdimm/nvdimm/flush: Allow architecture to override
    the flush barrier (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - mac80211: always wind down STA state (git-fixes).

  - mac80211: fix use of skb payload instead of header
    (git-fixes).

  - mac80211: free sta in sta_info_insert_finish() on errors
    (git-fixes).

  - mac80211: minstrel: fix tx status processing corner case
    (git-fixes).

  - mac80211: minstrel: remove deferred sampling code
    (git-fixes).

  - mei: protect mei_cl_mtu from null dereference
    (git-fixes).

  - memcg: fix NULL pointer dereference in
    __mem_cgroup_usage_unregister_event (bsc#1177703).

  - mfd: sprd: Add wakeup capability for PMIC IRQ
    (git-fixes).

  - mm, THP, swap: fix allocating cluster for swapfile by
    mistake (bsc#1178755).

  - mm, memcg: fix inconsistent oom event behavior
    (bsc#1178659).

  - mm/gup: allow FOLL_FORCE for get_user_pages_fast() (git
    fixes (mm/gup)).

  - mm/gup: fix gup_fast with dynamic page table folding
    (bnc#1176586, LTC#188235).

  - mm/ksm: fix NULL pointer dereference when KSM zero page
    is enabled (git fixes (mm/ksm)).

  - mm/memcg: fix refcount error while moving and swapping
    (bsc#1178686).

  - mm/memcontrol.c: add missed css_put() (bsc#1178661).

  - mm: fix exec activate_mm vs TLB shootdown and lazy tlb
    switching race (MM Functionality, bsc#1178426).

  - mm: fix kthread_use_mm() vs TLB invalidate (MM
    Functionality, bsc#1178426).

  - mm: mempolicy: require at least one nodeid for
    MPOL_PREFERRED (git fixes (mm/mempolicy)).

  - mm: swap: make page_evictable() inline (git fixes
    (mm/vmscan)).

  - mm: swap: use smp_mb__after_atomic() to order LRU bit
    set (git fixes (mm/vmscan)).

  - mmc: renesas_sdhi_core: Add missing tmio_mmc_host_free()
    at remove (git-fixes).

  - mmc: sdhci-of-esdhc: Handle pulse width detection
    erratum for more SoCs (git-fixes).

  - mmc: sdhci-pci: Prefer SDR25 timing for High Speed mode
    for BYT-based Intel controllers (git-fixes).

  - modsign: Add codeSigning EKU when generating X.509 key
    generation config (bsc#1177353, bsc#1179076).

  - net/mlx5: Clear bw_share upon VF disable (jsc#SLE-8464).

  - net/mlx5: E-Switch, Fail mlx5_esw_modify_vport_rate if
    qos disabled (jsc#SLE-8464).

  - net: add WARN_ONCE in kernel_sendpage() for improper
    zero-copy send (bsc#1172873).

  - net: ena: Capitalize all log strings and improve code
    readability (bsc#1177397).

  - net: ena: Change RSS related macros and variables names
    (bsc#1177397).

  - net: ena: Change license into format to SPDX in all
    files (bsc#1177397).

  - net: ena: Change log message to netif/dev function
    (bsc#1177397).

  - net: ena: Fix all static chekers' warnings
    (bsc#1177397).

  - net: ena: Remove redundant print of placement policy
    (bsc#1177397).

  - net: ena: ethtool: Add new device statistics
    (bsc#1177397).

  - net: ena: ethtool: add stats printing to XDP queues
    (bsc#1177397).

  - net: ena: ethtool: convert stat_offset to 64 bit
    resolution (bsc#1177397).

  - net: ena: fix packet's addresses for rx_offset feature
    (bsc#1174852).

  - net: ena: handle bad request id in ena_netdev
    (bsc#1174852).

  - net: ena: xdp: add queue counters for xdp actions
    (bsc#1177397).

  - net: fix pos incrementment in ipv6_route_seq_next
    (bsc#1154353).

  - net: introduce helper sendpage_ok() in
    include/linux/net.h (bsc#1172873).

  - net: usb: qmi_wwan: add Telit LE910Cx 0x1230 composition
    (git-fixes).

  - nfc: s3fwrn5: use signed integer for parsing GPIO
    numbers (git-fixes).

  - nvme-tcp: check page by sendpage_ok() before calling
    kernel_sendpage() (bsc#1172873).

  - nvme: do not update disk info for multipathed device
    (bsc#1171558).

  - pinctrl: amd: fix incorrect way to disable debounce
    filter (git-fixes).

  - pinctrl: amd: use higher precision for 512 RtcClk
    (git-fixes).

  - pinctrl: aspeed: Fix GPI only function problem
    (git-fixes).

  - pinctrl: intel: Set default bias in case no particular
    value given (git-fixes).

  - platform/x86: thinkpad_acpi: Send tablet mode switch at
    wakeup time (git-fixes).

  - platform/x86: toshiba_acpi: Fix the wrong variable
    assignment (git-fixes).

  - powerpc/64s/radix: Fix mm_cpumask trimming race vs
    kthread_use_mm (MM Functionality, bsc#1178426).

  - powerpc/perf: consolidate GPCI hcall structs into
    asm/hvcall.h (jsc#SLE-16360 jsc#SLE-16915).

  - powerpc/pmem: Add flush routines using new pmem store
    and sync instruction (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - powerpc/pmem: Add new instructions for persistent
    storage and sync (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - powerpc/pmem: Avoid the barrier in flush routines
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Initialize pmem device on newer hardware
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Restrict papr_scm to P8 and above
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Update ppc64 to use the new barrier
    instruction (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109
    ltc#187964).

  - powerpc/pseries: Add KVM guest doorbell restrictions
    (jsc#SLE-15869 jsc#SLE-16321).

  - powerpc/pseries: Use doorbells even if XIVE is available
    (jsc#SLE-15869 jsc#SLE-16321).

  - powerpc/pseries: new lparcfg key/value pair:
    partition_affinity_score (jsc#SLE-16360 jsc#SLE-16915).

  - powerpc/vnic: Extend 'failover pending' window
    (bsc#1176855 ltc#187293).

  - powerpc: Inline doorbell sending functions
    (jsc#SLE-15869 jsc#SLE-16321).

  - powerpc: select ARCH_WANT_IRQS_OFF_ACTIVATE_MM (MM
    Functionality, bsc#1178426).

  - qla2xxx: Add MODULE_VERSION back to driver
    (bsc#1179160).

  - reboot: fix overflow parsing reboot cpu number
    (git-fixes).

  - regulator: avoid resolve_supply() infinite recursion
    (git-fixes).

  - regulator: fix memory leak with repeated
    set_machine_constraints() (git-fixes).

  - regulator: pfuze100: limit pfuze-support-disable-sw to
    pfuze(100,200) (git-fixes).

  - regulator: ti-abb: Fix array out of bound read access on
    the first transition (git-fixes).

  - regulator: workaround self-referent regulators
    (git-fixes).

  - rfkill: Fix use-after-free in rfkill_resume()
    (git-fixes).

  - ring-buffer: Fix recursion protection transitions
    between interrupt context (git-fixes).

  - rpm/kernel-binary.spec.in: avoid using barewords
    (bsc#1179014)

  - rpm/kernel-binary.spec.in: avoid using more barewords
    (bsc#1179014)

  - rpm/kernel-binary.spec.in: use grep -E instead of egrep
    (bsc#1179045)

  - rpm/kernel-obs-build.spec.in: Add -q option to modprobe
    calls (bsc#1178401)

  - rpm/kernel-(source,binary).spec: do not include ghost
    symlinks (boo#1179082).

  - rpm/mkspec: do not build kernel-obs-build on x86_32 We
    want to use 64bit kernel due to various bugs
    (bsc#1178762 to name one).

  - s390/bpf: Fix multiple tail calls (git-fixes).

  - s390/cpum_cf,perf: change DFLT_CCERROR counter name
    (bsc#1175918 LTC#187935).

  - s390/cpum_sf.c: fix file permission for cpum_sfb_size
    (git-fixes).

  - s390/dasd: fix NULL pointer dereference for ERP requests
    (git-fixes).

  - s390/pkey: fix paes selftest failure with paes and pkey
    static build (git-fixes).

  - s390/zcrypt: Fix ZCRYPT_PERDEV_REQCNT ioctl (bsc#1177070
    LTC#188342).

  - s390/zcrypt: fix kmalloc 256k failure (bsc#1177066
    LTC#188341).

  - sched/fair: Ensure tasks spreading in LLC during LB (git
    fixes (sched)).

  - sched/fair: Fix unthrottle_cfs_rq() for leaf_cfs_rq list
    (git fixes (sched)).

  - sched: Fix loadavg accounting race on arm64 kabi
    (bnc#1178227).

  - sched: Fix rq->nr_iowait ordering (git fixes (sched)).

  - scripts/lib/SUSE/MyBS.pm: properly close prjconf Macros:
    section

  - scsi: libiscsi: Fix NOP race condition (bsc#1176481).

  - scsi: libiscsi: use sendpage_ok() in
    iscsi_tcp_segment_map() (bsc#1172873).

  - spi: lpspi: Fix use-after-free on unbind (git-fixes).

  - staging: rtl8723bs: Add 024c:0627 to the list of SDIO
    device-ids (git-fixes).

  - svcrdma: fix bounce buffers for unaligned offsets and
    multiple pages (git-fixes).

  - tcp: use sendpage_ok() to detect misused .sendpage
    (bsc#1172873).

  - thunderbolt: Add the missed ida_simple_remove() in
    ring_request_msix() (git-fixes).

  - thunderbolt: Fix memory leak if ida_simple_get() fails
    in enumerate_services() (git-fixes).

  - timer: Fix wheel index calculation on last level
    (git-fixes).

  - timer: Prevent base->clk from moving backward
    (git-fixes).

  - tpm: efi: Do not create binary_bios_measurements file
    for an empty log (git-fixes).

  - tpm_tis: Disable interrupts on ThinkPad T490s
    (git-fixes).

  - tracing: Fix out of bounds write in get_trace_buf
    (git-fixes).

  - tty: serial: fsl_lpuart: LS1021A had a FIFO size of 16
    words, like LS1028A (git-fixes).

  - tty: serial: fsl_lpuart: add LS1028A support
    (git-fixes).

  - tty: serial: imx: fix potential deadlock (git-fixes).

  - tty: serial: imx: keep console clocks always on
    (git-fixes).

  - uio: Fix use-after-free in uio_unregister_device()
    (git-fixes).

  - usb: cdc-acm: Add DISABLE_ECHO for Renesas USB Download
    mode (git-fixes).

  - usb: core: driver: fix stray tabs in error messages
    (git-fixes).

  - usb: gadget: Fix memleak in gadgetfs_fill_super
    (git-fixes).

  - usb: gadget: f_midi: Fix memleak in f_midi_alloc
    (git-fixes).

  - usb: gadget: goku_udc: fix potential crashes in probe
    (git-fixes).

  - usb: host: fsl-mph-dr-of: check return of dma_set_mask()
    (git-fixes).

  - usb: typec: tcpm: reset hard_reset_count for any
    disconnect (git-fixes).

  - video: hyperv_fb: Fix the cache type when mapping the
    VRAM (git-fixes).

  - video: hyperv_fb: include vmalloc.h (git-fixes).

  - virtio: virtio_console: fix DMA memory allocation for
    rproc serial (git-fixes).

  - vt: Disable KD_FONT_OP_COPY (bsc#1178589).

  - x86/hyperv: Clarify comment on x2apic mode (git-fixes).

  - x86/i8259: Use printk_deferred() to prevent deadlock
    (git-fixes).

  - x86/microcode/intel: Check patch signature before saving
    microcode for early loading (bsc#1152489).

  - x86/speculation: Allow IBPB to be conditionally enabled
    on CPUs with always-on STIBP (bsc#1152489).

  - xfs: fix a missing unlock on error in xfs_fs_map_blocks
    (git-fixes).

  - xfs: fix brainos in the refcount scrubber's rmap
    fragment processor (git-fixes).

  - xfs: fix flags argument to rmap lookup when converting
    shared file rmaps (git-fixes).

  - xfs: fix rmap key and record comparison functions
    (git-fixes).

  - xfs: revert 'xfs: fix rmap key and record comparison
    functions' (git-fixes).

  - xfs: set the unwritten bit in rmap lookup flags in
    xchk_bmap_get_rmapextents (git-fixes).

  - xhci: Fix sizeof() mismatch (git-fixes).

  - xhci: hisilicon: fix refercence leak in xhci_histb_probe
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179432");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27777");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.54.1.lp152.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.54.1.lp152.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.54.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.54.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.54.1") ) flag++;

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
