#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1655.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141388);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-14381", "CVE-2020-14386", "CVE-2020-14390", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-26088");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1655)");
  script_summary(english:"Check for the openSUSE-2020-1655 patch");

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

  - CVE-2020-25212: Fixed nfs getxattr kernel panic and
    memory overflow that could lead to crashes or privilege
    escalations (bsc#1176381).

  - CVE-2020-14381: Fixed inode life-time issue in futex
    handling (bsc#1176011).

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

  - CVE-2020-26088: A missing CAP_NET_RAW check in NFC
    socket creation in net/nfc/rawsock.c could be used by
    local attackers to create raw sockets, bypassing
    security mechanisms, aka CID-26896f01467a (bnc#1176990).

  - CVE-2020-14390: When changing screen size, an
    out-of-bounds memory write can occur leading to memory
    corruption or a denial of service. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out
    (bnc#1176235 bnc#1176278).

  - CVE-2020-0432: In skb_to_mamac of networking.c, there is
    a possible out of bounds write due to an integer
    overflow. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1176721).

  - CVE-2020-0427: In create_pinctrl of core.c, there is a
    possible out of bounds read due to a use after free.
    This could lead to local information disclosure with no
    additional execution privileges needed. User interaction
    is not needed for exploitation (bnc#1176725).

  - CVE-2020-0431: In kbd_keycode of keyboard.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation
    (bnc#1176722).

  - CVE-2020-0404: In uvc_scan_chain_forward of
    uvc_driver.c, there is a possible linked list corruption
    due to an unusual root cause. This could lead to local
    escalation of privilege in the kernel with no additional
    execution privileges needed. User interaction is not
    needed for exploitation (bnc#1176423).

  - CVE-2020-25284: The rbd block device driver in
    drivers/block/rbd.c used incomplete permission checking
    for access to rbd devices, which could be leveraged by
    local attackers to map or unmap rbd block devices, aka
    CID-f44d04e696fe (bnc#1176482).

  - CVE-2020-14386: Memory corruption in af_apcket can be
    exploited to gain root privileges from unprivileged
    processes. The highest threat from this vulnerability is
    to data confidentiality and integrity (bnc#1176069).

The following non-security bugs were fixed :

  - 9p: Fix memory leak in v9fs_mount (git-fixes).

  - ACPI: EC: Reference count query handlers under lock
    (git-fixes).

  - Add de2b41be8fcc x86, vmlinux.lds: Page-align end of
    ..page_aligned sections

  - Add f29dfa53cc8a x86/bugs/multihit: Fix mitigation
    reporting when VMX is not in use

  - airo: Add missing CAP_NET_ADMIN check in
    AIROOLDIOCTL/SIOCDEVPRIVATE (git-fixes).

  - airo: Fix possible info leak in
    AIROOLDIOCTL/SIOCDEVPRIVATE (git-fixes).

  - airo: Fix read overflows sending packets (git-fixes).

  - ALSA: asihpi: fix iounmap in error handler (git-fixes).

  - ALSA: firewire-digi00x: exclude Avid Adrenaline from
    detection (git-fixes).

  - ALSA; firewire-tascam: exclude Tascam FE-8 from
    detection (git-fixes).

  - ALSA: hda: Fix 2 channel swapping for Tegra (git-fixes).

  - ALSA: hda: fix a runtime pm issue in SOF when integrated
    GPU is disabled (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion
    NT950XCJ-X716A (git-fixes).

  - ALSA: hda/realtek - Improved routing for Thinkpad X1
    7th/8th Gen (git-fixes).

  - altera-stapl: altera_get_note: prevent write beyond end
    of 'key' (git-fixes).

  - amd-xgbe: Add a check for an skb in the timestamp path
    (git-fixes).

  - amd-xgbe: Add additional dynamic debug messages
    (git-fixes).

  - amd-xgbe: Add additional ethtool statistics (git-fixes).

  - amd-xgbe: Add ethtool show/set channels support
    (git-fixes).

  - amd-xgbe: Add ethtool show/set ring parameter support
    (git-fixes).

  - amd-xgbe: Add ethtool support to retrieve SFP module
    info (git-fixes).

  - amd-xgbe: Add hardware features debug output
    (git-fixes).

  - amd-xgbe: Add NUMA affinity support for IRQ hints
    (git-fixes).

  - amd-xgbe: Add NUMA affinity support for memory
    allocations (git-fixes).

  - amd-xgbe: Add per queue Tx and Rx statistics
    (git-fixes).

  - amd-xgbe: Advertise FEC support with the KR re-driver
    (git-fixes).

  - amd-xgbe: Always attempt link training in KR mode
    (git-fixes).

  - amd-xgbe: Be sure driver shuts down cleanly on module
    removal (git-fixes).

  - amd-xgbe: Convert to generic power management
    (git-fixes).

  - amd-xgbe: Fix debug output of max channel counts
    (git-fixes).

  - amd-xgbe: Fix error path in xgbe_mod_init() (git-fixes).

  - amd-xgbe: Fixes for working with PHYs that support
    2.5GbE (git-fixes).

  - amd-xgbe: Fix SFP PHY supported/advertised settings
    (git-fixes).

  - amd-xgbe: fix spelling mistake: 'avialable' ->
    'available' (git-fixes).

  - amd-xgbe: Handle return code from software reset
    function (git-fixes).

  - amd-xgbe: Improve SFP 100Mbps auto-negotiation
    (git-fixes).

  - amd-xgbe: Interrupt summary bits are h/w version
    dependent (git-fixes).

  - amd-xgbe: Limit the I2C error messages that are output
    (git-fixes).

  - amd-xgbe: Mark expected switch fall-throughs
    (git-fixes).

  - amd-xgbe: Optimize DMA channel interrupt enablement
    (git-fixes).

  - amd-xgbe: Prepare for ethtool set-channel support
    (git-fixes).

  - amd-xgbe: Prevent looping forever if timestamp update
    fails (git-fixes).

  - amd-xgbe: Read and save the port property registers
    during probe (git-fixes).

  - amd-xgbe: Remove field that indicates SFP diagnostic
    support (git-fixes).

  - amd-xgbe: remove unnecessary conversion to bool
    (git-fixes).

  - amd-xgbe: Remove use of comm_owned field (git-fixes).

  - amd-xgbe: Set the MDIO mode for 10000Base-T
    configuration (git-fixes).

  - amd-xgbe: Simplify the burst length settings
    (git-fixes).

  - amd-xgbe: Update the BelFuse quirk to support SGMII
    (git-fixes).

  - amd-xgbe: Update TSO packet statistics accuracy
    (git-fixes).

  - amd-xgbe: use devm_platform_ioremap_resource() to
    simplify code (git-fixes).

  - amd-xgbe: use dma_mapping_error to check map errors
    (git-fixes).

  - amd-xgbe: Use __napi_schedule() in BH context
    (git-fixes).

  - amd-xgbe: Use the proper register during PTP
    initialization (git-fixes).

  - ar5523: Add USB ID of SMCWUSBT-G2 wireless adapter
    (git-fixes).

  - arm64: KVM: Do not generate UNDEF when LORegion feature
    is present (jsc#SLE-4084).

  - arm64: KVM: regmap: Fix unexpected switch fall-through
    (jsc#SLE-4084).

  - asm-generic: fix -Wtype-limits compiler warnings
    (bsc#1112178).

  - ASoC: kirkwood: fix IRQ error handling (git-fixes).

  - ASoC: tegra: Fix reference count leaks (git-fixes).

  - ath10k: fix array out-of-bounds access (git-fixes).

  - ath10k: fix memory leak for tpc_stats_final (git-fixes).

  - ath10k: use kzalloc to read for
    ath10k_sdio_hif_diag_read (git-fixes).

  - batman-adv: Add missing include for in_interrupt()
    (git-fixes).

  - batman-adv: Avoid uninitialized chaddr when handling
    DHCP (git-fixes).

  - batman-adv: bla: fix type misuse for backbone_gw hash
    indexing (git-fixes).

  - batman-adv: bla: use netif_rx_ni when not in interrupt
    context (git-fixes).

  - batman-adv: mcast: fix duplicate mcast packets in BLA
    backbone from mesh (git-fixes).

  - batman-adv: mcast/TT: fix wrongly dropped or rerouted
    packets (git-fixes).

  - bcache: Convert pr_<level> uses to a more typical style
    (git fixes (block drivers)).

  - bcache: fix overflow in offset_to_stripe() (git fixes
    (block drivers)).

  - bcm63xx_enet: correct clock usage (git-fixes).

  - bcm63xx_enet: do not write to random DMA channel on
    BCM6345 (git-fixes).

  - bitfield.h: do not compile-time validate _val in
    FIELD_FIT (git fixes (bitfield)).

  - blktrace: fix debugfs use after free (git fixes (block
    drivers)).

  - block: add docs for gendisk / request_queue refcount
    helpers (git fixes (block drivers)).

  - block: revert back to synchronous request_queue removal
    (git fixes (block drivers)).

  - block: Use non _rcu version of list functions for
    tag_set_list (git-fixes).

  - Bluetooth: Fix refcount use-after-free issue
    (git-fixes).

  - Bluetooth: guard against controllers sending zero'd
    events (git-fixes).

  - Bluetooth: Handle Inquiry Cancel error after Inquiry
    Complete (git-fixes).

  - Bluetooth: L2CAP: handle l2cap config request during
    open state (git-fixes).

  - Bluetooth: prefetch channel before killing sock
    (git-fixes).

  - bnxt_en: Fix completion ring sizing with TPA enabled
    (networking-stable-20_07_29).

  - bonding: use nla_get_u64 to extract the value for
    IFLA_BOND_AD_ACTOR_SYSTEM (git-fixes).

  - btrfs: require only sector size alignment for parent eb
    bytenr (bsc#1176789).

  - btrfs: tree-checker: fix the error message for transid
    error (bsc#1176788).

  - ceph: do not allow setlease on cephfs (bsc#1177041).

  - ceph: fix potential mdsc use-after-free crash
    (bsc#1177042).

  - ceph: fix use-after-free for fsc->mdsc (bsc#1177043).

  - ceph: handle zero-length feature mask in session
    messages (bsc#1177044).

  - cfg80211: regulatory: reject invalid hints
    (bsc#1176699).

  - cifs: Fix leak when handling lease break for cached root
    fid (bsc#1176242).

  - cifs/smb3: Fix data inconsistent when punch hole
    (bsc#1176544).

  - cifs/smb3: Fix data inconsistent when zero file range
    (bsc#1176536).

  - clk: Add (devm_)clk_get_optional() functions
    (git-fixes).

  - clk: rockchip: Fix initialization of mux_pll_src_4plls_p
    (git-fixes).

  - clk: samsung: exynos4: mark 'chipid' clock as
    CLK_IGNORE_UNUSED (git-fixes).

  - clk/ti/adpll: allocate room for terminating null
    (git-fixes).

  - clocksource/drivers/h8300_timer8: Fix wrong return value
    in h8300_8timer_init() (git-fixes).

  - cpufreq: intel_pstate: Fix EPP setting via sysfs in
    active mode (bsc#1176966).

  - dmaengine: at_hdmac: check return value of
    of_find_device_by_node() in at_dma_xlate() (git-fixes).

  - dmaengine: of-dma: Fix of_dma_router_xlate's
    of_dma_xlate handling (git-fixes).

  - dmaengine: pl330: Fix burst length if burst size is
    smaller than bus width (git-fixes).

  - dmaengine: tegra-apb: Prevent race conditions on
    channel's freeing (git-fixes).

  - dmaengine: zynqmp_dma: fix burst length configuration
    (git-fixes).

  - dm crypt: avoid truncating the logical block size (git
    fixes (block drivers)).

  - dm: fix redundant IO accounting for bios that need
    splitting (git fixes (block drivers)).

  - dm integrity: fix a deadlock due to offloading to an
    incorrect workqueue (git fixes (block drivers)).

  - dm integrity: fix integrity recalculation that is
    improperly skipped (git fixes (block drivers)).

  - dm: report suspended device during destroy (git fixes
    (block drivers)).

  - dm rq: do not call blk_mq_queue_stopped() in
    dm_stop_queue() (git fixes (block drivers)).

  - dm: use noio when sending kobject event (git fixes
    (block drivers)).

  - dm writecache: add cond_resched to loop in
    persistent_memory_claim() (git fixes (block drivers)).

  - dm writecache: correct uncommitted_block when discarding
    uncommitted entry (git fixes (block drivers)).

  - dm zoned: assign max_io_len correctly (git fixes (block
    drivers)).

  - drivers: char: tlclk.c: Avoid data race between init and
    interrupt handler (git-fixes).

  - Drivers: hv: Specify receive buffer size using Hyper-V
    page size (bsc#1176877).

  - Drivers: hv: vmbus: Add timeout to vmbus_wait_for_unload
    (git-fixes).

  - drivers: net: add missing interrupt.h include
    (git-fixes).

  - drivers/net/ethernet/marvell/mvmdio.c: Fix non OF case
    (git-fixes).

  - drivers/net/wan/x25_asy: Fix to make it work
    (networking-stable-20_07_29).

  - drm/amd/display: dal_ddc_i2c_payloads_create can fail
    causing panic (git-fixes).

  - drm/amd/display: fix ref count leak in amdgpu_drm_ioctl
    (git-fixes).

  - drm/amdgpu/display: fix ref count leak when
    pm_runtime_get_sync fails (git-fixes).

  - drm/amdgpu: Fix buffer overflow in INFO ioctl
    (git-fixes).

  - drm/amdgpu: Fix bug in reporting voltage for CIK
    (git-fixes).

  - drm/amdgpu: fix ref count leak in amdgpu_driver_open_kms
    (git-fixes).

  - drm/amdgpu: increase atombios cmd timeout (git-fixes).

  - drm/amdgpu/powerplay: fix AVFS handling with custom
    powerplay table (git-fixes).

  - drm/amdgpu/powerplay/smu7: fix AVFS handling with custom
    powerplay table (git-fixes).

  - drm/amdkfd: fix a memory leak issue (git-fixes).

  - drm/amdkfd: Fix reference count leaks (git-fixes).

  - drm/amd/pm: correct Vega10 swctf limit setting
    (git-fixes).

  - drm/amd/pm: correct Vega12 swctf limit setting
    (git-fixes).

  - drm/ast: Initialize DRAM type before posting GPU
    (bsc#1113956) &#9;* context changes

  - drm/mediatek: Add exception handing in mtk_drm_probe()
    if component init fail (git-fixes).

  - drm/mediatek: Add missing put_device() call in
    mtk_hdmi_dt_parse_pdata() (git-fixes).

  - drm/msm/a5xx: Always set an OPP supported hardware value
    (git-fixes).

  - drm/msm: add shutdown support for display
    platform_driver (git-fixes).

  - drm/msm: Disable preemption on all 5xx targets
    (git-fixes).

  - drm/msm: fix leaks if initialization fails (git-fixes).

  - drm/msm/gpu: make ringbuffer readonly (bsc#1112178)
    &#9;* context changes

  - drm/nouveau/debugfs: fix runtime pm imbalance on error
    (git-fixes).

  - drm/nouveau/dispnv50: fix runtime pm imbalance on error
    (git-fixes).

  - drm/nouveau/drm/noveau: fix reference count leak in
    nouveau_fbcon_open (git-fixes).

  - drm/nouveau: Fix reference count leak in
    nouveau_connector_detect (git-fixes).

  - drm/nouveau: fix reference count leak in
    nv50_disp_atomic_commit (git-fixes).

  - drm/nouveau: fix runtime pm imbalance on error
    (git-fixes).

  - drm/omap: fix possible object reference leak
    (git-fixes).

  - drm/radeon: fix multiple reference count leak
    (git-fixes).

  - drm/radeon: Prefer lower feedback dividers (git-fixes).

  - drm/radeon: revert 'Prefer lower feedback dividers'
    (git-fixes).

  - drm/sun4i: Fix dsi dcs long write function (git-fixes).

  - drm/sun4i: sun8i-csc: Secondary CSC register correction
    (git-fixes).

  - drm/tve200: Stabilize enable/disable (git-fixes).

  - drm/vc4/vc4_hdmi: fill ASoC card owner (git-fixes).

  - e1000: Do not perform reset in reset_task if we are
    already down (git-fixes).

  - EDAC: Fix reference count leaks (bsc#1112178).

  - fbcon: prevent user font height or width change from
    causing (bsc#1112178)

  - Fix error in kabi fix for: NFSv4: Fix OPEN / CLOSE race
    (bsc#1176950).

  - ftrace: Move RCU is watching check after recursion check
    (git-fixes).

  - ftrace: Setup correct FTRACE_FL_REGS flags for module
    (git-fixes).

  - gma/gma500: fix a memory disclosure bug due to
    uninitialized bytes (git-fixes).

  - gpio: tc35894: fix up tc35894 interrupt configuration
    (git-fixes).

  - gtp: add missing gtp_encap_disable_sock() in
    gtp_encap_enable() (git-fixes).

  - gtp: fix Illegal context switch in RCU read-side
    critical section (git-fixes).

  - gtp: fix use-after-free in gtp_newlink() (git-fixes).

  - HID: hiddev: Fix slab-out-of-bounds write in
    hiddev_ioctl_usage() (git-fixes).

  - hsr: use netdev_err() instead of WARN_ONCE()
    (bsc#1176659).

  - hv_utils: drain the timesync packets on
    onchannelcallback (bsc#1176877).

  - hv_utils: return error if host timesysnc update is stale
    (bsc#1176877).

  - hwmon: (applesmc) check status earlier (git-fixes).

  - i2c: core: Do not fail PRP0001 enumeration when no ID
    table exist (git-fixes).

  - i2c: cpm: Fix i2c_ram structure (git-fixes).

  - ibmvnic: add missing parenthesis in do_reset()
    (bsc#1176700 ltc#188140).

  - ieee802154/adf7242: check status of adf7242_read_reg
    (git-fixes).

  - ieee802154: fix one possible memleak in
    ca8210_dev_com_init (git-fixes).

  - iio:accel:bmc150-accel: Fix timestamp alignment and
    prevent data leak (git-fixes).

  - iio: accel: kxsd9: Fix alignment of local buffer
    (git-fixes).

  - iio:accel:mma7455: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:adc:ina2xx Fix timestamp alignment issue
    (git-fixes).

  - iio: adc: mcp3422: fix locking on error path
    (git-fixes).

  - iio: adc: mcp3422: fix locking scope (git-fixes).

  - iio:adc:ti-adc081c Fix alignment and data leak issues
    (git-fixes).

  - iio: adc: ti-ads1015: fix conversion when CONFIG_PM is
    not set (git-fixes).

  - iio: improve IIO_CONCENTRATION channel type description
    (git-fixes).

  - iio:light:ltr501 Fix timestamp alignment issue
    (git-fixes).

  - iio:light:max44000 Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:magnetometer:ak8975 Fix alignment and data leak
    issues (git-fixes).

  - include: add additional sizes (bsc#1094244 ltc#168122).

  - iommu/amd: Fix IOMMU AVIC not properly update the is_run
    bit in IRTE (bsc#1177293).

  - iommu/amd: Fix potential @entry null deref
    (bsc#1177294).

  - iommu/amd: Print extended features in one line to fix
    divergent log levels (bsc#1176316).

  - iommu/amd: Re-factor guest virtual APIC (de-)activation
    code (bsc#1177291).

  - iommu/amd: Restore IRTE.RemapEn bit after programming
    IRTE (bsc#1176317).

  - iommu/amd: Restore IRTE.RemapEn bit for
    amd_iommu_activate_guest_mode (bsc#1177295).

  - iommu/amd: Use cmpxchg_double() when updating 128-bit
    IRTE (bsc#1176318).

  - iommu/exynos: add missing put_device() call in
    exynos_iommu_of_xlate() (bsc#1177296).

  - iommu/omap: Check for failure of a call to
    omap_iommu_dump_ctx (bsc#1176319).

  - iommu/vt-d: Serialize IOMMU GCMD register modifications
    (bsc#1176320).

  - kernel-binary.spec.in: Package the obj_install_dir as
    explicit filelist.

  - kernel-syms.spec.in: Also use bz compression
    (boo#1175882).

  - KVM: arm64: Change 32-bit handling of VM system
    registers (jsc#SLE-4084).

  - KVM: arm64: Cleanup __activate_traps and
    __deactive_traps for VHE and non-VHE (jsc#SLE-4084).

  - KVM: arm64: Configure c15, PMU, and debug register traps
    on cpu load/put for VHE (jsc#SLE-4084).

  - KVM: arm64: Defer saving/restoring 32-bit sysregs to
    vcpu load/put (jsc#SLE-4084).

  - KVM: arm64: Defer saving/restoring 64-bit sysregs to
    vcpu load/put on VHE (jsc#SLE-4084).

  - KVM: arm64: Directly call VHE and non-VHE FPSIMD enabled
    functions (jsc#SLE-4084).

  - KVM: arm64: Do not deactivate VM on VHE systems
    (jsc#SLE-4084).

  - KVM: arm64: Do not save the host ELR_EL2 and SPSR_EL2 on
    VHE systems (jsc#SLE-4084).

  - KVM: arm64: Factor out fault info population and gic
    workarounds (jsc#SLE-4084).

  - KVM: arm64: Fix order of vcpu_write_sys_reg() arguments
    (jsc#SLE-4084).

  - KVM: arm64: Forbid kprobing of the VHE world-switch code
    (jsc#SLE-4084).

  - KVM: arm64: Improve debug register save/restore flow
    (jsc#SLE-4084).

  - KVM: arm64: Introduce framework for accessing deferred
    sysregs (jsc#SLE-4084).

  - KVM: arm64: Introduce separate VHE/non-VHE sysreg
    save/restore functions (jsc#SLE-4084).

  - KVM: arm64: Introduce VHE-specific kvm_vcpu_run
    (jsc#SLE-4084).

  - KVM: arm64: Move common VHE/non-VHE trap config in
    separate functions (jsc#SLE-4084).

  - KVM: arm64: Move debug dirty flag calculation out of
    world switch (jsc#SLE-4084).

  - KVM: arm64: Move HCR_INT_OVERRIDE to default HCR_EL2
    guest flag (jsc#SLE-4084).

  - KVM: arm64: Move userspace system registers into
    separate function (jsc#SLE-4084).

  - KVM: arm64: Prepare to handle deferred save/restore of
    32-bit registers (jsc#SLE-4084).

  - KVM: arm64: Prepare to handle deferred save/restore of
    ELR_EL1 (jsc#SLE-4084).

  - KVM: arm64: Remove kern_hyp_va() use in VHE switch
    function (jsc#SLE-4084).

  - KVM: arm64: Remove noop calls to timer save/restore from
    VHE switch (jsc#SLE-4084).

  - KVM: arm64: Rework hyp_panic for VHE and non-VHE
    (jsc#SLE-4084).

  - KVM: arm64: Rewrite sysreg alternatives to static keys
    (jsc#SLE-4084).

  - KVM: arm64: Rewrite system register accessors to
    read/write functions (jsc#SLE-4084).

  - KVM: arm64: Slightly improve debug save/restore
    functions (jsc#SLE-4084).

  - KVM: arm64: Unify non-VHE host/guest sysreg save and
    restore functions (jsc#SLE-4084).

  - KVM: arm64: Write arch.mdcr_el2 changes since last
    vcpu_load on VHE (jsc#SLE-4084).

  - KVM: arm/arm64: Avoid vcpu_load for other vcpu ioctls
    than KVM_RUN (jsc#SLE-4084).

  - KVM: arm/arm64: Avoid VGICv3 save/restore on VHE with no
    IRQs (jsc#SLE-4084).

  - KVM: arm/arm64: Get rid of vcpu->arch.irq_lines
    (jsc#SLE-4084).

  - KVM: arm/arm64: Handle VGICv3 save/restore from the main
    VGIC code on VHE (jsc#SLE-4084).

  - KVM: arm/arm64: Move vcpu_load call after
    kvm_vcpu_first_run_init (jsc#SLE-4084).

  - KVM: arm/arm64: Move VGIC APR save/restore to vgic
    put/load (jsc#SLE-4084).

  - KVM: arm/arm64: Prepare to handle deferred save/restore
    of SPSR_EL1 (jsc#SLE-4084).

  - KVM: arm/arm64: Remove leftover comment from
    kvm_vcpu_run_vhe (jsc#SLE-4084).

  - KVM: introduce kvm_arch_vcpu_async_ioctl (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_get_fpu (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_get_mpstate (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_get_regs (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific kvm_arch_vcpu_ioctl
    (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_run (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_set_fpu (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_set_guest_debug (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_set_mpstate (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_set_regs (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_set_sregs (jsc#SLE-4084).

  - KVM: Move vcpu_load to arch-specific
    kvm_arch_vcpu_ioctl_translate (jsc#SLE-4084).

  - KVM: PPC: Fix compile error that occurs when
    CONFIG_ALTIVEC=n (jsc#SLE-4084).

  - KVM: Prepare for moving vcpu_load/vcpu_put into arch
    specific code (jsc#SLE-4084).

  - KVM: SVM: Add a dedicated INVD intercept routine
    (bsc#1112178).

  - KVM: SVM: Fix disable pause loop exit/pause filtering
    capability on SVM (bsc#1176321).

  - KVM: SVM: fix svn_pin_memory()'s use of
    get_user_pages_fast() (bsc#1112178).

  - KVM: Take vcpu->mutex outside vcpu_load (jsc#SLE-4084).

  - libceph: allow setting abort_on_full for rbd
    (bsc#1169972).

  - libnvdimm: cover up nvdimm_security_ops changes
    (bsc#1171742).

  - libnvdimm: cover up struct nvdimm changes (bsc#1171742).

  - libnvdimm/security, acpi/nfit: unify zero-key for all
    security commands (bsc#1171742).

  - libnvdimm/security: fix a typo (bsc#1171742
    bsc#1167527).

  - libnvdimm/security: Introduce a 'frozen' attribute
    (bsc#1171742).

  - lib/raid6: use vdupq_n_u8 to avoid endianness warnings
    (git fixes (block drivers)).

  - livepatch: Add -fdump-ipa-clones to build (). Add
    support for -fdump-ipa-clones GCC option. Update config
    files accordingly.

  - mac802154: tx: fix use-after-free (git-fixes).

  - md: raid0/linear: fix dereference before null check on
    pointer mddev (git fixes (block drivers)).

  - media: davinci: vpif_capture: fix potential double free
    (git-fixes).

  - media: pci: ttpci: av7110: fix possible buffer overflow
    caused by bad DMA value in debiirq() (git-fixes).

  - media: smiapp: Fix error handling at NVM reading
    (git-fixes).

  - media: ti-vpe: cal: Restrict DMA to avoid memory
    corruption (git-fixes).

  - mfd: intel-lpss: Add Intel Emmitsburg PCH PCI IDs
    (git-fixes).

  - mfd: mfd-core: Protect against NULL call-back function
    pointer (git-fixes).

  - mm: Avoid calling build_all_zonelists_init under hotplug
    context (bsc#1154366).

  - mmc: cqhci: Add cqhci_deactivate() (git-fixes).

  - mmc: sdhci-msm: Add retries when all tuning phases are
    found valid (git-fixes).

  - mmc: sdhci-pci: Fix SDHCI_RESET_ALL for CQHCI for Intel
    GLK-based controllers (git-fixes).

  - mmc: sdhci: Workaround broken command queuing on Intel
    GLK based IRBIS models (git-fixes).

  - mm/page_alloc.c: fix a crash in free_pages_prepare()
    (git fixes (mm/pgalloc)).

  - mm/vmalloc.c: move 'area->pages' after if statement (git
    fixes (mm/vmalloc)).

  - mtd: cfi_cmdset_0002: do not free cfi->cfiq in error
    path of cfi_amdstd_setup() (git-fixes).

  - mtd: lpddr: Fix a double free in probe() (git-fixes).

  - mtd: phram: fix a double free issue in error path
    (git-fixes).

  - mtd: properly check all write ioctls for permissions
    (git-fixes).

  - net: 8390: Fix manufacturer name in Kconfig help text
    (git-fixes).

  - net: amd: fix return type of ndo_start_xmit function
    (git-fixes).

  - net/amd: Remove useless driver version (git-fixes).

  - net: amd-xgbe: fix comparison to bitshift when dealing
    with a mask (git-fixes).

  - net: amd-xgbe: Get rid of custom hex_dump_to_buffer()
    (git-fixes).

  - net: apple: Fix manufacturer name in Kconfig help text
    (git-fixes).

  - net: broadcom: Fix manufacturer name in Kconfig help
    text (git-fixes).

  - net: dsa: b53: Fix sparse warnings in b53_mmap.c
    (git-fixes).

  - net: dsa: b53: Use strlcpy() for ethtool::get_strings
    (git-fixes).

  - net: dsa: mv88e6xxx: fix 6085 frame mode masking
    (git-fixes).

  - net: dsa: mv88e6xxx: Fix interrupt masking on removal
    (git-fixes).

  - net: dsa: mv88e6xxx: Fix name of switch 88E6141
    (git-fixes).

  - net: dsa: mv88e6xxx: fix shift of FID bits in
    mv88e6185_g1_vtu_loadpurge() (git-fixes).

  - net: dsa: mv88e6xxx: Unregister MDIO bus on error path
    (git-fixes).

  - net: dsa: qca8k: Allow overwriting CPU port setting
    (git-fixes).

  - net: dsa: qca8k: Enable RXMAC when bringing up a port
    (git-fixes).

  - net: dsa: qca8k: Force CPU port to its highest bandwidth
    (git-fixes).

  - net: ethernet: mlx4: Fix memory allocation in
    mlx4_buddy_init() (git-fixes).

  - net: fs_enet: do not call phy_stop() in interrupts
    (git-fixes).

  - net: initialize fastreuse on inet_inherit_port
    (networking-stable-20_08_15).

  - net: lan78xx: Bail out if lan78xx_get_endpoints fails
    (git-fixes).

  - net: lan78xx: replace bogus endpoint lookup
    (networking-stable-20_08_08).

  - net: lio_core: fix potential sign-extension overflow on
    large shift (git-fixes).

  - net/mlx5: Add meaningful return codes to status_to_err
    function (git-fixes).

  - net/mlx5: E-Switch, Use correct flags when configuring
    vlan (git-fixes).

  - net/mlx5e: XDP, Avoid checksum complete when XDP prog is
    loaded (git-fixes).

  - net: mvmdio: defer probe of orion-mdio if a clock is not
    ready (git-fixes).

  - net: mvneta: fix mtu change on port without link
    (git-fixes).

  - net-next: ax88796: Do not free IRQ in ax_remove()
    (already freed in ax_close()) (git-fixes).

  - net/nfc/rawsock.c: add CAP_NET_RAW check
    (networking-stable-20_08_15).

  - net: qca_spi: Avoid packet drop during initial sync
    (git-fixes).

  - net: qca_spi: Make sure the QCA7000 reset is triggered
    (git-fixes).

  - net: refactor bind_bucket fastreuse into helper
    (networking-stable-20_08_15).

  - net/smc: fix dmb buffer shortage (git-fixes).

  - net/smc: fix restoring of fallback changes (git-fixes).

  - net/smc: fix sock refcounting in case of termination
    (git-fixes).

  - net/smc: improve close of terminated socket (git-fixes).

  - net/smc: Prevent kernel-infoleak in __smc_diag_dump()
    (git-fixes).

  - net/smc: remove freed buffer from list (git-fixes).

  - net/smc: reset sndbuf_desc if freed (git-fixes).

  - net/smc: set rx_off for SMCR explicitly (git-fixes).

  - net/smc: switch smcd_dev_list spinlock to mutex
    (git-fixes).

  - net/smc: tolerate future SMCD versions (git-fixes).

  - net: stmmac: call correct function in
    stmmac_mac_config_rx_queues_routing() (git-fixes).

  - net: stmmac: Disable ACS Feature for GMAC >= 4
    (git-fixes).

  - net: stmmac: do not stop NAPI processing when dropping a
    packet (git-fixes).

  - net: stmmac: dwmac4: fix flow control issue (git-fixes).

  - net: stmmac: dwmac_lib: fix interchanged sleep/timeout
    values in DMA reset function (git-fixes).

  - net: stmmac: dwmac-meson8b: Add missing boundary to
    RGMII TX clock array (git-fixes).

  - net: stmmac: dwmac-meson8b: fix internal RGMII clock
    configuration (git-fixes).

  - net: stmmac: dwmac-meson8b: fix setting the RGMII TX
    clock on Meson8b (git-fixes).

  - net: stmmac: dwmac-meson8b: Fix the RGMII TX delay on
    Meson8b/8m2 SoCs (git-fixes).

  - net: stmmac: dwmac-meson8b: only configure the clocks in
    RGMII mode (git-fixes).

  - net: stmmac: dwmac-meson8b: propagate rate changes to
    the parent clock (git-fixes).

  - net: stmmac: Fix error handling path in
    'alloc_dma_rx_desc_resources()' (git-fixes).

  - net: stmmac: Fix error handling path in
    'alloc_dma_tx_desc_resources()' (git-fixes).

  - net: stmmac: rename dwmac4_tx_queue_routing() to match
    reality (git-fixes).

  - net: stmmac: set MSS for each tx DMA channel
    (git-fixes).

  - net: stmmac: Use correct values in TQS/RQS fields
    (git-fixes).

  - net-sysfs: add a newline when printing 'tx_timeout' by
    sysfs (networking-stable-20_07_29).

  - net: systemport: Fix software statistics for SYSTEMPORT
    Lite (git-fixes).

  - net: systemport: Fix sparse warnings in
    bcm_sysport_insert_tsb() (git-fixes).

  - net: tc35815: Explicitly check NET_IP_ALIGN is not zero
    in tc35815_rx (git-fixes).

  - net: tulip: de4x5: Drop redundant MODULE_DEVICE_TABLE()
    (git-fixes).

  - net: ucc_geth - fix Oops when changing number of buffers
    in the ring (git-fixes).

  - NFSv4: do not mark all open state for recovery when
    handling recallable state revoked flag (bsc#1176935).

  - nvme-fc: set max_segments to lldd max value
    (bsc#1176038).

  - nvme-pci: override the value of the controller's numa
    node (bsc#1176507).

  - ocfs2: give applications more IO opportunities during
    fstrim (bsc#1175228).

  - omapfb: fix multiple reference count leaks due to
    pm_runtime_get_sync (git-fixes).

  - PCI/ASPM: Allow re-enabling Clock PM (git-fixes).

  - PCI: Fix pci_create_slot() reference count leak
    (git-fixes).

  - PCI: qcom: Add missing ipq806x clocks in PCIe driver
    (git-fixes).

  - PCI: qcom: Add missing reset for ipq806x (git-fixes).

  - PCI: qcom: Add support for tx term offset for rev 2.1.0
    (git-fixes).

  - PCI: qcom: Define some PARF params needed for ipq8064
    SoC (git-fixes).

  - PCI: rcar: Fix incorrect programming of OB windows
    (git-fixes).

  - phy: samsung: s5pv210-usb2: Add delay after reset
    (git-fixes).

  - pinctrl: mvebu: Fix i2c sda definition for 98DX3236
    (git-fixes).

  - platform/x86: fix kconfig dependency warning for
    FUJITSU_LAPTOP (git-fixes).

  - platform/x86: thinkpad_acpi: initialize tp_nvram_state
    variable (git-fixes).

  - platform/x86: thinkpad_acpi: re-initialize ACPI buffer
    size when reuse (git-fixes).

  - powerpc/64s: Blacklist functions invoked on a trap
    (bsc#1094244 ltc#168122).

  - powerpc/64s: Fix HV NMI vs HV interrupt recoverability
    test (bsc#1094244 ltc#168122).

  - powerpc/64s: Fix unrelocated interrupt trampoline
    address test (bsc#1094244 ltc#168122).

  - powerpc/64s: Include <asm/nmi.h> header file to fix a
    warning (bsc#1094244 ltc#168122).

  - powerpc/64s: machine check do not trace real-mode
    handler (bsc#1094244 ltc#168122).

  - powerpc/64s: sreset panic if there is no debugger or
    crash dump handlers (bsc#1094244 ltc#168122).

  - powerpc/64s: system reset interrupt preserve HSRRs
    (bsc#1094244 ltc#168122).

  - powerpc: Add cputime_to_nsecs() (bsc#1065729).

  - powerpc/book3s64/radix: Add kernel command line option
    to disable radix GTSE (bsc#1055186 ltc#153436).

  - powerpc/book3s64/radix: Fix boot failure with large
    amount of guest memory (bsc#1176022 ltc#187208).

  - powerpc: Implement ftrace_enabled() helpers (bsc#1094244
    ltc#168122).

  - powerpc/init: Do not advertise radix during
    client-architecture-support (bsc#1055186 ltc#153436 ).

  - powerpc/kernel: Cleanup machine check function
    declarations (bsc#1065729).

  - powerpc/kernel: Enables memory hot-remove after reboot
    on pseries guests (bsc#1177030 ltc#187588).

  - powerpc/mm: Enable radix GTSE only if supported
    (bsc#1055186 ltc#153436).

  - powerpc/mm: Limit resize_hpt_for_hotplug() call to hash
    guests only (bsc#1177030 ltc#187588).

  - powerpc/mm: Move book3s64 specifics in subdirectory
    mm/book3s64 (bsc#1176022 ltc#187208).

  - powerpc/powernv: Remove real mode access limit for early
    allocations (bsc#1176022 ltc#187208).

  - powerpc/prom: Enable Radix GTSE in cpu pa-features
    (bsc#1055186 ltc#153436).

  - powerpc/pseries/le: Work around a firmware quirk
    (bsc#1094244 ltc#168122).

  - powerpc/pseries: lift RTAS limit for radix (bsc#1176022
    ltc#187208).

  - powerpc/pseries: Limit machine check stack to 4GB
    (bsc#1094244 ltc#168122).

  - powerpc/pseries: Machine check use rtas_call_unlocked()
    with args on stack (bsc#1094244 ltc#168122).

  - powerpc/pseries: radix is not subject to RMA limit,
    remove it (bsc#1176022 ltc#187208).

  - powerpc/pseries/ras: Avoid calling rtas_token() in NMI
    paths (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: Fix FWNMI_VALID off by one
    (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: fwnmi avoid modifying r3 in error
    case (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: fwnmi sreset should not interlock
    (bsc#1094244 ltc#168122).

  - powerpc/traps: Do not trace system reset (bsc#1094244
    ltc#168122).

  - powerpc/traps: fix recoverability of machine check
    handling on book3s/32 (bsc#1094244 ltc#168122).

  - powerpc/traps: Make unrecoverable NMIs die instead of
    panic (bsc#1094244 ltc#168122).

  - powerpc/xmon: Use `dcbf` inplace of `dcbi` instruction
    for 64bit Book3S (bsc#1065729).

  - power: supply: max17040: Correct voltage reading
    (git-fixes).

  - rcu: Do RCU GP kthread self-wakeup from softirq and
    interrupt (git fixes (rcu)).

  - regulator: push allocation in
    set_consumer_device_supply() out of lock (git-fixes).

  - Revert 'ALSA: hda: Add support for Loongson 7A1000
    controller' (git-fixes).

  - Revert 'ALSA: usb-audio: Disable Lenovo P620 Rear
    line-in volume control' (git-fixes).

  - Revert 'i2c: cadence: Fix the hold bit setting'
    (git-fixes).

  - rpadlpar_io: Add MODULE_DESCRIPTION entries to kernel
    modules (bsc#1176869 ltc#188243).

  - rpm/constraints.in: recognize also kernel-source-azure
    (bsc#1176732)

  - rpm/kernel-binary.spec.in: Also sign ppc64 kernels
    (jsc#SLE-15857 jsc#SLE-13618).

  - rpm/kernel-cert-subpackage: add CA check on key
    enrollment (bsc#1173115) To avoid the unnecessary key
    enrollment, when enrolling the signing key of the kernel
    package, '--ca-check' is added to mokutil so that
    mokutil will ignore the request if the CA of the signing
    key already exists in MokList or UEFI db. Since the
    macro, %_suse_kernel_module_subpackage, is only defined
    in a kernel module package (KMP), it's used to determine
    whether the %post script is running in a kernel package,
    or a kernel module package.

  - rpm/kernel-source.spec.in: Also use bz compression
    (boo#1175882).

  - rpm/macros.kernel-source: pass -c proerly in kernel
    module package (bsc#1176698) The '-c' option wasn't
    passed down to %_kernel_module_package so the ueficert
    subpackage wasn't generated even if the certificate is
    specified in the spec file.

  - rtc: ds1374: fix possible race condition (git-fixes).

  - rtlwifi: rtl8192cu: Prevent leaking urb (git-fixes).

  - rxrpc: Fix race between recvmsg and sendmsg on immediate
    call failure (networking-stable-20_08_08).

  - rxrpc: Fix sendmsg() returning EPIPE due to recvmsg()
    returning ENODATA (networking-stable-20_07_29).

  - s390/mm: fix huge pte soft dirty copying (git-fixes).

  - s390/qeth: do not process empty bridge port events
    (git-fixes).

  - s390/qeth: integrate RX refill worker with NAPI
    (git-fixes).

  - s390/qeth: tolerate pre-filled RX buffer (git-fixes).

  - scsi: fcoe: Memory leak fix in fcoe_sysfs_fcf_del()
    (bsc#1174899).

  - scsi: fnic: Do not call 'scsi_done()' for unhandled
    commands (bsc#1168468, bsc#1171675).

  - scsi: ibmvfc: Avoid link down on FS9100 canister reboot
    (bsc#1176962 ltc#188304).

  - scsi: ibmvfc: Use compiler attribute defines instead of
    __attribute__() (bsc#1176962 ltc#188304).

  - scsi: iscsi: iscsi_tcp: Avoid holding spinlock while
    calling getpeername() (bsc#1177258).

  - scsi: libfc: Fix for double free() (bsc#1174899).

  - scsi: libfc: free response frame from GPN_ID
    (bsc#1174899).

  - scsi: libfc: Free skb in fc_disc_gpn_id_resp() for valid
    cases (bsc#1174899).

  - scsi: lpfc: Add dependency on CPU_FREQ (git-fixes).

  - scsi: lpfc: Fix setting IRQ affinity with an empty CPU
    mask (git-fixes).

  - scsi: qla2xxx: Fix regression on sparc64 (git-fixes).

  - scsi: qla2xxx: Fix the return value (bsc#1171688).

  - scsi: qla2xxx: Fix the size used in a
    'dma_free_coherent()' call (bsc#1171688).

  - scsi: qla2xxx: Fix wrong return value in
    qla_nvme_register_hba() (bsc#1171688).

  - scsi: qla2xxx: Fix wrong return value in
    qlt_chk_unresolv_exchg() (bsc#1171688).

  - scsi: qla2xxx: Handle incorrect entry_type entries
    (bsc#1171688).

  - scsi: qla2xxx: Log calling function name in
    qla2x00_get_sp_from_handle() (bsc#1171688).

  - scsi: qla2xxx: Remove pci-dma-compat wrapper API
    (bsc#1171688).

  - scsi: qla2xxx: Remove redundant variable initialization
    (bsc#1171688).

  - scsi: qla2xxx: Remove superfluous memset()
    (bsc#1171688).

  - scsi: qla2xxx: Simplify return value logic in
    qla2x00_get_sp_from_handle() (bsc#1171688).

  - scsi: qla2xxx: Suppress two recently introduced compiler
    warnings (git-fixes).

  - scsi: qla2xxx: Warn if done() or free() are called on an
    already freed srb (bsc#1171688).

  - sdhci: tegra: Remove SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK
    for Tegra186 (git-fixes).

  - sdhci: tegra: Remove SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK
    for Tegra210 (git-fixes).

  - serial: 8250: 8250_omap: Terminate DMA before pushing
    data on RX timeout (git-fixes).

  - serial: 8250_omap: Fix sleeping function called from
    invalid context during probe (git-fixes).

  - serial: 8250_port: Do not service RX FIFO if throttled
    (git-fixes).

  - Set CONFIG_HAVE_KVM_VCPU_ASYNC_IOCTL=y (jsc#SLE-4084).

  - smb3: Honor persistent/resilient handle flags for
    multiuser mounts (bsc#1176546).

  - smb3: Honor 'seal' flag for multiuser mounts
    (bsc#1176545).

  - smb3: warn on confusing error scenario with sec=krb5
    (bsc#1176548).

  - staging:r8188eu: avoid skb_clone for amsdu to msdu
    conversion (git-fixes).

  - stmmac: Do not access tx_q->dirty_tx before
    netif_tx_lock (git-fixes).

  - tcp: apply a floor of 1 for RTT samples from TCP
    timestamps (networking-stable-20_08_08).

  - thermal: ti-soc-thermal: Fix bogus thermal shutdowns for
    omap4430 (git-fixes).

  - tools/power/cpupower: Fix initializer override in
    hsw_ext_cstates (bsc#1112178).

  - usb: core: fix slab-out-of-bounds Read in
    read_descriptors (git-fixes).

  - usb: dwc3: Increase timeout for CmdAct cleared by device
    controller (git-fixes).

  - usb: EHCI: ehci-mv: fix error handling in
    mv_ehci_probe() (git-fixes).

  - usb: EHCI: ehci-mv: fix less than zero comparison of an
    unsigned int (git-fixes).

  - usb: Fix out of sync data toggle if a configured device
    is reconfigured (git-fixes).

  - usb: gadget: f_ncm: add bounds checks to
    ncm_unwrap_ntb() (git-fixes).

  - usb: gadget: f_ncm: Fix NDP16 datagram validation
    (git-fixes).

  - usb: gadget: u_f: add overflow checks to VLA macros
    (git-fixes).

  - usb: gadget: u_f: Unbreak offset calculation in VLAs
    (git-fixes).

  - usb: hso: check for return value in
    hso_serial_common_create() (networking-stable-20_08_08).

  - usblp: fix race between disconnect() and read()
    (git-fixes).

  - usb: lvtest: return proper error code in probe
    (git-fixes).

  - usbnet: ipheth: fix potential NULL pointer dereference
    in ipheth_carrier_set (git-fixes).

  - usb: qmi_wwan: add D-Link DWM-222 A2 device ID
    (git-fixes).

  - usb: quirks: Add no-lpm quirk for another Raydium
    touchscreen (git-fixes).

  - usb: quirks: Add USB_QUIRK_IGNORE_REMOTE_WAKEUP quirk
    for BYD zhaoxin notebook (git-fixes).

  - usb: quirks: Ignore duplicate endpoint on Sound Devices
    MixPre-D (git-fixes).

  - usb: serial: ftdi_sio: add IDs for Xsens Mti USB
    converter (git-fixes).

  - usb: serial: option: add support for
    SIM7070/SIM7080/SIM7090 modules (git-fixes).

  - usb: serial: option: support dynamic Quectel USB
    compositions (git-fixes).

  - usb: sisusbvga: Fix a potential UB casued by left
    shifting a negative value (git-fixes).

  - usb: storage: Add unusual_uas entry for Sony PSZ drives
    (git-fixes).

  - usb: typec: ucsi: acpi: Check the _DEP dependencies
    (git-fixes).

  - usb: uas: Add quirk for PNY Pro Elite (git-fixes).

  - usb: UAS: fix disconnect by unplugging a hub
    (git-fixes).

  - usb: yurex: Fix bad gfp argument (git-fixes).

  - vgacon: remove software scrollback support
    (bsc#1176278).

  - video: fbdev: fix OOB read in vga_8planes_imageblit()
    (git-fixes).

  - virtio-blk: free vblk-vqs in error path of
    virtblk_probe() (git fixes (block drivers)).

  - vmxnet3: fix cksum offload issues for non-udp tunnels
    (git-fixes).

  - vrf: prevent adding upper devices (git-fixes).

  - vxge: fix return of a free'd memblock on a failed dma
    mapping (git-fixes).

  - x86/fsgsbase/64: Fix NULL deref in 86_fsgsbase_read_task
    (bsc#1112178).

  - xen: do not reschedule in preemption off sections
    (bsc#1175749).

  - xen/events: do not use chip_data for legacy IRQs
    (bsc#1065600).

  - XEN uses irqdesc::irq_data_common::handler_data to store
    a per interrupt XEN data pointer which contains XEN
    specific information (bsc#1065600).

  - xgbe: no need to check return value of debugfs_create
    functions (git-fixes).

  - xgbe: switch to more generic VxLAN detection
    (git-fixes).

  - xhci: Do warm-reset when both CAS and XDEV_RESUME are
    set (git-fixes).

  - yam: fix possible memory leak in yam_init_driver
    (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169972"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177121"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962356"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.71.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.71.2") ) flag++;

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
