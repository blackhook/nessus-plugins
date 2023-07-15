#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2507.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131061);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-16231", "CVE-2019-17055", "CVE-2019-18805");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2507)");
  script_summary(english:"Check for the openSUSE-2019-2507 patch");

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

  - CVE-2019-0154: An unprotected read access to i915
    registers has been fixed that could have been abused to
    facilitate a local denial-of-service attack.
    (bsc#1135966)

  - CVE-2019-0155: A privilege escalation vulnerability has
    been fixed in the i915 module that allowed batch buffers
    from user mode to gain super user privileges.
    (bsc#1135967)

  - CVE-2019-16231: drivers/net/fjes/fjes_main.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150466).

  - CVE-2019-18805: There was a net/ipv4/tcp_input.c signed
    integer overflow in tcp_ack_update_rtt() when userspace
    writes a very large integer to
    /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading to a denial
    of service or possibly unspecified other impact, aka
    CID-19fad20d15a6 (bnc#1156187).

  - CVE-2019-17055: base_sock_create in
    drivers/isdn/mISDN/socket.c in the AF_ISDN network
    module did not enforce CAP_NET_RAW, which means that
    unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21 (bnc#1152782).

  - CVE-2019-11135: Aborting an asynchronous TSX operation
    on Intel CPUs with Transactional Memory support could be
    used to facilitate sidechannel information leaks out of
    microarchitectural buffers, similar to the previously
    described 'Microarchitectural Data Sampling' attack.

    The Linux kernel was supplemented with the option to
    disable TSX operation altogether (requiring CPU
    Microcode updates on older systems) and better flushing
    of microarchitectural buffers (VERW).

    The set of options available is described in our TID at
    https://www.suse.com/support/kb/doc/?id=7024251

  - CVE-2018-12207: Untrusted virtual machines on Intel CPUs
    could exploit a race condition in the Instruction Fetch
    Unit of the Intel CPU to cause a Machine Exception
    during Page Size Change, causing the CPU core to be
    non-functional.

    The Linux Kernel kvm hypervisor was adjusted to avoid
    page size changes in executable pages by splitting /
    merging huge pages into small pages as needed.

    More information can be found on
    https://www.suse.com/support/kb/doc/?id=7023735

  - CVE-2019-10220: Added sanity checks on the pathnames
    passed to the user space. (bsc#1144903).

The following non-security bugs were fixed :

  - ALSA: bebob: Fix prototype of helper function to return
    negative value (bsc#1051510).

  - ALSA: bebob: fix to detect configured source of sampling
    clock for Focusrite Saffire Pro i/o series (git-fixes).

  - ALSA: firewire-motu: add support for MOTU 4pre
    (bsc#1111666).

  - ALSA: hda/ca0132 - Fix possible workqueue stall
    (bsc#1155836).

  - ALSA: hda/realtek - Add support for ALC623
    (bsc#1051510).

  - ALSA: hda/realtek - Fix 2 front mics of codec 0x623
    (bsc#1051510).

  - ALSA: timer: Fix incorrectly assigned timer instance
    (git-fixes).

  - ALSA: timer: Fix mutex deadlock at releasing card
    (bsc#1051510).

  - ALSA: usb-audio: Add DSD support for Gustard U16/X26 USB
    Interface (bsc#1051510).

  - ALSA: usb-audio: Disable quirks for BOSS Katana
    amplifiers (bsc#1111666).

  - ALSA: usb-audio: Fix copy&paste error in the validator
    (bsc#1111666).

  - arm64: Add decoding macros for CP15_32 and CP15_64 traps
    (jsc#ECO-561).

  - arm64: Add part number for Neoverse N1 (jsc#ECO-561).

  - arm64: Add silicon-errata.txt entry for ARM erratum
    1188873 (jsc#ECO-561).

  - arm64: Add support for new control bits CTR_EL0.DIC and
    CTR_EL0.IDC (jsc#ECO-561,jsc#SLE-10671).

  - arm64: Apply ARM64_ERRATUM_1188873 to Neoverse-N1
    (jsc#ECO-561).

  - arm64: arch_timer: Add workaround for ARM erratum
    1188873 (jsc#ECO-561).

  - arm64: arch_timer: avoid unused function warning
    (jsc#ECO-561).

  - arm64: compat: Add CNTFRQ trap handler (jsc#ECO-561).

  - arm64: compat: Add CNTVCT trap handler (jsc#ECO-561).

  - arm64: compat: Add condition code checks and IT advance
    (jsc#ECO-561).

  - arm64: compat: Add cp15_32 and cp15_64 handler arrays
    (jsc#ECO-561).

  - arm64: compat: Add separate CP15 trapping hook
    (jsc#ECO-561).

  - arm64: compat: Workaround Neoverse-N1 #1542419 for
    compat user-space (jsc#ECO-561,jsc#SLE-10671).

  - arm64: cpu_errata: Remove
    ARM64_MISMATCHED_CACHE_LINE_SIZE
    (jsc#ECO-561,jsc#SLE-10671).

  - arm64/cpufeature: Convert hook_lock to raw_spin_lock_t
    in cpu_enable_ssbs() (jsc#ECO-561).

  - arm64: cpufeature: ctr: Fix cpu capability check for
    late CPUs (jsc#ECO-561,jsc#SLE-10671).

  - arm64: cpufeature: Detect SSBS and advertise to
    userspace (jsc#ECO-561).

  - arm64: cpufeature: Fix handling of CTR_EL0.IDC field
    (jsc#ECO-561,jsc#SLE-10671).

  - arm64: cpufeature: Trap CTR_EL0 access only where it is
    necessary (jsc#ECO-561,jsc#SLE-10671).

  - arm64: cpu: Move errata and feature enable callbacks
    closer to callers (jsc#ECO-561).

  - arm64: entry: Allow handling of undefined instructions
    from EL1 (jsc#ECO-561).

  - arm64: errata: Hide CTR_EL0.DIC on systems affected by
    Neoverse-N1 #1542419 (jsc#ECO-561,jsc#SLE-10671).

  - arm64: Fake the IminLine size on systems affected by
    Neoverse-N1 #1542419 (jsc#ECO-561,jsc#SLE-10671).

  - arm64: Fix mismatched cache line size detection
    (jsc#ECO-561,jsc#SLE-10671).

  - arm64: Fix silly typo in comment (jsc#ECO-561).

  - arm64: fix SSBS sanitization (jsc#ECO-561).

  - arm64: force_signal_inject: WARN if called from kernel
    context (jsc#ECO-561).

  - arm64: Force SSBS on context switch (jsc#ECO-561).

  - arm64: Handle erratum 1418040 as a superset of erratum
    1188873 (jsc#ECO-561).

  - arm64: Introduce sysreg_clear_set() (jsc#ECO-561).

  - arm64: kill change_cpacr() (jsc#ECO-561).

  - arm64: kill config_sctlr_el1() (jsc#ECO-561).

  - arm64: KVM: Add invalidate_icache_range helper
    (jsc#ECO-561,jsc#SLE-10671).

  - arm64: KVM: PTE/PMD S2 XN bit definition
    (jsc#ECO-561,jsc#SLE-10671).

  - arm64: Make ARM64_ERRATUM_1188873 depend on COMPAT
    (jsc#ECO-561).

  - arm64: move SCTLR_EL(1,2) assertions to <asm/sysreg.h>
    (jsc#ECO-561).

  - arm64: Restrict ARM64_ERRATUM_1188873 mitigation to
    AArch32 (jsc#ECO-561).

  - arm64: ssbd: Add support for PSTATE.SSBS rather than
    trapping to EL3 (jsc#ECO-561).

  - arm64: ssbd: Drop #ifdefs for PR_SPEC_STORE_BYPASS
    (jsc#ECO-561).

  - arm: KVM: Add optimized PIPT icache flushing
    (jsc#ECO-561,jsc#SLE-10671).

  - ath10k: assign 'n_cipher_suites = 11' for WCN3990 to
    enable WPA3 (bsc#1111666).

  - brcmfmac: sdio: Disable auto-tuning around commands
    expected to fail (bsc#1111666).

  - brcmfmac: sdio: Do not tune while the card is off
    (bsc#1111666).

  - can: dev: call netif_carrier_off() in register_candev()
    (bsc#1051510).

  - config: arm64: enable erratum 1418040 and 1542419

  - dmaengine: bcm2835: Print error in case setting DMA mask
    fails (bsc#1051510).

  - dmaengine: imx-sdma: fix size check for sdma
    script_number (bsc#1051510).

  - drm/amd/display: fix odm combine pipe reset
    (bsc#1111666).

  - drm/amdgpu: fix memory leak (bsc#1111666).

  - drm/amdgpu/powerplay/vega10: allow undervolting in p7
    (bsc#1111666).

  - drm/i915: Add gen9 BCS cmdparsing (bsc#1135967)

  - drm/i915: Add gen9 BCS cmdparsing (bsc#1135967)

  - drm/i915: Add support for mandatory cmdparsing
    (bsc#1135967)

  - drm/i915: Add support for mandatory cmdparsing
    (bsc#1135967)

  - drm/i915: Allow parsing of unsized batches (bsc#1135967)

  - drm/i915: Allow parsing of unsized batches (bsc#1135967)

  - drm/i915/cmdparser: Add support for backward jumps
    (bsc#1135967)

  - drm/i915/cmdparser: Add support for backward jumps
    (bsc#1135967)

  - drm/i915/cmdparser: Ignore Length operands during
    (bsc#1135967)

  - drm/i915/cmdparser: Ignore Length operands during
    command matching (bsc#1135967)

  - drm/i915/cmdparser: Use explicit goto for error paths
    (bsc#1135967)

  - drm/i915/cmdparser: Use explicit goto for error paths
    (bsc#1135967)

  - drm/i915/cml: Add second PCH ID for CMP (bsc#1111666).

  - drm/i915: Disable Secure Batches for gen6+

  - drm/i915: Disable Secure Batches for gen6+ (bsc#1135967)

  - drm/i915/gen8+: Add RC6 CTX corruption WA (bsc#1135967)

  - drm/i915/gen8+: Add RC6 CTX corruption WA (bsc#1135967)

  - drm/i915/gtt: Add read only pages to gen8_pte_encode
    (bsc#1135967)

  - drm/i915/gtt: Disable read-only support under GVT
    (bsc#1135967)

  - drm/i915/gtt: Read-only pages for insert_entries on bdw
    (bsc#1135967)

  - drm/i915/ilk: Fix warning when reading emon_status with
    no output (bsc#1111666).

  - drm/i915: Lower RM timeout to avoid DSI hard hangs
    (bsc#1135967)

  - drm/i915: Lower RM timeout to avoid DSI hard hangs
    (bsc#1135967)

  - drm/i915: Prevent writing into a read-only object via a
    GGTT mmap (bsc#1135967)

  - drm/i915: Remove Master tables from cmdparser

  - drm/i915: Remove Master tables from cmdparser
    (bsc#1135967)

  - drm/i915: Rename gen7 cmdparser tables (bsc#1135967)

  - drm/i915: Rename gen7 cmdparser tables (bsc#1135967)

  - drm/i915: Support ro ppgtt mapped cmdparser shadow
    (bsc#1135967)

  - drm/i915: Support ro ppgtt mapped cmdparser shadow
    buffers (bsc#1135967)

  - drm/msm/dpu: handle failures while initializing displays
    (bsc#1111666).

  - hyperv: set nvme msi interrupts to unmanaged
    (jsc#SLE-8953, jsc#SLE-9221, jsc#SLE-4941, bsc#1119461,
    bsc#1119465, bsc#1138190, bsc#1154905).

  - IB/core: Add mitigation for Spectre V1 (bsc#1155671)

  - integrity: prevent deadlock during digsig verification
    (bsc#1090631).

  - irqchip/gic-v3-its: Fix command queue pointer comparison
    bug (jsc#ECO-561).

  - irqchip/gic-v3-its: Fix LPI release for Multi-MSI
    devices (jsc#ECO-561).

  - irqchip/gic-v3-its: Fix misuse of GENMASK macro
    (jsc#ECO-561).

  - iwlwifi: do not panic in error path on non-msix systems
    (bsc#1155692).

  - iwlwifi: exclude GEO SAR support for 3168 (bsc#1111666).

  - iwlwifi: exclude GEO SAR support for 3168 (git-fixes).

  - iwlwifi: fw: do not send GEO_TX_POWER_LIMIT command to
    FW version 36 (bsc#1111666).

  - kabi protect enum RDMA_DRIVER_EFA (jsc#SLE-4805)

  - kABI workaround for drm_vma_offset_node readonly field
    addition (bsc#1135967)

  - kABI workaround for mmc_host retune_crc_disable flag
    addition (bsc#1111666).

  - KVM: arm64: Set SCTLR_EL2.DSSBS if SSBD is forcefully
    disabled and !vhe (jsc#ECO-561).

  - KVM: arm/arm64: Clean dcache to PoC when changing PTE
    due to CoW (jsc#ECO-561,jsc#SLE-10671).

  - KVM: arm/arm64: Detangle kvm_mmu.h from kvm_hyp.h
    (jsc#ECO-561,jsc#SLE-10671).

  - KVM: arm/arm64: Drop vcpu parameter from guest cache
    maintenance operartions (jsc#ECO-561,jsc#SLE-10671).

  - KVM: arm/arm64: Limit icache invalidation to prefetch
    aborts (jsc#ECO-561,jsc#SLE-10671).

  - KVM: arm/arm64: Only clean the dcache on translation
    fault (jsc#ECO-561,jsc#SLE-10671).

  - KVM: arm/arm64: Preserve Exec permission across R/W
    permission faults (jsc#ECO-561,jsc#SLE-10671).

  - KVM: arm/arm64: Split dcache/icache flushing
    (jsc#ECO-561,jsc#SLE-10671).

  - KVM: vmx, svm: always run with EFER.NXE=1 when shadow
    paging is active (bsc#1117665).

  - md/raid0: avoid RAID0 data corruption due to layout
    confusion (bsc#1140090).

  - md/raid0: fix warning message for parameter
    default_layout (bsc#1140090).

  - mmc: core: Add sdio_retune_hold_now() and
    sdio_retune_release() (bsc#1111666).

  - mmc: core: API to temporarily disable retuning for SDIO
    CRC errors (bsc#1111666).

  - Move upstreamed CA0132 fix into sorted section

  - net: openvswitch: free vport unless register_netdevice()
    succeeds (git-fixes).

  - phylink: fix kernel-doc warnings (bsc#1111666).

  - power: supply: max14656: fix potential use-after-free
    (bsc#1051510).

  - RDMA/efa: Add Amazon EFA driver (jsc#SLE-4805)

  - RDMA/hns: Add reset process for function-clear
    (bsc#1155061).

  - RDMA/hns: Remove the some magic number (bsc#1155061).

  - RDMA/restrack: Track driver QP types in resource tracker
    (jsc#SLE-4805)

  - Revert 'ALSA: hda: Flush interrupts on disabling'
    (bsc#1051510).

  - Revert synaptics-rmi4 patch due to regression
    (bsc#1155982) Also blacklisting it

  - rpm/kernel-subpackage-spec: Mention debuginfo in the
    subpackage description (bsc#1149119).

  - s390: add support for IBM z15 machines (bsc#1152696
    LTC#181731).

  - s390/cpumsf: Check for CPU Measurement sampling
    (bsc#1153681 LTC#181855).

  - s390: fix setting of mio addressing control (bsc#1152665
    LTC#181729).

  - s390/pci: add mio_enabled attribute (bsc#1152665
    LTC#181729).

  - s390/pci: correctly handle MIO opt-out (bsc#1152665
    LTC#181729).

  - s390/pci: deal with devices that have no support for MIO
    instructions (bsc#1152665 LTC#181729).

  - s390/pci: fix MSI message data (bsc#1152697 LTC#181730).

  - sc16is7xx: Fix for 'Unexpected interrupt: 8'
    (bsc#1051510).

  - sched/fair: Avoid divide by zero when rebalancing
    domains (bsc#1096254).

  - scsi: lpfc: Limit xri count for kdump environment
    (bsc#1154124).

  - scsi: qla2xxx: Add error handling for PLOGI ELS
    passthrough (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Capture FW dump on MPI heartbeat stop
    event (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Check for MB timeout while capturing
    ISP27/28xx FW dump (bsc#1143706 bsc#1082635
    bsc#1123034).

  - scsi: qla2xxx: Do command completion on abort timeout
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: do not use zero for FC4_PRIORITY_NVME
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Dual FCP-NVMe target port support
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix a dma_pool_free() call (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix device connect issues in P2P
    configuration (bsc#1143706 bsc#1082635 bsc#1154526
    bsc#1048942).

  - scsi: qla2xxx: Fix double scsi_done for abort path
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix driver unload hang (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix memory leak when sending I/O fails
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix N2N link reset (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix N2N link up fail (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix partial flash write of MBI
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix SRB leak on switch command timeout
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix stale mem access on driver unload
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix unbound sleep in fcport delete path
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: fixup incorrect usage of host_byte
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Improve logging for scan thread
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Initialized mailbox to prevent driver
    load failure (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: initialize fc4_type_priority (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Optimize NPIV tear down process
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Remove an include directive (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: remove redundant assignment to pointer
    host (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Retry PLOGI on FC-NVMe PRLI failure
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Set remove flag for all VP (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Silence fwdump template message
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: stop timer in shutdown path (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Update driver version to 10.01.00.20-k
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Update driver version to 10.01.00.21-k
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: sd: Ignore a failure to sync cache due to lack of
    authorization (git-fixes).

  - scsi: storvsc: Add ability to change scsi queue depth
    (bsc#1155021).

  - scsi: zfcp: fix reaction on bit error threshold
    notification (bsc#1154956 LTC#182054).

  - serial: fix kernel-doc warning in comments
    (bsc#1051510).

  - serial: mctrl_gpio: Check for NULL pointer
    (bsc#1051510).

  - serial: uartlite: fix exit path NULL pointer
    (bsc#1051510).

  - staging: rtl8188eu: fix null dereference when kzalloc
    fails (bsc#1051510).

  - supporte.conf: add efivarfs to kernel-default-base
    (bsc#1154858).

  - tracing: Get trace_array reference for available_tracers
    files (bsc#1156429).

  - usb: gadget: Reject endpoints with 0 maxpacket value
    (bsc#1051510).

  - usb: gadget: udc: atmel: Fix interrupt storm in FIFO
    mode (bsc#1051510).

  - usb: handle warm-reset port requests on hub resume
    (bsc#1051510).

  - usb: ldusb: fix control-message timeout (bsc#1051510).

  - usb: ldusb: fix ring-buffer locking (bsc#1051510).

  - usb: serial: whiteheat: fix line-speed endianness
    (bsc#1051510).

  - usb: serial: whiteheat: fix potential slab corruption
    (bsc#1051510).

  - usb-storage: Revert commit 747668dbc061 ('usb-storage:
    Set virt_boundary_mask to avoid SG overflows')
    (bsc#1051510).

  - wil6210: fix freeing of rx buffers in EDMA mode
    (bsc#1111666)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc/?id=7023735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc/?id=7024251"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10220");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.32.1") ) flag++;

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
