#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1194.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104166);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13080", "CVE-2017-15265", "CVE-2017-15649", "CVE-2017-6346");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1194) (KRACK)");
  script_summary(english:"Check for the openSUSE-2017-1194 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.92 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2)
    allowed reinstallation of the Group Temporal Key (GTK)
    during the group key handshake, allowing an attacker
    within radio range to replay frames from access points
    to clients (bnc#1063667).

  - CVE-2017-15265: Race condition in the ALSA subsystem in
    the Linux kernel allowed local users to cause a denial
    of service (use-after-free) or possibly have unspecified
    other impact via crafted /dev/snd/seq ioctl calls,
    related to sound/core/seq/seq_clientmgr.c and
    sound/core/seq/seq_ports.c (bnc#1062520).

  - CVE-2017-15649: net/packet/af_packet.c in the Linux
    kernel allowed local users to gain privileges via
    crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind) that
    leads to a use-after-free, a different vulnerability
    than CVE-2017-6346 (bnc#1064388).

The following non-security bugs were fixed :

  - acpi/processor: Check for duplicate processor ids at
    hotplug time (bnc#1056230).

  - acpi/processor: Implement DEVICE operator for processor
    enumeration (bnc#1056230).

  - add mainline tags to hyperv patches

  - alsa: au88x0: avoid theoretical uninitialized access
    (bnc#1012382).

  - alsa: compress: Remove unused variable (bnc#1012382).

  - alsa: usb-audio: Check out-of-bounds access by corrupted
    buffer descriptor (bnc#1012382).

  - alsa: usx2y: Suppress kernel warning at page allocation
    failures (bnc#1012382).

  - arm64: add function to get a cpu's MADT GICC table
    (bsc#1062279).

  - arm64: dts: Add Broadcom Vulcan PMU in dts
    (fate#319481).

  - arm64/perf: Access pmu register using
    <read/write;gt;_sys_reg (bsc#1062279).

  - arm64/perf: Add Broadcom Vulcan PMU support
    (fate#319481).

  - arm64/perf: Changed events naming as per the ARM ARM
    (fate#319481).

  - arm64/perf: Define complete ARMv8 recommended
    implementation defined events (fate#319481).

  - arm64: perf: do not expose CHAIN event in sysfs
    (bsc#1062279).

  - arm64: perf: Extend event config for ARMv8.1
    (bsc#1062279).

  - arm64/perf: Filter common events based on PMCEIDn_EL0
    (fate#319481).

  - arm64: perf: Ignore exclude_hv when kernel is running in
    HYP (bsc#1062279).

  - arm64: perf: move to common attr_group fields
    (bsc#1062279).

  - arm64: perf: Use the builtin_platform_driver
    (bsc#1062279).

  - arm64: pmu: add fallback probe table (bsc#1062279).

  - arm64: pmu: Hoist pmu platform device name
    (bsc#1062279).

  - arm64: pmu: Probe default hw/cache counters
    (bsc#1062279).

  - arm64: pmuv3: handle pmuv3+ (bsc#1062279).

  - arm64: pmuv3: handle !PMUv3 when probing (bsc#1062279).

  - arm64: pmuv3: use arm_pmu ACPI framework (bsc#1062279).

  - arm64: pmu: Wire-up Cortex A53 L2 cache events and DTLB
    refills (bsc#1062279).

  - arm: 8635/1: nommu: allow enabling REMAP_VECTORS_TO_RAM
    (bnc#1012382).

  - arm: dts: r8a7790: Use R-Car Gen 2 fallback binding for
    msiof nodes (bnc#1012382).

  - arm/perf: Convert to hotplug state machine
    (bsc#1062279).

  - arm/perf: Fix hotplug state machine conversion
    (bsc#1062279).

  - arm/perf: Use multi instance instead of custom list
    (bsc#1062279).

  - arm: remove duplicate 'const' annotations'
    (bnc#1012382).

  - asoc: dapm: fix some pointer error handling
    (bnc#1012382).

  - asoc: dapm: handle probe deferrals (bnc#1012382).

  - audit: log 32-bit socketcalls (bnc#1012382).

  - blacklist 0e7736c6b806 powerpc/powernv: Fix data type
    for @r in pnv_ioda_parse_m64_window()

  - blacklist.conf: fix commit exists twice in upstream,
    blacklist one of them

  - blacklist.conf: stack limit warning isn't triggered on
    SP3

  - block: genhd: add device_add_disk_with_groups
    (bsc#1060400).

  - bnx2x: Do not log mc removal needlessly (bsc#1019680
    FATE#321692).

  - bnxt_en: Do not setup MAC address in
    bnxt_hwrm_func_qcaps() (bsc#963575 FATE#320144).

  - bnxt_en: Free MSIX vectors when unregistering the device
    from bnxt_re (bsc#1020412 FATE#321671).

  - bnxt_re: Do not issue cmd to delete GID for QP1 GID
    entry before the QP is destroyed (bsc#1056596).

  - bnxt_re: Fix compare and swap atomic operands
    (bsc#1056596).

  - bnxt_re: Fix memory leak in FRMR path (bsc#1056596).

  - bnxt_re: Fix race between the netdev register and
    unregister events (bsc#1037579).

  - bnxt_re: Fix update of qplib_qp.mtu when modified
    (bsc#1056596).

  - bnxt_re: Free up devices in module_exit path
    (bsc#1056596).

  - bnxt_re: Remove RTNL lock dependency in
    bnxt_re_query_port (bsc#1056596).

  - bnxt_re: Stop issuing further cmds to FW once a cmd
    times out (bsc#1056596).

  - brcmfmac: setup passive scan if requested by user-space
    (bnc#1012382).

  - bridge: netlink: register netdevice before executing
    changelink (bnc#1012382).

  - ceph: avoid panic in create_session_open_msg() if
    utsname() returns NULL (bsc#1061451).

  - ceph: check negative offsets in ceph_llseek()
    (bsc#1061451).

  - ceph: fix message order check in handle_cap_export()
    (bsc#1061451).

  - ceph: fix NULL pointer dereference in ceph_flush_snaps()
    (bsc#1061451).

  - ceph: limit osd read size to CEPH_MSG_MAX_DATA_LEN
    (bsc#1061451).

  - ceph: limit osd write size (bsc#1061451).

  - ceph: stop on-going cached readdir if mds revokes
    FILE_SHARED cap (bsc#1061451).

  - ceph: validate correctness of some mount options
    (bsc#1061451).

  - documentation: arm64: pmu: Add Broadcom Vulcan PMU
    binding (fate#319481).

  - driver-core: platform: Add platform_irq_count()
    (bsc#1062279).

  - driver core: platform: Do not read past the end of
    'driver_override' buffer (bnc#1012382).

  - drivers: firmware: psci: drop duplicate const from
    psci_of_match (FATE#319482 bnc#1012382).

  - drivers: hv: fcopy: restore correct transfer length
    (bnc#1012382).

  - drivers/perf: arm_pmu_acpi: avoid perf IRQ init when
    guest PMU is off (bsc#1062279).

  - drivers/perf: arm_pmu_acpi: Release memory obtained by
    kasprintf (bsc#1062279).

  - drivers/perf: arm_pmu: add ACPI framework (bsc#1062279).

  - drivers/perf: arm_pmu: add common attr group fields
    (bsc#1062279).

  - drivers/perf: arm_pmu: Always consider IRQ0 as an error
    (bsc#1062279).

  - drivers/perf: arm_pmu: Avoid leaking pmu->irq_affinity
    on error (bsc#1062279).

  - drivers/perf: arm_pmu: avoid NULL dereference when not
    using devicetree (bsc#1062279).

  - drivers/perf: arm-pmu: convert arm_pmu_mutex to spinlock
    (bsc#1062279).

  - drivers/perf: arm_pmu: Defer the setting of
    __oprofile_cpu_pmu (bsc#1062279).

  - drivers/perf: arm_pmu: define armpmu_init_fn
    (bsc#1062279).

  - drivers/perf: arm_pmu: expose a cpumask in sysfs
    (bsc#1062279).

  - drivers/perf: arm_pmu: factor out pmu registration
    (bsc#1062279).

  - drivers/perf: arm-pmu: Fix handling of SPI lacking
    'interrupt-affinity' property (bsc#1062279).

  - drivers/perf: arm_pmu: Fix NULL pointer dereference
    during probe (bsc#1062279).

  - drivers/perf: arm-pmu: fix RCU usage on pmu resume from
    low-power (bsc#1062279).

  - drivers/perf: arm_pmu: Fix reference count of a
    device_node in of_pmu_irq_cfg (bsc#1062279).

  - drivers/perf: arm_pmu: fold init into alloc
    (bsc#1062279).

  - drivers/perf: arm_pmu: handle no platform_device
    (bsc#1062279).

  - drivers/perf: arm-pmu: Handle per-interrupt affinity
    mask (bsc#1062279).

  - drivers/perf: arm_pmu: implement CPU_PM notifier
    (bsc#1062279).

  - drivers/perf: arm_pmu: make info messages more verbose
    (bsc#1062279).

  - drivers/perf: arm_pmu: manage interrupts per-cpu
    (bsc#1062279).

  - drivers/perf: arm_pmu: move irq request/free into probe
    (bsc#1062279).

  - drivers/perf: arm_pmu: only use common attr_groups
    (bsc#1062279).

  - drivers/perf: arm_pmu: remove pointless PMU disabling
    (bsc#1062279).

  - drivers/perf: arm_pmu: rename irq request/free functions
    (bsc#1062279).

  - drivers/perf: arm_pmu: Request PMU SPIs with
    IRQF_PER_CPU (bsc#1062279).

  - drivers/perf: arm_pmu: rework per-cpu allocation
    (bsc#1062279).

  - drivers/perf: arm_pmu: simplify cpu_pmu_request_irqs()
    (bsc#1062279).

  - drivers/perf: arm_pmu: split cpu-local irq request/free
    (bsc#1062279).

  - drivers/perf: arm_pmu: split irq request from enable
    (bsc#1062279).

  - drivers/perf: arm_pmu: split out platform device probe
    logic (bsc#1062279).

  - drivers/perf: kill armpmu_register (bsc#1062279).

  - drm/amdkfd: fix improper return value on error
    (bnc#1012382).

  - drm: bridge: add DT bindings for TI ths8135
    (bnc#1012382).

  - drm_fourcc: Fix DRM_FORMAT_MOD_LINEAR #define
    (bnc#1012382).

  - drm/i915/bios: ignore HDMI on port A (bnc#1012382).

  - e1000e: use disable_hardirq() also for MSIX vectors in
    e1000_netpoll() (bsc#1022912 FATE#321246).

  - edac, sb_edac: Assign EDAC memory controller per h/w
    controller (bsc#1061721).

  - edac, sb_edac: Avoid creating SOCK memory controller
    (bsc#1061721).

  - edac, sb_edac: Bump driver version and do some cleanups
    (bsc#1061721).

  - edac, sb_edac: Carve out dimm-populating loop
    (bsc#1061721).

  - edac, sb_edac: Check if ECC enabled when at least one
    DIMM is present (bsc#1061721).

  - edac, sb_edac: Classify memory mirroring modes
    (bsc#1061721).

  - edac, sb_edac: Classify PCI-IDs by topology
    (bsc#1061721).

  - edac, sb_edac: Do not create a second memory controller
    if HA1 is not present (bsc#1061721).

  - edac, sb_edac: Do not use 'Socket#' in the memory
    controller name (bsc#1061721).

  - edac, sb_edac: Drop NUM_CHANNELS from 8 back to 4
    (bsc#1061721).

  - edac, sb_edac: Fix mod_name (bsc#1061721).

  - edac, sb_edac: Get rid of ->show_interleave_mode()
    (bsc#1061721).

  - edac, sb_edac: Remove double buffering of error records
    (bsc#1061721).

  - edac, sb_edac: Remove NULL pointer check on array
    pci_tad (bsc#1061721).

  - edac, skx_edac: Handle systems with segmented PCI busses
    (bsc#1063102).

  - ext4: do not allow encrypted operations without keys
    (bnc#1012382).

  - extcon: axp288: Use vbus-valid instead of -present to
    determine cable presence (bnc#1012382).

  - exynos-gsc: Do not swap cb/cr for semi planar formats
    (bnc#1012382).

  - fix flags ordering (bsc#1034075 comment 131)

  - Fix mpage_writepage() for pages with buffers
    (bsc#1050471).

  - fix whitespace according to upstream commit

  - fs/epoll: cache leftmost node (bsc#1056427).

  - fs/mpage.c: fix mpage_writepage() for pages with buffers
    (bsc#1050471). Update to version in mainline

  - ftrace: Fix kmemleak in unregister_ftrace_graph
    (bnc#1012382).

  - gfs2: Fix reference to ERR_PTR in gfs2_glock_iter_next
    (bnc#1012382).

  - hid: i2c-hid: allocate hid buffers for real worst case
    (bnc#1012382).

  - hwmon: (gl520sm) Fix overflows and crash seen when
    writing into limit attributes (bnc#1012382).

  - i2c: meson: fix wrong variable usage in
    meson_i2c_put_data (bnc#1012382).

  - i40e: Initialize 64-bit statistics TX ring seqcount
    (bsc#1024346 FATE#321239 bsc#1024373 FATE#321247).

  - i40iw: Add missing memory barriers (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Fix port number for query QP (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - ib/core: Add generic function to extract IB speed from
    netdev (bsc#1056596).

  - ib/core: Add ordered workqueue for RoCE GID management
    (bsc#1056596).

  - ib/core: Fix for core panic (bsc#1022595 FATE#322350).

  - ib/core: Fix the validations of a multicast LID in
    attach or detach operations (bsc#1022595 FATE#322350).

  - ib/i40iw: Fix error code in i40iw_create_cq()
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - ib/ipoib: Fix deadlock over vlan_mutex (bnc#1012382
    bsc#1022595 FATE#322350).

  - ib/ipoib: Replace list_del of the neigh->list with
    list_del_init (FATE#322350 bnc#1012382 bsc#1022595).

  - ib/ipoib: rtnl_unlock can not come after free_netdev
    (FATE#322350 bnc#1012382 bsc#1022595).

  - ib/mlx5: Change logic for dispatching IB events for port
    state (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - ib/mlx5: Fix cached MR allocation flow (bsc#1015342
    FATE#321688 bsc#1015343 FATE#321689).

  - ib/mlx5: Fix Raw Packet QP event handler assignment
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - ibmvnic: Set state UP (bsc#1062962).

  - ib/qib: fix false-postive maybe-uninitialized warning
    (FATE#321231 FATE#321473 FATE#322149 FATE#322153
    bnc#1012382).

  - igb: re-assign hw address pointer on reset after PCI
    error (bnc#1012382).

  - iio: ad7793: Fix the serial interface reset
    (bnc#1012382).

  - iio: adc: axp288: Drop bogus AXP288_ADC_TS_PIN_CTRL
    register modifications (bnc#1012382).

  - iio: adc: hx711: Add DT binding for avia,hx711
    (bnc#1012382).

  - iio: adc: mcp320x: Fix oops on module unload
    (bnc#1012382).

  - iio: adc: mcp320x: Fix readout of negative voltages
    (bnc#1012382).

  - iio: adc: twl4030: Disable the vusb3v1 rugulator in the
    error handling path of 'twl4030_madc_probe()'
    (bnc#1012382).

  - iio: adc: twl4030: Fix an error handling path in
    'twl4030_madc_probe()' (bnc#1012382).

  - iio: ad_sigma_delta: Implement a dedicated reset
    function (bnc#1012382).

  - iio: core: Return error for failed read_reg
    (bnc#1012382).

  - iommu/io-pgtable-arm: Check for leaf entry before
    dereferencing it (bnc#1012382).

  - iwlwifi: add workaround to disable wide channels in 5GHz
    (bnc#1012382).

  - kabi fixup struct nvmet_sq (bsc#1063349).

  - kABI: protect enum fs_flow_table_type (bsc#1015342
    FATE#321688 bsc#1015343 FATE#321689).

  - kABI: protect struct mlx5_priv (bsc#1015342 FATE#321688
    bsc#1015343 FATE#321689).

  - kABI: protect struct rm_data_op (kabi).

  - kABI: protect struct sdio_func (kabi).

  - libata: transport: Remove circular dependency at free
    time (bnc#1012382).

  - libceph: do not allow bidirectional swap of
    pg-upmap-items (bsc#1061451).

  - lsm: fix smack_inode_removexattr and xattr_getsecurity
    memleak (bnc#1012382).

  - md/raid10: submit bio directly to replacement disk
    (bnc#1012382).

  - mips: Ensure bss section ends on a long-aligned address
    (bnc#1012382).

  - mips: Fix minimum alignment requirement of IRQ stack
    (git-fixes).

  - mips: IRQ Stack: Unwind IRQ stack onto task stack
    (bnc#1012382).

  - mips: Lantiq: Fix another request_mem_region() return
    code check (bnc#1012382).

  - mips: ralink: Fix incorrect assignment on ralink_soc
    (bnc#1012382).

  - mlx5: Avoid that mlx5_ib_sg_to_klms() overflows the klms
    array (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - mm: avoid marking swap cached page as lazyfree (VM
    Functionality, bsc#1061775).

  - mm/backing-dev.c: fix an error handling path in
    'cgwb_create()' (bnc#1063475).

  - mm,compaction: serialize waitqueue_active() checks (for
    real) (bsc#971975).

  - mmc: sdio: fix alignment issue in struct sdio_func
    (bnc#1012382).

  - mm: discard memblock data later (bnc#1063460).

  - mm: fix data corruption caused by lazyfree page (VM
    Functionality, bsc#1061775).

  - mm/memblock.c: reversed logic in memblock_discard()
    (bnc#1063460).

  - mm: meminit: mark init_reserved_page as __meminit
    (bnc#1063509).

  - mm/memory_hotplug: change
    pfn_to_section_nr/section_nr_to_pfn macro to inline
    function (bnc#1063501).

  - mm/memory_hotplug: define
    find_(smallest|biggest)_section_pfn as unsigned long
    (bnc#1063520).

  - net: core: Prevent from dereferencing NULL pointer when
    releasing SKB (bnc#1012382).

  - netfilter: invoke synchronize_rcu after set the _hook_
    to NULL (bnc#1012382).

  - netfilter: nfnl_cthelper: fix incorrect
    helper->expect_class_max (bnc#1012382).

  - net/mlx4_core: Enable 4K UAR if SRIOV module parameter
    is not enabled (bsc#966191 FATE#320230 bsc#966186
    FATE#320228).

  - net/mlx5: Check device capability for maximum flow
    counters (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5: Delay events till ib registration ends
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5e: Check for qos capability in dcbnl_initialize
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5e: Do not add/remove 802.1ad rules when changing
    802.1Q VLAN filter (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5e: Fix calculated checksum offloads counters
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5e: Fix dangling page pointer on DMA mapping
    error (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5e: Fix DCB_CAP_ATTR_DCBX capability for DCBNL
    getcap (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5e: Fix inline header size for small packets
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5e: Print netdev features correctly in error
    message (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5e: Schedule overflow check work to mlx5e
    workqueue (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5: E-Switch, Unload the representors in the
    correct order (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5: Fix arm SRQ command for ISSI version 0
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5: Fix command completion after timeout access
    invalid structure (bsc#966318 FATE#320158 bsc#966316
    FATE#320159).

  - net/mlx5: Fix counter list hardware structure
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5: Remove the flag MLX5_INTERFACE_STATE_SHUTDOWN
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5: Skip mlx5_unload_one if mlx5_load_one fails
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net: mvpp2: fix the mac address used when using PPv2.2
    (bsc#1032150).

  - net: mvpp2: use (get, put)_cpu() instead of
    smp_processor_id() (bsc#1032150).

  - net/packet: check length in getsockopt() called with
    PACKET_HDRLEN (bnc#1012382).

  - netvsc: Initialize 64-bit stats seqcount (fate#320485).

  - nvme: allow timed-out ios to retry (bsc#1063349).

  - nvme: fix sqhd reference when admin queue connect fails
    (bsc#1063349).

  - nvme: fix visibility of 'uuid' ns attribute
    (bsc#1060400).

  - nvme: protect against simultaneous shutdown invocations
    (FATE#319965 bnc#1012382 bsc#964944).

  - nvme: stop aer posting if controller state not live
    (bsc#1063349).

  - nvmet: implement valid sqhd values in completions
    (bsc#1063349).

  - nvmet: synchronize sqhd update (bsc#1063349).

  - nvme: use device_add_disk_with_groups() (bsc#1060400).

  - parisc: perf: Fix potential NULL pointer dereference
    (bnc#1012382).

  - partitions/efi: Fix integer overflow in GPT size
    calculation (FATE#322379 bnc#1012382 bsc#1020989).

  - perf: arm: acpi: remove cpu hotplug statemachine
    dependency (bsc#1062279).

  - perf: arm: platform: remove cpu hotplug statemachine
    dependency (bsc#1062279).

  - perf: arm: replace irq_get_percpu_devid_partition call
    (bsc#1062279).

  - perf: arm: temporary workaround for build errors
    (bsc#1062279).

  - perf: Convert to using %pOF instead of full_name
    (bsc#1062279).

  - powerpc: Fix unused function warning 'lmb_to_memblock'
    (FATE#322022).

  - powerpc/pseries: Add pseries hotplug workqueue
    (FATE#322022).

  - powerpc/pseries: Auto-online hotplugged memory
    (FATE#322022).

  - powerpc/pseries: Check memory device state before
    onlining/offlining (FATE#322022).

  - powerpc/pseries: Correct possible read beyond dlpar
    sysfs buffer (FATE#322022).

  - powerpc/pseries: Do not attempt to acquire drc during
    memory hot add for assigned lmbs (FATE#322022).

  - powerpc/pseries: Fix build break when MEMORY_HOTREMOVE=n
    (FATE#322022).

  - powerpc/pseries: fix memory leak in
    queue_hotplug_event() error path (FATE#322022).

  - powerpc/pseries: Implement indexed-count hotplug memory
    add (FATE#322022).

  - powerpc/pseries: Implement indexed-count hotplug memory
    remove (FATE#322022).

  - powerpc/pseries: Introduce memory hotplug READD
    operation (FATE#322022).

  - powerpc/pseries: Make the acquire/release of the drc for
    memory a separate step (FATE#322022).

  - powerpc/pseries: Remove call to memblock_add()
    (FATE#322022).

  - powerpc/pseries: Revert 'Auto-online hotplugged memory'
    (FATE#322022).

  - powerpc/pseries: Use kernel hotplug queue for PowerVM
    hotplug events (FATE#322022).

  - powerpc/pseries: Use lmb_is_removable() to check
    removability (FATE#322022).

  - powerpc/pseries: Verify CPU does not exist before adding
    (FATE#322022).

  - rdma: Fix return value check for ib_get_eth_speed()
    (bsc#1056596).

  - rdma/qedr: Parse VLAN ID correctly and ignore the value
    of zero (bsc#1019695 FATE#321703 bsc#1019699 FATE#321702
    bsc#1022604 FATE#321747).

  - rdma/qedr: Parse vlan priority as sl (bsc#1019695
    FATE#321703 bsc#1019699 FATE#321702 bsc#1022604
    FATE#321747).

  - rds: ib: add error handle (bnc#1012382).

  - rds: rdma: Fix the composite message user notification
    (bnc#1012382).

  - README.BRANCH: Add Michal and Johannes as
    co-maintainers.

  - Remove superfluous hunk in bigmem backport
    (bsc#1064436). Refresh
    patches.arch/powerpc-bigmem-16-mm-Add-addr_limit-to-mm_c
    ontext-and-use-it-t.patch.

  - Revert 'x86/acpi: Enable MADT APIs to return disabled
    apicids' (bnc#1056230).

  - Revert 'x86/acpi: Set persistent cpuid <-> nodeid
    mapping when booting' (bnc#1056230).

  - s390/cpcmd,vmcp: avoid GFP_DMA allocations (bnc#1060249,
    LTC#159112).

  - s390/qdio: avoid reschedule of outbound tasklet once
    killed (bnc#1060249, LTC#159885).

  - s390/topology: alternative topology for topology-less
    machines (bnc#1060249, LTC#159177).

  - s390/topology: always use s390 specific
    sched_domain_topology_level (bnc#1060249, LTC#159177).

  - s390/topology: enable / disable topology dynamically
    (bnc#1060249, LTC#159177).

  - sched/cpuset/pm: Fix cpuset vs. suspend-resume bugs
    (bnc#1012382).

  - scsi: fixup kernel warning during rmmod() (bsc#1052360).

  - scsi: libfc: fix a deadlock in fc_rport_work
    (bsc#1063695).

  - scsi: lpfc: Ensure io aborts interlocked with the target
    (bsc#1056587).

  - scsi: qedi: off by one in qedi_get_cmd_from_tid()
    (bsc#1004527, FATE#321744).

  - scsi: qla2xxx: Fix uninitialized work element
    (bsc#1019675,FATE#321701).

  - scsi: scsi_transport_fc: Also check for NOTPRESENT in
    fc_remote_port_add() (bsc#1037890).

  - scsi: scsi_transport_fc: set scsi_target_id upon rescan
    (bsc#1058135).

  - scsi: sd: Do not override max_sectors_kb sysfs setting
    (bsc#1025461).

  - scsi: sd: Remove LBPRZ dependency for discards
    (bsc#1060985). This patch is originally part of a larger
    series which can't be easily backported to SLE-12. For a
    reasoning why we think it's safe to apply, see
    bsc#1060985, comment 20.

  - scsi: sg: close race condition in
    sg_remove_sfp_usercontext() (bsc#1064206).

  - scsi: sg: do not return bogus Sg_requests (bsc#1064206).

  - scsi: sg: only check for dxfer_len greater than 256M
    (bsc#1064206).

  - sh_eth: use correct name for ECMR_MPDE bit
    (bnc#1012382).

  - staging: iio: ad7192: Fix - use the dedicated reset
    function avoiding dma from stack (bnc#1012382).

  - stm class: Fix a use-after-free (bnc#1012382).

  - supported.conf: enable dw_mmc-rockchip driver
    References: bsc#1064064

  - team: call netdev_change_features out of team lock
    (bsc#1055567).

  - team: fix memory leaks (bnc#1012382).

  - ttpci: address stringop overflow warning (bnc#1012382).

  - tty: goldfish: Fix a parameter of a call to free_irq
    (bnc#1012382).

  - usb: chipidea: vbus event may exist before starting
    gadget (bnc#1012382).

  - usb: core: harden cdc_parse_cdc_header (bnc#1012382).

  - usb: devio: Do not corrupt user memory (bnc#1012382).

  - usb: dummy-hcd: fix connection failures (wrong speed)
    (bnc#1012382).

  - usb: dummy-hcd: Fix erroneous synchronization change
    (bnc#1012382).

  - usb: dummy-hcd: fix infinite-loop resubmission bug
    (bnc#1012382).

  - usb: fix out-of-bounds in usb_set_configuration
    (bnc#1012382).

  - usb: gadgetfs: fix copy_to_user while holding spinlock
    (bnc#1012382).

  - usb: gadgetfs: Fix crash caused by inadequate
    synchronization (bnc#1012382).

  - usb: gadget: inode.c: fix unbalanced spin_lock in
    ep0_write (bnc#1012382).

  - usb: gadget: mass_storage: set msg_registered after msg
    registered (bnc#1012382).

  - usb: gadget: udc: atmel: set vbus irqflags explicitly
    (bnc#1012382).

  - usb: g_mass_storage: Fix deadlock when driver is unbound
    (bnc#1012382).

  - usb: Increase quirk delay for USB devices (bnc#1012382).

  - usb: pci-quirks.c: Corrected timeout values used in
    handshake (bnc#1012382).

  - usb: plusb: Add support for PL-27A1 (bnc#1012382).

  - usb: renesas_usbhs: fix the BCLR setting condition for
    non-DCP pipe (bnc#1012382).

  - usb: renesas_usbhs: fix usbhsf_fifo_clear() for RX
    direction (bnc#1012382).

  - usb: serial: mos7720: fix control-message error handling
    (bnc#1012382).

  - usb: serial: mos7840: fix control-message error handling
    (bnc#1012382).

  - usb-storage: unusual_devs entry to fix write-access
    regression for Seagate external drives (bnc#1012382).

  - usb: uas: fix bug in handling of alternate settings
    (bnc#1012382).

  - uwb: ensure that endpoint is interrupt (bnc#1012382).

  - uwb: properly check kthread_run return value
    (bnc#1012382).

  - x86/acpi: Restore the order of CPU IDs (bnc#1056230).

  - x86/cpu: Remove unused and undefined
    __generic_processor_info() declaration (bnc#1056230).

  - x86 edac, sb_edac.c: Take account of channel hashing
    when needed (bsc#1061721).

  - x86/mshyperv: Remove excess #includes from mshyperv.h
    (fate#320485).

  - xfs: handle error if xfs_btree_get_bufs fails
    (bsc#1059863).

  - xfs: remove kmem_zalloc_greedy (bnc#1012382).

  - xhci: fix finding correct bus_state structure for USB
    3.1 hosts (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019680"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.92-31.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.92-31.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.92-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.92-31.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
