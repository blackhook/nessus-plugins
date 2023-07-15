#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1224.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104246);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13080", "CVE-2017-15265", "CVE-2017-15649", "CVE-2017-6346");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1224) (KRACK)");
  script_summary(english:"Check for the openSUSE-2017-1224 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.92 to receive various
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

  - alsa: au88x0: avoid theoretical uninitialized access
    (bnc#1012382).

  - alsa: compress: Remove unused variable (bnc#1012382).

  - alsa: usb-audio: Check out-of-bounds access by corrupted
    buffer descriptor (bnc#1012382).

  - alsa: usx2y: Suppress kernel warning at page allocation
    failures (bnc#1012382).

  - arm: 8635/1: nommu: allow enabling REMAP_VECTORS_TO_RAM
    (bnc#1012382).

  - arm: dts: r8a7790: Use R-Car Gen 2 fallback binding for
    msiof nodes (bnc#1012382).

  - arm: remove duplicate 'const' annotations'
    (bnc#1012382).

  - asoc: dapm: fix some pointer error handling
    (bnc#1012382).

  - asoc: dapm: handle probe deferrals (bnc#1012382).

  - audit: log 32-bit socketcalls (bnc#1012382).

  - blacklist 0e7736c6b806 powerpc/powernv: Fix data type
    for @r in pnv_ioda_parse_m64_window()

  - blacklist.conf: not fitting cleanup patch

  - brcmfmac: setup passive scan if requested by user-space
    (bnc#1012382).

  - bridge: netlink: register netdevice before executing
    changelink (bnc#1012382).

  - ceph: avoid panic in create_session_open_msg() if
    utsname() returns NULL (bsc#1061451).

  - ceph: check negative offsets in ceph_llseek()
    (bsc#1061451).

  - driver core: platform: Do not read past the end of
    'driver_override' buffer (bnc#1012382).

  - drivers: firmware: psci: drop duplicate const from
    psci_of_match (bnc#1012382).

  - drivers: hv: fcopy: restore correct transfer length
    (bnc#1012382).

  - drm/amdkfd: fix improper return value on error
    (bnc#1012382).

  - drm: bridge: add DT bindings for TI ths8135
    (bnc#1012382).

  - drm_fourcc: Fix DRM_FORMAT_MOD_LINEAR #define
    (bnc#1012382).

  - drm/i915/bios: ignore HDMI on port A (bnc#1012382).

  - ext4: do not allow encrypted operations without keys
    (bnc#1012382).

  - extcon: axp288: Use vbus-valid instead of -present to
    determine cable presence (bnc#1012382).

  - exynos-gsc: Do not swap cb/cr for semi planar formats
    (bnc#1012382).

  - fix whitespace according to upstream commit

  - fs/epoll: cache leftmost node (bsc#1056427).

  - ftrace: Fix kmemleak in unregister_ftrace_graph
    (bnc#1012382).

  - gfs2: Fix reference to ERR_PTR in gfs2_glock_iter_next
    (bnc#1012382).

  - hid: i2c-hid: allocate hid buffers for real worst case
    (bnc#1012382).

  - hpsa: correct lun data caching bitmap definition
    (bsc#1028971).

  - hwmon: (gl520sm) Fix overflows and crash seen when
    writing into limit attributes (bnc#1012382).

  - i2c: meson: fix wrong variable usage in
    meson_i2c_put_data (bnc#1012382).

  - i40e: Initialize 64-bit statistics TX ring seqcount
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Add missing memory barriers (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Fix port number for query QP (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - ib/core: Fix for core panic (bsc#1022595 FATE#322350).

  - ib/core: Fix the validations of a multicast LID in
    attach or detach operations (bsc#1022595 FATE#322350).

  - ib/i40iw: Fix error code in i40iw_create_cq()
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - ib/ipoib: Fix deadlock over vlan_mutex (bnc#1012382).

  - ib/ipoib: Replace list_del of the neigh->list with
    list_del_init (bnc#1012382).

  - ib/ipoib: rtnl_unlock can not come after free_netdev
    (bnc#1012382).

  - ib/mlx5: Fix Raw Packet QP event handler assignment
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - ibmvnic: Set state UP (bsc#1062962).

  - ib/qib: fix false-postive maybe-uninitialized warning
    (bnc#1012382).

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

  - ixgbe: Fix incorrect bitwise operations of PTP Rx
    timestamp flags (bsc#969474 FATE#319812 bsc#969475
    FATE#319814).

  - kABI: protect struct rm_data_op (kabi).

  - kABI: protect struct sdio_func (kabi).

  - libata: transport: Remove circular dependency at free
    time (bnc#1012382).

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

  - mm/backing-dev.c: fix an error handling path in
    'cgwb_create()' (bnc#1063475).

  - mm,compaction: serialize waitqueue_active() checks (for
    real) (bsc#971975).

  - mmc: sdio: fix alignment issue in struct sdio_func
    (bnc#1012382).

  - mm: discard memblock data later (bnc#1063460).

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

  - net/mlx5e: Fix wrong delay calculation for overflow
    check scheduling (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5e: Schedule overflow check work to mlx5e
    workqueue (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5: Skip mlx5_unload_one if mlx5_load_one fails
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/packet: check length in getsockopt() called with
    PACKET_HDRLEN (bnc#1012382).

  - nvme: protect against simultaneous shutdown invocations
    (FATE#319965 bnc#1012382 bsc#964944).

  - parisc: perf: Fix potential NULL pointer dereference
    (bnc#1012382).

  - partitions/efi: Fix integer overflow in GPT size
    calculation (bnc#1012382).

  - qed: Fix stack corruption on probe (bsc#966318
    FATE#320158 bsc#966316 FATE#320159).

  - rds: ib: add error handle (bnc#1012382).

  - rds: RDMA: Fix the composite message user notification
    (bnc#1012382).

  - README.BRANCH: Add Michal and Johannes as
    co-maintainers.

  - sched/cpuset/pm: Fix cpuset vs. suspend-resume bugs
    (bnc#1012382).

  - scsi: hpsa: add 'ctlr_num' sysfs attribute
    (bsc#1028971).

  - scsi: hpsa: bump driver version (bsc#1022600
    fate#321928).

  - scsi: hpsa: change driver version (bsc#1022600
    bsc#1028971 fate#321928).

  - scsi: hpsa: Check for null device pointers
    (bsc#1028971).

  - scsi: hpsa: Check for null devices in ioaccel
    (bsc#1028971).

  - scsi: hpsa: Check for vpd support before sending
    (bsc#1028971).

  - scsi: hpsa: cleanup reset handler (bsc#1022600
    fate#321928).

  - scsi: hpsa: correct call to hpsa_do_reset (bsc#1028971).

  - scsi: hpsa: correct logical resets (bsc#1028971).

  - scsi: hpsa: correct queue depth for externals
    (bsc#1022600 fate#321928).

  - scsi: hpsa: correct resets on retried commands
    (bsc#1022600 fate#321928).

  - scsi: hpsa: correct scsi 6byte lba calculation
    (bsc#1028971).

  - scsi: hpsa: Determine device external status earlier
    (bsc#1028971).

  - scsi: hpsa: do not get enclosure info for external
    devices (bsc#1022600 fate#321928).

  - scsi: hpsa: do not reset enclosures (bsc#1022600
    fate#321928).

  - scsi: hpsa: do not timeout reset operations (bsc#1022600
    bsc#1028971 fate#321928).

  - scsi: hpsa: fallback to use legacy REPORT PHYS command
    (bsc#1028971).

  - scsi: hpsa: fix volume offline state (bsc#1022600
    bsc#1028971 fate#321928).

  - scsi: hpsa: limit outstanding rescans (bsc#1022600
    bsc#1028971 fate#321928).

  - scsi: hpsa: Prevent sending bmic commands to externals
    (bsc#1028971).

  - scsi: hpsa: remove abort handler (bsc#1022600
    fate#321928).

  - scsi: hpsa: remove coalescing settings for ioaccel2
    (bsc#1028971).

  - scsi: hpsa: remove memory allocate failure message
    (bsc#1028971).

  - scsi: hpsa: Remove unneeded void pointer cast
    (bsc#1028971).

  - scsi: hpsa: rescan later if reset in progress
    (bsc#1022600 fate#321928).

  - scsi: hpsa: send ioaccel requests with 0 length down
    raid path (bsc#1022600 fate#321928).

  - scsi: hpsa: separate monitor events from rescan worker
    (bsc#1022600 fate#321928).

  - scsi: hpsa: update check for logical volume status
    (bsc#1022600 bsc#1028971 fate#321928).

  - scsi: hpsa: update identify physical device structure
    (bsc#1022600 fate#321928).

  - scsi: hpsa: update pci ids (bsc#1022600 bsc#1028971
    fate#321928).

  - scsi: hpsa: update reset handler (bsc#1022600
    fate#321928).

  - scsi: hpsa: use designated initializers (bsc#1028971).

  - scsi: hpsa: use %phN for short hex dumps (bsc#1028971).

  - scsi: libfc: fix a deadlock in fc_rport_work
    (bsc#1063695).

  - scsi: sd: Do not override max_sectors_kb sysfs setting
    (bsc#1025461).

  - scsi: sd: Remove LBPRZ dependency for discards
    (bsc#1060985). This patch is originally part of a larger
    series which can't be easily backported to SLE-12. For a
    reasoning why we think it's safe to apply, see
    bsc#1060985, comment 20.

  - scsi: sg: close race condition in
    sg_remove_sfp_usercontext() (bsc#1064206).

  - sh_eth: use correct name for ECMR_MPDE bit
    (bnc#1012382).

  - staging: iio: ad7192: Fix - use the dedicated reset
    function avoiding dma from stack (bnc#1012382).

  - stm class: Fix a use-after-free (bnc#1012382).

  - supported.conf: mark hid-multitouch as supported
    (FATE#323670)

  - team: call netdev_change_features out of team lock
    (bsc#1055567).

  - team: fix memory leaks (bnc#1012382).

  - tpm_tis: Do not fall back to a hardcoded address for
    TPM2 (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048).

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

  - xfs: handle error if xfs_btree_get_bufs fails
    (bsc#1059863).

  - xfs: remove kmem_zalloc_greedy (bnc#1012382).

  - xhci: fix finding correct bus_state structure for USB
    3.1 hosts (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059863"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062962"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063695"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969475"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.92-18.36.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.92-18.36.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.92-18.36.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.92-18.36.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
