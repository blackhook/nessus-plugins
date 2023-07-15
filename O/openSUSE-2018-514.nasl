#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-514.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110104);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18257", "CVE-2018-1000199", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1065", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803", "CVE-2018-7492", "CVE-2018-8781", "CVE-2018-8822");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-514) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-514 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.132 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-3639: Information leaks using 'Memory
    Disambiguation' feature in modern CPUs were mitigated,
    aka 'Spectre Variant 4' (bnc#1087082).

    A new boot commandline option was introduced,
    'spec_store_bypass_disable', which can have following
    values :

  - auto: Kernel detects whether your CPU model contains an
    implementation of Speculative Store Bypass and picks the
    most appropriate mitigation.

  - on: disable Speculative Store Bypass

  - off: enable Speculative Store Bypass

  - prctl: Control Speculative Store Bypass per thread via
    prctl. Speculative Store Bypass is enabled for a process
    by default. The state of the control is inherited on
    fork.

  - seccomp: Same as 'prctl' above, but all seccomp threads
    will disable SSB unless they explicitly opt out.

    The default is 'seccomp', meaning programs need explicit
    opt-in into the mitigation.

    Status can be queried via the
    /sys/devices/system/cpu/vulnerabilities/spec_store_bypas
    s file, containing :

  - 'Vulnerable'

  - 'Mitigation: Speculative Store Bypass disabled'

  - 'Mitigation: Speculative Store Bypass disabled via
    prctl'

  - 'Mitigation: Speculative Store Bypass disabled via prctl
    and seccomp'

  - CVE-2017-18257: The __get_data_block function in
    fs/f2fs/data.c allowed local users to cause a denial of
    service (integer overflow and loop) via crafted use of
    the open and fallocate system calls with an
    FS_IOC_FIEMAP ioctl. (bnc#1088241)

  - CVE-2018-1130: Linux kernel was vulnerable to a NULL
    pointer dereference in dccp_write_xmit() function in
    net/dccp/output.c in that allowed a local user to cause
    a denial of service by a number of certain crafted
    system calls (bnc#1092904).

  - CVE-2018-5803: An error in the _sctp_make_chunk()
    function when handling SCTP, packet length could have
    been exploited by a malicious local user to cause a
    kernel crash and a DoS. (bnc#1083900).

  - CVE-2018-1065: The netfilter subsystem mishandled the
    case of a rule blob that contains a jump but lacks a
    user-defined chain, which allowed local users to cause a
    denial of service (NULL pointer dereference) by
    leveraging the CAP_NET_RAW or CAP_NET_ADMIN capability,
    related to arpt_do_table in
    net/ipv4/netfilter/arp_tables.c, ipt_do_table in
    net/ipv4/netfilter/ip_tables.c, and ip6t_do_table in
    net/ipv6/netfilter/ip6_tables.c (bnc#1083650).

  - CVE-2018-7492: A NULL pointer dereference was found in
    the net/rds/rdma.c __rds_rdma_map() function that
    allowed local attackers to cause a system panic and a
    denial-of-service, related to RDS_GET_MR and
    RDS_GET_MR_FOR_DEST (bnc#1082962).

  - CVE-2018-8781: The udl_fb_mmap function in
    drivers/gpu/drm/udl/udl_fb.c had an integer-overflow
    vulnerability allowing local users with access to the
    udldrmfb driver to obtain full read and write
    permissions on kernel physical pages, resulting in a
    code execution in kernel space (bnc#1090643).

  - CVE-2018-10124: The kill_something_info function in
    kernel/signal.c might have allowed local users to cause
    a denial of service via an INT_MIN argument
    (bnc#1089752).

  - CVE-2018-10087: The kernel_wait4 function in
    kernel/exit.c might have allowed local users to cause a
    denial of service by triggering an attempted use of the
    -INT_MIN value (bnc#1089608).

  - CVE-2018-8822: Incorrect buffer length handling in the
    ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c
    could be exploited by malicious NCPFS servers to crash
    the kernel or execute code (bnc#1086162).

  - CVE-2018-1000199: A bug in x86 debug register handling
    of ptrace() could lead to memory corruption, possibly a
    denial of service or privilege escalation (bsc#1089895).

The following non-security bugs were fixed :

  - acpica: Disassembler: Abort on an invalid/unknown AML
    opcode (bnc#1012382).

  - acpica: Events: Add runtime stub support for event APIs
    (bnc#1012382).

  - acpi / hotplug / PCI: Check presence of slot itself in
    get_slot_status() (bnc#1012382).

  - acpi, PCI, irq: remove redundant check for null string
    pointer (bnc#1012382).

  - acpi / scan: Send change uevent with offine
    environmental data (bsc#1082485).

  - acpi / video: Add quirk to force acpi-video backlight on
    Samsung 670Z5E (bnc#1012382).

  - alsa: aloop: Add missing cable lock to ctl API callbacks
    (bnc#1012382).

  - alsa: aloop: Mark paused device as inactive
    (bnc#1012382).

  - alsa: asihpi: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: control: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: core: Report audio_tstamp in snd_pcm_sync_ptr
    (bnc#1012382).

  - alsa: hda/conexant - Add fixup for HP Z2 G4 workstation
    (bsc#1092975).

  - alsa: hda: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: hda - New VIA controller suppor no-snoop path
    (bnc#1012382).

  - alsa: hda/realtek - Add some fixes for ALC233
    (bnc#1012382).

  - alsa: hdspm: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: line6: Use correct endpoint type for midi output
    (bnc#1012382).

  - alsa: opl3: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: oss: consolidate kmalloc/memset 0 call to kzalloc
    (bnc#1012382).

  - alsa: pcm: Avoid potential races between OSS ioctls and
    read/write (bnc#1012382).

  - alsa: pcm: Check PCM state at xfern compat ioctl
    (bnc#1012382).

  - alsa: pcm: Fix endless loop for XRUN recovery in OSS
    emulation (bnc#1012382).

  - alsa: pcm: Fix mutex unbalance in OSS emulation ioctls
    (bnc#1012382).

  - alsa: pcm: Fix UAF at PCM release via PCM timer access
    (bnc#1012382).

  - alsa: pcm: potential uninitialized return values
    (bnc#1012382).

  - alsa: pcm: Return -EBUSY for OSS ioctls changing busy
    streams (bnc#1012382).

  - alsa: pcm: Use dma_bytes as size parameter in
    dma_mmap_coherent() (bnc#1012382).

  - alsa: pcm: Use ERESTARTSYS instead of EINTR in OSS
    emulation (bnc#1012382).

  - alsa: rawmidi: Fix missing input substream checks in
    compat ioctls (bnc#1012382).

  - alsa: rme9652: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: seq: Fix races at MIDI encoding in
    snd_virmidi_output_trigger() (bnc#1012382).

  - alsa: seq: oss: Fix unbalanced use lock for synth MIDI
    device (bnc#1012382).

  - alsa: seq: oss: Hardening for potential Spectre v1
    (bnc#1012382).

  - alsa: usb-audio: Skip broken EU on Dell dock USB-audio
    (bsc#1090658).

  - arm64: Add ARM_SMCCC_ARCH_WORKAROUND_1 BP hardening
    support (bsc#1068032).

  - arm64: avoid overflow in VA_START and PAGE_OFFSET
    (bnc#1012382).

  - arm64: capabilities: Handle duplicate entries for a
    capability (bsc#1068032).

  - arm64: cpufeature: __this_cpu_has_cap() shouldn't stop
    early (bsc#1068032).

  - arm64: Enforce BBM for huge IO/VMAP mappings
    (bsc#1088313).

  - arm64: fix smccc compilation (bsc#1068032).

  - arm64: futex: Fix undefined behaviour with
    FUTEX_OP_OPARG_SHIFT usage (bnc#1012382).

  - arm64: Kill PSCI_GET_VERSION as a variant-2 workaround
    (bsc#1068032).

  - arm64: kvm: Add SMCCC_ARCH_WORKAROUND_1 fast handling
    (bsc#1068032).

  - arm64: kvm: Increment PC after handling an SMC trap
    (bsc#1068032).

  - arm64: kvm: Report SMCCC_ARCH_WORKAROUND_1 BP hardening
    support (bsc#1068032).

  - arm64: mm: fix thinko in non-global page table attribute
    check (bsc#1088050).

  - arm64: Relax ARM_SMCCC_ARCH_WORKAROUND_1 discovery
    (bsc#1068032).

  - arm: amba: Do not read past the end of sysfs
    'driver_override' buffer (bnc#1012382).

  - arm: amba: Fix race condition with driver_override
    (bnc#1012382).

  - arm: amba: Make driver_override output consistent with
    other buses (bnc#1012382).

  - arm/arm64: kvm: Add PSCI_VERSION helper (bsc#1068032).

  - arm/arm64: kvm: Add smccc accessors to PSCI code
    (bsc#1068032).

  - arm/arm64: kvm: Advertise SMCCC v1.1 (bsc#1068032).

  - arm/arm64: kvm: Consolidate the PSCI include files
    (bsc#1068032).

  - arm/arm64: kvm: Implement PSCI 1.0 support
    (bsc#1068032).

  - arm/arm64: kvm: Turn kvm_psci_version into a static
    inline (bsc#1068032).

  - arm/arm64: smccc: Implement SMCCC v1.1 inline primitive
    (bsc#1068032).

  - arm/arm64: smccc: Make function identifiers an unsigned
    quantity (bsc#1068032).

  - arm: davinci: da8xx: Create DSP device only when
    assigned memory (bnc#1012382).

  - arm: dts: am57xx-beagle-x15-common: Add overide
    powerhold property (bnc#1012382).

  - arm: dts: at91: at91sam9g25: fix mux-mask pinctrl
    property (bnc#1012382).

  - arm: dts: at91: sama5d4: fix pinctrl compatible string
    (bnc#1012382).

  - arm: dts: dra7: Add power hold and power controller
    properties to palmas (bnc#1012382).

  - arm: dts: imx53-qsrb: Pulldown PMIC IRQ pin
    (bnc#1012382).

  - arm: dts: imx6qdl-wandboard: Fix audio channel swap
    (bnc#1012382).

  - arm: dts: ls1021a: add 'fsl,ls1021a-esdhc' compatible
    string to esdhc node (bnc#1012382).

  - arm: imx: Add MXC_CPU_IMX6ULL and cpu_is_imx6ull
    (bnc#1012382).

  - arp: fix arp_filter on l3slave devices (bnc#1012382).

  - arp: honour gratuitous ARP _replies_ (bnc#1012382).

  - ASoC: fsl_esai: Fix divisor calculation failure at lower
    ratio (bnc#1012382).

  - ASoC: Intel: cht_bsw_rt5645: Analog Mic support
    (bnc#1012382).

  - ASoC: rsnd: SSI PIO adjust to 24bit mode (bnc#1012382).

  - ASoC: ssm2602: Replace reg_default_raw with reg_default
    (bnc#1012382).

  - async_tx: Fix DMA_PREP_FENCE usage in
    do_async_gen_syndrome() (bnc#1012382).

  - ata: libahci: properly propagate return value of
    platform_get_irq() (bnc#1012382).

  - ath10k: fix rfc1042 header retrieval in QCA4019 with eth
    decap mode (bnc#1012382).

  - ath10k: rebuild crypto header in rx data frames
    (bnc#1012382).

  - ath5k: fix memory leak on buf on failed eeprom read
    (bnc#1012382).

  - ath9k_hw: check if the chip failed to wake up
    (bnc#1012382).

  - atm: zatm: Fix potential Spectre v1 (bnc#1012382).

  - audit: add tty field to LOGIN event (bnc#1012382).

  - autofs: mount point create should honour passed in mode
    (bnc#1012382).

  - bcache: segregate flash only volume write streams
    (bnc#1012382).

  - bcache: stop writeback thread after detaching
    (bnc#1012382).

  - bdi: Fix oops in wb_workfn() (bnc#1012382).

  - blacklist.conf: Add an omapdrm entry (bsc#1090708,
    bsc#1090718)

  - blk-mq: fix bad clear of RQF_MQ_INFLIGHT in
    blk_mq_ct_ctx_init() (bsc#1085058).

  - blk-mq: fix kernel oops in blk_mq_tag_idle()
    (bnc#1012382).

  - block: correctly mask out flags in blk_rq_append_bio()
    (bsc#1085058).

  - block/loop: fix deadlock after loop_set_status
    (bnc#1012382).

  - block: sanity check for integrity intervals
    (bsc#1091728).

  - bluetooth: Fix missing encryption refresh on Security
    Request (bnc#1012382).

  - bluetooth: Send HCI Set Event Mask Page 2 command only
    when needed (bnc#1012382).

  - bna: Avoid reading past end of buffer (bnc#1012382).

  - bnx2x: Allow vfs to disable txvlan offload
    (bnc#1012382).

  - bonding: do not set slave_dev npinfo before
    slave_enable_netpoll in bond_enslave (bnc#1012382).

  - bonding: Do not update slave->link until ready to commit
    (bnc#1012382).

  - bonding: fix the err path for dev hwaddr sync in
    bond_enslave (bnc#1012382).

  - bonding: move dev_mc_sync after master_upper_dev_link in
    bond_enslave (bnc#1012382).

  - bonding: process the err returned by dev_set_allmulti
    properly in bond_enslave (bnc#1012382).

  - bpf: map_get_next_key to return first key on NULL
    (bnc#1012382).

  - btrfs: fix incorrect error return ret being passed to
    mapping_set_error (bnc#1012382).

  - btrfs: Fix wrong first_key parameter in replace_path
    (Followup fix for bsc#1084721).

  - btrfs: Only check first key for committed tree blocks
    (bsc#1084721).

  - btrfs: Validate child tree block's level and first key
    (bsc#1084721).

  - bus: brcmstb_gisb: correct support for 64-bit address
    output (bnc#1012382).

  - bus: brcmstb_gisb: Use register offsets with writes too
    (bnc#1012382).

  - can: kvaser_usb: Increase correct stats counter in
    kvaser_usb_rx_can_msg() (bnc#1012382).

  - cdc_ether: flag the Cinterion AHS8 modem by gemalto as
    WWAN (bnc#1012382).

  - cdrom: information leak in cdrom_ioctl_media_changed()
    (bnc#1012382).

  - ceph: adding protection for showing cap reservation info
    (bsc#1089115).

  - ceph: always update atime/mtime/ctime for new inode
    (bsc#1089115).

  - ceph: check if mds create snaprealm when setting quota
    (fate#324665 bsc#1089115).

  - ceph: do not check quota for snap inode (fate#324665
    bsc#1089115).

  - ceph: fix invalid point dereference for error case in
    mdsc destroy (bsc#1089115).

  - ceph: fix root quota realm check (fate#324665
    bsc#1089115).

  - ceph: fix rsize/wsize capping in
    ceph_direct_read_write() (bsc#1089115).

  - ceph: quota: add counter for snaprealms with quota
    (fate#324665 bsc#1089115).

  - ceph: quota: add initial infrastructure to support
    cephfs quotas (fate#324665 bsc#1089115).

  - ceph: quota: cache inode pointer in ceph_snap_realm
    (fate#324665 bsc#1089115).

  - ceph: quota: do not allow cross-quota renames
    (fate#324665 bsc#1089115).

  - ceph: quota: report root dir quota usage in statfs
    (fate#324665 bsc#1089115).

  - ceph: quota: support for ceph.quota.max_bytes
    (fate#324665 bsc#1089115).

  - ceph: quota: support for ceph.quota.max_files
    (fate#324665 bsc#1089115).

  - ceph: quota: update MDS when max_bytes is approaching
    (fate#324665 bsc#1089115).

  - cfg80211: make RATE_INFO_BW_20 the default
    (bnc#1012382).

  - ch9200: use skb_cow_head() to deal with cloned skbs
    (bsc#1088684).

  - cifs: do not allow creating sockets except with SMB1
    posix exensions (bnc#1012382).

  - cifs: silence compiler warnings showing up with
    gcc-8.0.0 (bsc#1090734).

  - cifs: silence lockdep splat in cifs_relock_file()
    (bnc#1012382).

  - cifs: Use file_dentry() (bsc#1093008).

  - clk: bcm2835: De-assert/assert PLL reset signal when
    appropriate (bnc#1012382).

  - clk: Fix __set_clk_rates error print-string
    (bnc#1012382).

  - clk: mvebu: armada-38x: add support for 1866MHz variants
    (bnc#1012382).

  - clk: mvebu: armada-38x: add support for missing clocks
    (bnc#1012382).

  - clk: scpi: fix return type of __scpi_dvfs_round_rate
    (bnc#1012382).

  - clocksource/drivers/arm_arch_timer: Avoid infinite
    recursion when ftrace is enabled (bsc#1090225).

  - cpumask: Add helper cpumask_available() (bnc#1012382).

  - crypto: af_alg - fix possible uninit-value in alg_bind()
    (bnc#1012382).

  - crypto: ahash - Fix early termination in hash walk
    (bnc#1012382).

  - crypto: x86/cast5-avx - fix ECB encryption when long sg
    follows short one (bnc#1012382).

  - cx25840: fix unchecked return values (bnc#1012382).

  - cxgb4: fix incorrect cim_la output for T6 (bnc#1012382).

  - cxgb4: Fix queue free path of ULD drivers (bsc#1022743
    FATE#322540).

  - cxgb4: FW upgrade fixes (bnc#1012382).

  - cxgb4vf: Fix SGE FL buffer initialization logic for 64K
    pages (bnc#1012382).

  - dccp: initialize ireq->ir_mark (bnc#1012382).

  - dmaengine: at_xdmac: fix rare residue corruption
    (bnc#1012382).

  - dmaengine: imx-sdma: Handle return value of
    clk_prepare_enable (bnc#1012382).

  - dm ioctl: remove double parentheses (bnc#1012382).

  - Documentation: pinctrl: palmas: Add
    ti,palmas-powerhold-override property definition
    (bnc#1012382).

  - Do not leak MNT_INTERNAL away from internal mounts
    (bnc#1012382).

  - drivers/infiniband/core/verbs.c: fix build with
    gcc-4.4.4 (FATE#321732).

  - drivers/infiniband/ulp/srpt/ib_srpt.c: fix build with
    gcc-4.4.4 (bnc#1024296,FATE#321265).

  - drivers/misc/vmw_vmci/vmci_queue_pair.c: fix a couple
    integer overflow tests (bnc#1012382).

  - drm/omap: fix tiled buffer stride calculations
    (bnc#1012382).

  - drm/radeon: Fix PCIe lane width calculation
    (bnc#1012382).

  - drm/virtio: fix vq wait_event condition (bnc#1012382).

  - drm/vmwgfx: Fix a buffer object leak (bnc#1012382).

  - e1000e: fix race condition around skb_tstamp_tx()
    (bnc#1012382).

  - e1000e: Undo e1000e_pm_freeze if __e1000_shutdown fails
    (bnc#1012382).

  - EDAC, mv64x60: Fix an error handling path (bnc#1012382).

  - Enable uinput driver (bsc#1092566).

  - esp: Fix memleaks on error paths (git-fixes).

  - ext4: add validity checks for bitmap block numbers
    (bnc#1012382).

  - ext4: bugfix for mmaped pages in
    mpage_release_unused_pages() (bnc#1012382).

  - ext4: do not allow r/w mounts if metadata blocks overlap
    the superblock (bnc#1012382).

  - ext4: do not update checksum of new initialized bitmaps
    (bnc#1012382).

  - ext4: fail ext4_iget for root directory if unallocated
    (bnc#1012382).

  - ext4: fix bitmap position validation (bnc#1012382).

  - ext4: fix deadlock between inline_data and
    ext4_expand_extra_isize_ea() (bnc#1012382).

  - ext4: Fix hole length detection in ext4_ind_map_blocks()
    (bsc#1090953).

  - ext4: fix off-by-one on max nr_pages in
    ext4_find_unwritten_pgoff() (bnc#1012382).

  - ext4: prevent right-shifting extents beyond
    EXT_MAX_BLOCKS (bnc#1012382).

  - ext4: set h_journal if there is a failure starting a
    reserved handle (bnc#1012382).

  - fanotify: fix logic of events on child (bnc#1012382).

  - firmware/psci: Expose PSCI conduit (bsc#1068032).

  - firmware/psci: Expose SMCCC version through psci_ops
    (bsc#1068032).

  - fix race in drivers/char/random.c:get_reg()
    (bnc#1012382).

  - frv: declare jiffies to be located in the .data section
    (bnc#1012382).

  - fs: compat: Remove warning from COMPATIBLE_IOCTL
    (bnc#1012382).

  - fs/proc: Stop trying to report thread stacks
    (bnc#1012382).

  - fs/reiserfs/journal.c: add missing resierfs_warning()
    arg (bnc#1012382).

  - genirq: Use cpumask_available() for check of cpumask
    variable (bnc#1012382).

  - getname_kernel() needs to make sure that ->name !=
    ->iname in long case (bnc#1012382).

  - gpio: label descriptors using the device name
    (bnc#1012382).

  - gpmi-nand: Handle ECC Errors in erased pages
    (bnc#1012382).

  - hdlcdrv: Fix divide by zero in hdlcdrv_ioctl
    (bnc#1012382).

  - HID: core: Fix size as type u32 (bnc#1012382).

  - HID: Fix hid_report_len usage (bnc#1012382).

  - HID: hidraw: Fix crash on HIDIOCGFEATURE with a
    destroyed device (bnc#1012382).

  - HID: i2c-hid: fix size check and type usage
    (bnc#1012382).

  - hwmon: (ina2xx) Fix access to uninitialized mutex
    (git-fixes).

  - hwmon: (ina2xx) Make calibration register value fixed
    (bnc#1012382).

  - hypfs_kill_super(): deal with failed allocations
    (bnc#1012382).

  - i40iw: Free IEQ resources (bsc#969476 FATE#319648
    bsc#969477 FATE#319816).

  - IB/core: Fix possible crash to access NULL netdev
    (bsc#966191 FATE#320230 bsc#966186 FATE#320228).

  - IB/core: Generate GID change event regardless of RoCE
    GID table property (bsc#966191 FATE#320230 bsc#966186
    FATE#320228).

  - IB/mlx4: Fix corruption of RoCEv2 IPv4 GIDs (bsc#966191
    FATE#320230 bsc#966186 FATE#320228).

  - IB/mlx4: Include GID type when deleting GIDs from HW
    table under RoCE (bsc#966191 FATE#320230 bsc#966186
    FATE#320228).

  - IB/mlx5: Avoid passing an invalid QP type to firmware
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - IB/mlx5: Fix an error code in __mlx5_ib_modify_qp()
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - IB/mlx5: Fix incorrect size of klms in the memory region
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - IB/mlx5: Fix out-of-bounds read in
    create_raw_packet_qp_rq (bsc#966170 FATE#320225
    bsc#966172 FATE#320226).

  - IB/mlx5: revisit -Wmaybe-uninitialized warning
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - IB/mlx5: Set the default active rate and width to QDR
    and 4X (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - IB/mlx5: Use unlimited rate when static rate is not
    supported (bnc#1012382).

  - ibmvnic: Clean actual number of RX or TX pools
    (bsc#1092289).

  - ibmvnic: Clear pending interrupt after device reset
    (bsc#1089644).

  - ibmvnic: Define vnic_login_client_data name field as
    unsized array (bsc#1089198).

  - ibmvnic: Disable irqs before exiting reset from closed
    state (bsc#1084610).

  - ibmvnic: Do not notify peers on parameter change resets
    (bsc#1089198).

  - ibmvnic: Do not reset CRQ for Mobility driver resets
    (bsc#1088600).

  - ibmvnic: Fix DMA mapping mistakes (bsc#1088600).

  - ibmvnic: Fix failover case for non-redundant
    configuration (bsc#1088600).

  - ibmvnic: Fix non-fatal firmware error reset
    (bsc#1093990).

  - ibmvnic: Fix reset scheduler error handling
    (bsc#1088600).

  - ibmvnic: Fix statistics buffers memory leak
    (bsc#1093990).

  - ibmvnic: Free coherent DMA memory if FW map failed
    (bsc#1093990).

  - ibmvnic: Handle all login error conditions
    (bsc#1089198).

  - ibmvnic: Zero used TX descriptor counter on reset
    (bsc#1088600).

  - ib/srp: Fix completion vector assignment algorithm
    (bnc#1012382).

  - ib/srp: Fix srp_abort() (bnc#1012382).

  - ib/srpt: Fix abort handling (bnc#1012382).

  - ib/srpt: Fix an out-of-bounds stack access in
    srpt_zerolength_write() (bnc#1024296,FATE#321265).

  - iio: hi8435: avoid garbage event at first enable
    (bnc#1012382).

  - iio: hi8435: cleanup reset gpio (bnc#1012382).

  - iio: magnetometer: st_magn_spi: fix spi_device_id table
    (bnc#1012382).

  - input: ALPS - fix multi-touch decoding on SS4 plus
    touchpads (git-fixes).

  - input: ALPS - fix trackstick button handling on V8
    devices (git-fixes).

  - input: ALPS - fix TrackStick support for SS5 hardware
    (git-fixes).

  - input: ALPS - fix two-finger scroll breakage in right
    side on ALPS touchpad (git-fixes).

  - input: atmel_mxt_ts - add touchpad button mapping for
    Samsung Chromebook Pro (bnc#1012382).

  - input: drv260x - fix initializing overdrive voltage
    (bnc#1012382).

  - input: elan_i2c - check if device is there before really
    probing (bnc#1012382).

  - input: elan_i2c - clear INT before resetting controller
    (bnc#1012382).

  - input: elantech - force relative mode on a certain
    module (bnc#1012382).

  - input: i8042 - add Lenovo ThinkPad L460 to i8042 reset
    list (bnc#1012382).

  - input: i8042 - enable MUX on Sony VAIO VGN-CS series to
    fix touchpad (bnc#1012382).

  - input: leds - fix out of bound access (bnc#1012382).

  - input: mousedev - fix implicit conversion warning
    (bnc#1012382).

  - iommu/vt-d: Fix a potential memory leak (bnc#1012382).

  - ip6_gre: better validate user provided tunnel names
    (bnc#1012382).

  - ip6_tunnel: better validate user provided tunnel names
    (bnc#1012382).

  - ipc/shm: fix use-after-free of shm file via
    remap_file_pages() (bnc#1012382).

  - ipmi: create hardware-independent softdep for
    ipmi_devintf (bsc#1009062, bsc#1060799).

  - ipmi_ssif: Fix kernel panic at msg_done_handler
    (bsc#1088871).

  - ipsec: check return value of skb_to_sgvec always
    (bnc#1012382).

  - ip_tunnel: better validate user provided tunnel names
    (bnc#1012382).

  - ipv6: add RTA_TABLE and RTA_PREFSRC to rtm_ipv6_policy
    (bnc#1012382).

  - ipv6: avoid dad-failures for addresses with NODAD
    (bnc#1012382).

  - ipv6: sit: better validate user provided tunnel names
    (bnc#1012382).

  - ipv6: the entire IPv6 header chain must fit the first
    fragment (bnc#1012382).

  - ipvs: fix rtnl_lock lockups caused by start_sync_thread
    (bnc#1012382).

  - iw_cxgb4: print mapped ports correctly (bsc#321658
    FATE#1005778 bsc#321660 FATE#1005780 bsc#321661
    FATE#1005781).

  - jbd2: fix use after free in kjournald2() (bnc#1012382).

  - jbd2: if the journal is aborted then do not allow update
    of the log tail (bnc#1012382).

  - jffs2_kill_sb(): deal with failed allocations
    (bnc#1012382).

  - jiffies.h: declare jiffies and jiffies_64 with
    ____cacheline_aligned_in_smp (bnc#1012382).

  - kABI: add tty include to audit.c (kabi).

  - kABI: protect hid report functions (kabi).

  - kABI: protect jiffies types (kabi).

  - kABI: protect skb_to_sgvec* (kabi).

  - kABI: protect sound/timer.h include in sound pcm.c
    (kabi).

  - kABI: protect struct ath10k_hw_params (kabi).

  - kABI: protect struct cstate (kabi).

  - kABI: protect struct _lowcore (kabi).

  - kABI: protect tty include in audit.h (kabi).

  - kabi/severities: Ignore kgr_shadow_* kABI changes

  - kbuild: provide a __UNIQUE_ID for clang (bnc#1012382).

  - kexec_file: do not add extra alignment to efi memmap
    (bsc#1044596).

  - keys: DNS: limit the length of option strings
    (bnc#1012382).

  - kgraft/bnx2fc: Do not block kGraft in bnx2fc_l2_rcv
    kthread (bsc#1094033, fate#313296).

  - kGraft: fix small race in reversion code (bsc#1083125).

  - kobject: do not use WARN for registration failures
    (bnc#1012382).

  - kvm: Fix nopvspin static branch init usage
    (bsc#1056427).

  - kvm: Introduce nopvspin kernel parameter (bsc#1056427).

  - kvm: nVMX: Fix handling of lmsw instruction
    (bnc#1012382).

  - kvm: PPC: Book3S PR: Check copy_to/from_user return
    values (bnc#1012382).

  - kvm: s390: Enable all facility bits that are known good
    for passthrough (FATE#324071 LTC#158956 bnc#1012382
    bsc#1073059 bsc#1076805).

  - kvm: SVM: do not zero out segment attributes if segment
    is unusable or not present (bnc#1012382).

  - l2tp: check sockaddr length in pppol2tp_connect()
    (bnc#1012382).

  - l2tp: fix missing print session offset info
    (bnc#1012382).

  - lan78xx: Correctly indicate invalid OTP (bnc#1012382).

  - leds: pca955x: Correct I2C Functionality (bnc#1012382).

  - libata: Apply NOLPM quirk for SanDisk SD7UB3Q*G1001 SSDs
    (bnc#1012382).

  - libceph, ceph: change permission for readonly debugfs
    entries (bsc#1089115).

  - libceph: fix misjudgement of maximum monitor number
    (bsc#1089115).

  - libceph: reschedule a tick in finish_hunting()
    (bsc#1089115).

  - libceph: un-backoff on tick when we have a authenticated
    session (bsc#1089115).

  - libceph: validate con->state at the top of try_write()
    (bsc#1089115).

  - livepatch: Allow to call a custom callback when freeing
    shadow variables (bsc#1082299 fate#313296).

  - livepatch: Initialize shadow variables safely by a
    custom callback (bsc#1082299 fate#313296).

  - llc: delete timers synchronously in llc_sk_free()
    (bnc#1012382).

  - llc: fix NULL pointer deref for SOCK_ZAPPED
    (bnc#1012382).

  - llc: hold llc_sap before release_sock() (bnc#1012382).

  - llist: clang: introduce member_address_is_nonnull()
    (bnc#1012382).

  - lockd: fix lockd shutdown race (bnc#1012382).

  - lockd: lost rollback of set_grace_period() in
    lockd_down_net() (git-fixes).

  - mac80211: Add RX flag to indicate ICV stripped
    (bnc#1012382).

  - mac80211: allow not sending MIC up from driver for HW
    crypto (bnc#1012382).

  - mac80211: allow same PN for AMSDU sub-frames
    (bnc#1012382).

  - mac80211: bail out from prep_connection() if a reconfig
    is ongoing (bnc#1012382).

  - mceusb: sporadic RX truncation corruption fix
    (bnc#1012382).

  - md: document lifetime of internal rdev pointer
    (bsc#1056415).

  - md: fix two problems with setting the 're-add' device
    state (bsc#1089023).

  - md: only allow remove_and_add_spares when no sync_thread
    running (bsc#1056415).

  - md raid10: fix NULL deference in
    handle_write_completed() (git-fixes).

  - md/raid10: reset the 'first' at the end of loop
    (bnc#1012382).

  - md/raid5: make use of spin_lock_irq over
    local_irq_disable + spin_lock (bnc#1012382).

  - media: v4l2-compat-ioctl32: do not oops on overlay
    (bnc#1012382).

  - media: videobuf2-core: do not go out of the buffer range
    (bnc#1012382).

  - mei: remove dev_err message on an unsupported ioctl
    (bnc#1012382).

  - mISDN: Fix a sleep-in-atomic bug (bnc#1012382).

  - mlx5: fix bug reading rss_hash_type from CQE
    (bnc#1012382).

  - mmc: dw_mmc: Fix the DTO/CTO timeout overflow
    calculation for 32-bit systems (bsc#1088267).

  - mmc: jz4740: Fix race condition in IRQ mask update
    (bnc#1012382).

  - mm/filemap.c: fix NULL pointer in
    page_cache_tree_insert() (bnc#1012382).

  - mm, slab: reschedule cache_reap() on the same CPU
    (bnc#1012382).

  - mtd: cfi: cmdset_0001: Do not allow read/write to
    suspend erase block (bnc#1012382).

  - mtd: cfi: cmdset_0001: Workaround Micron Erase suspend
    bug (bnc#1012382).

  - mtd: cfi: cmdset_0002: Do not allow read/write to
    suspend erase block (bnc#1012382).

  - mtd: jedec_probe: Fix crash in jedec_read_mfr()
    (bnc#1012382).

  - neighbour: update neigh timestamps iff update is
    effective (bnc#1012382).

  - net: af_packet: fix race in PACKET_(R|T)X_RING
    (bnc#1012382).

  - net: atm: Fix potential Spectre v1 (bnc#1012382).

  - net: cavium: liquidio: fix up 'Avoid dma_unmap_single on
    uninitialized ndata' (bnc#1012382).

  - net: cdc_ncm: Fix TX zero padding (bnc#1012382).

  - net: emac: fix reset timeout with AR8035 phy
    (bnc#1012382).

  - net: ethernet: ti: cpsw: adjust cpsw fifos depth for
    fullduplex flow control (bnc#1012382).

  - netfilter: bridge: ebt_among: add more missing match
    size checks (bnc#1012382).

  - netfilter: ctnetlink: fix incorrect nf_ct_put during
    hash resize (bnc#1012382).

  - netfilter: ctnetlink: Make some parameters integer to
    avoid enum mismatch (bnc#1012382).

  - netfilter: nf_nat_h323: fix logical-not-parentheses
    warning (bnc#1012382).

  - netfilter: x_tables: add and use xt_check_proc_name
    (bnc#1012382).

  - net: fix deadlock while clearing neighbor proxy table
    (bnc#1012382).

  - net: fix possible out-of-bound read in
    skb_network_protocol() (bnc#1012382).

  - net: fix rtnh_ok() (bnc#1012382).

  - net: fix uninit-value in __hw_addr_add_ex()
    (bnc#1012382).

  - net: fool proof dev_valid_name() (bnc#1012382).

  - net: freescale: fix potential NULL pointer dereference
    (bnc#1012382).

  - net: hns: Fix ethtool private flags (bnc#1012382
    bsc#1085511).

  - net: hns: Fix ethtool private flags (bsc#1085511).

  - net: ieee802154: fix net_device reference release too
    early (bnc#1012382).

  - net: initialize skb->peeked when cloning (bnc#1012382).

  - net/ipv6: Fix route leaking between VRFs (bnc#1012382).

  - net/ipv6: Increment OUTxxx counters after netfilter hook
    (bnc#1012382).

  - netlink: fix uninit-value in netlink_sendmsg
    (bnc#1012382).

  - netlink: make sure nladdr has correct size in
    netlink_connect() (bnc#1012382).

  - net: llc: add lock_sock in llc_ui_bind to avoid a race
    condition (bnc#1012382).

  - net/mlx4: Check if Granular QoS per VF has been enabled
    before updating QP qos_vport (bnc#1012382).

  - net/mlx4_core: Fix memory leak while delete slave's
    resources (bsc#966191 FATE#320230 bsc#966186
    FATE#320228).

  - net/mlx4_en: Avoid adding steering rules with invalid
    ring (bnc#1012382).

  - net/mlx4_en: Fix mixed PFC and Global pause user control
    requests (bsc#1015336 FATE#321685 bsc#1015337
    FATE#321686 bsc#1015340 FATE#321687).

  - net/mlx4: Fix the check in attaching steering rules
    (bnc#1012382).

  - net/mlx5: avoid build warning for uniprocessor
    (bnc#1012382).

  - net/mlx5e: Add error print in ETS init (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5e: Check support before TC swap in ETS init
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5e: E-Switch, Use the name of static array
    instead of its address (bsc#1015342 FATE#321688
    bsc#1015343 FATE#321689).

  - net/mlx5e: Remove unused define
    MLX5_MPWRQ_STRIDES_PER_PAGE (bsc#1015342 FATE#321688
    bsc#1015343 FATE#321689).

  - net/mlx5: Fix error handling in load one (bsc#1015342
    FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5: Fix ingress/egress naming mistake (bsc#1015342
    FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5: Tolerate irq_set_affinity_hint() failures
    (bnc#1012382).

  - net: move somaxconn init from sysctl code (bnc#1012382).

  - net: phy: avoid genphy_aneg_done() for PHYs without
    clause 22 support (bnc#1012382).

  - net: qca_spi: Fix alignment issues in rx path
    (bnc#1012382).

  - net sched actions: fix dumping which requires several
    messages to user space (bnc#1012382).

  - net/sched: fix NULL dereference in the error path of
    tcf_bpf_init() (bnc#1012382).

  - net: usb: qmi_wwan: add support for ublox R410M PID
    0x90b2 (bnc#1012382).

  - net: validate attribute sizes in neigh_dump_table()
    (bnc#1012382).

  - net: x25: fix one potential use-after-free issue
    (bnc#1012382).

  - net: xfrm: use preempt-safe this_cpu_read() in
    ipcomp_alloc_tfms() (bnc#1012382).

  - nfsv4.1: RECLAIM_COMPLETE must handle
    NFS4ERR_CONN_NOT_BOUND_TO_SESSION (bnc#1012382).

  - nfsv4.1: Work around a Linux server bug.. (bnc#1012382).

  - nospec: Kill array_index_nospec_mask_check()
    (bnc#1012382).

  - nospec: Move array_index_nospec() parameter checking
    into separate macro (bnc#1012382).

  - nvme: target: fix buffer overflow (FATE#321732
    FATE#321590 bsc#993388).

  - ocfs2/dlm: Fix up kABI in dlm_ctxt (bsc#1070404).

  - ocfs2/dlm: wait for dlm recovery done when migrating all
    lock resources (bsc#1070404).

  - ovl: filter trusted xattr for non-admin (bnc#1012382).

  - packet: fix bitfield update race (bnc#1012382).

  - parisc: Fix out of array access in match_pci_device()
    (bnc#1012382).

  - parport_pc: Add support for WCH CH382L PCI-E single
    parallel port card (bnc#1012382).

  - partitions/msdos: Unable to mount UFS 44bsd partitions
    (bnc#1012382).

  - PCI/ACPI: Fix bus range comparison in pci_mcfg_lookup()
    (bsc#1084699).

  - PCI/cxgb4: Extend T3 PCI quirk to T4+ devices
    (bsc#981348).

  - PCI: Make PCI_ROM_ADDRESS_MASK a 32-bit constant
    (bnc#1012382).

  - percpu: include linux/sched.h for cond_resched()
    (bnc#1012382).

  - perf/core: Correct event creation with PERF_FORMAT_GROUP
    (bnc#1012382).

  - perf/core: Fix locking for children siblings group read
    (git-fixes).

  - perf/core: Fix possible Spectre-v1 indexing for
    ->aux_pages[] (bnc#1012382).

  - perf/core: Fix the perf_cpu_time_max_percent check
    (bnc#1012382).

  - perf header: Set proper module name when build-id event
    found (bnc#1012382).

  - perf/hwbp: Simplify the perf-hwbp code, fix
    documentation (bnc#1012382).

  - perf intel-pt: Fix error recovery from missing TIP
    packet (bnc#1012382).

  - perf intel-pt: Fix overlap detection to identify
    consecutive buffers correctly (bnc#1012382).

  - perf intel-pt: Fix sync_switch (bnc#1012382).

  - perf intel-pt: Fix timestamp following overflow
    (bnc#1012382).

  - perf probe: Add warning message if there is unexpected
    event name (bnc#1012382).

  - perf: Remove superfluous allocation error check
    (bnc#1012382).

  - perf report: Ensure the perf DSO mapping matches what
    libdw sees (bnc#1012382).

  - perf: Return proper values for user stack errors
    (bnc#1012382).

  - perf tests: Decompress kernel module before objdump
    (bnc#1012382).

  - perf tools: Fix copyfile_offset update of output offset
    (bnc#1012382).

  - perf trace: Add mmap alias for s390 (bnc#1012382).

  - perf/x86/cstate: Fix possible Spectre-v1 indexing for
    pkg_msr (bnc#1012382).

  - perf/x86: Fix possible Spectre-v1 indexing for
    hw_perf_event cache_* (bnc#1012382).

  - perf/x86: Fix possible Spectre-v1 indexing for
    x86_pmu::event_map() (bnc#1012382).

  - perf/x86/msr: Fix possible Spectre-v1 indexing in the
    MSR driver (bnc#1012382).

  - pidns: disable pid allocation if pid_ns_prepare_proc()
    is failed in alloc_pid() (bnc#1012382).

  - platform/x86: ideapad-laptop: Add MIIX 720-12IKB to
    no_hw_rfkill (bsc#1093035).

  - pNFS/flexfiles: missing error code in
    ff_layout_alloc_lseg() (bnc#1012382).

  - powerpc/64: Fix smp_wmb barrier definition use use
    lwsync consistently (bnc#1012382).

  - powerpc/64s: Add barrier_nospec (bsc#1068032,
    bsc#1080157).

  - powerpc/64s: Add support for ori barrier_nospec patching
    (bsc#1068032, bsc#1080157).

  - powerpc/64s: Enable barrier_nospec based on firmware
    settings (bsc#1068032, bsc#1080157).

  - powerpc/64s: Enhance the information in
    cpu_show_meltdown() (bsc#1068032, bsc#1075087,
    bsc#1091041).

  - powerpc/64s: Enhance the information in
    cpu_show_spectre_v1() (bsc#1068032).

  - powerpc/64s: Fix section mismatch warnings from
    setup_rfi_flush() (bsc#1068032, bsc#1075087,
    bsc#1091041).

  - powerpc/64s: Move cpu_show_meltdown() (bsc#1068032,
    bsc#1075087, bsc#1091041).

  - powerpc/64s: Patch barrier_nospec in modules
    (bsc#1068032, bsc#1080157).

  - powerpc/64s: Wire up cpu_show_spectre_v1() (bsc#1068032,
    bsc#1075087, bsc#1091041).

  - powerpc/64s: Wire up cpu_show_spectre_v2() (bsc#1068032,
    bsc#1075087, bsc#1091041).

  - powerpc/64: Use barrier_nospec in syscall entry
    (bsc#1068032, bsc#1080157).

  - powerpc: Add security feature flags for Spectre/Meltdown
    (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/[booke|4xx]: Do not clobber TCR[WP] when setting
    TCR[DIE] (bnc#1012382).

  - powerpc: conditionally compile platform-specific serial
    drivers (bsc#1066223).

  - powerpc/crash: Remove the test for cpu_online in the IPI
    callback (bsc#1088242).

  - powerpc: Do not send system reset request through the
    oops path (bsc#1088242).

  - powerpc/eeh: Fix enabling bridge MMIO windows
    (bnc#1012382).

  - powerpc/fadump: Do not use hugepages when fadump is
    active (bsc#1092772).

  - powerpc/fadump: exclude memory holes while reserving
    memory in second kernel (bsc#1092772).

  - powerpc/lib: Fix off-by-one in alternate feature
    patching (bnc#1012382).

  - powerpc/mm: allow memory hotplug into a memoryless node
    (bsc#1090663).

  - powerpc/mm: Allow memory hotplug into an offline node
    (bsc#1090663).

  - powerpc: Move default security feature flags
    (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/powernv: define a standard delay for OPAL_BUSY
    type retry loops (bnc#1012382).

  - powerpc/powernv: Fix OPAL NVRAM driver OPAL_BUSY loops
    (bnc#1012382).

  - powerpc/powernv: Handle unknown OPAL errors in
    opal_nvram_write() (bnc#1012382).

  - powerpc/powernv: Set or clear security feature flags
    (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/powernv: Use the security flags in
    pnv_setup_rfi_flush() (bsc#1068032, bsc#1075087,
    bsc#1091041).

  - powerpc/pseries: Add new H_GET_CPU_CHARACTERISTICS flags
    (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/pseries: Fix clearing of security feature flags
    (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/pseries: Restore default security feature flags
    on setup (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/pseries: Set or clear security feature flags
    (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/pseries: Use the security flags in
    pseries_setup_rfi_flush() (bsc#1068032, bsc#1075087,
    bsc#1091041).

  - powerpc/rfi-flush: Always enable fallback flush on
    pseries (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/rfi-flush: Differentiate enabled and patched
    flush types (bsc#1068032, bsc#1075087, bsc#1091041).

  - powerpc/rfi-flush: Make it possible to call
    setup_rfi_flush() again (bsc#1068032, bsc#1075087,
    bsc#1091041).

  - powerpc: signals: Discard transaction state from signal
    frames (bsc#1094059).

  - powerpc/spufs: Fix coredump of SPU contexts
    (bnc#1012382).

  - powerpc: System reset avoid interleaving oops using die
    synchronisation (bsc#1088242).

  - powerpc: Use barrier_nospec in copy_from_user()
    (bsc#1068032, bsc#1080157).

  - pppoe: check sockaddr length in pppoe_connect()
    (bnc#1012382).

  - pptp: remove a buggy dst release in pptp_connect()
    (bnc#1012382).

  - qlge: Avoid reading past end of buffer (bnc#1012382).

  - r8152: add Linksys USB3GIGV1 id (bnc#1012382).

  - r8169: fix setting driver_data after register_netdev
    (bnc#1012382).

  - radeon: hide pointless #warning when compile testing
    (bnc#1012382).

  - random: use a tighter cap in credit_entropy_bits_safe()
    (bnc#1012382).

  - random: use lockless method of accessing and updating
    f->reg_idx (bnc#1012382).

  - ray_cs: Avoid reading past end of buffer (bnc#1012382).

  - rdma/core: Avoid that ib_drain_qp() triggers an
    out-of-bounds stack access (FATE#321732).

  - rdma/mlx5: Protect from NULL pointer derefence
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - rdma/mlx5: Protect from shift operand overflow
    (bnc#1012382).

  - rdma/qedr: fix QP's ack timeout configuration
    (bsc#1022604 FATE#321747).

  - rdma/qedr: Fix QP state initialization race (bsc#1022604
    FATE#321747).

  - rdma/qedr: Fix rc initialization on CNQ allocation
    failure (bsc#1022604 FATE#321747).

  - rdma/rxe: Fix an out-of-bounds read (FATE#322149).

  - rdma/ucma: Allow resolving address w/o specifying source
    address (bnc#1012382).

  - rdma/ucma: Check AF family prior resolving address
    (bnc#1012382).

  - rdma/ucma: Check that device exists prior to accessing
    it (bnc#1012382).

  - rdma/ucma: Check that device is connected prior to
    access it (bnc#1012382).

  - rdma/ucma: Do not allow join attempts for unsupported AF
    family (bnc#1012382).

  - rdma/ucma: Do not allow setting RDMA_OPTION_IB_PATH
    without an RDMA device (bnc#1012382).

  - rdma/ucma: Ensure that CM_ID exists prior to access it
    (bnc#1012382).

  - rdma/ucma: Fix use-after-free access in ucma_close
    (bnc#1012382).

  - rdma/ucma: Introduce safer rdma_addr_size() variants
    (bnc#1012382).

  - rds; Reset rs->rs_bound_addr in rds_add_bound() failure
    path (bnc#1012382).

  - regulator: gpio: Fix some error handling paths in
    'gpio_regulator_probe()' (bsc#1091960).

  - resource: fix integer overflow at reallocation
    (bnc#1012382).

  - Revert 'alsa: pcm: Fix mutex unbalance in OSS emulation
    ioctls' (kabi).

  - Revert 'alsa: pcm: Return -EBUSY for OSS ioctls changing
    busy streams' (kabi).

  - Revert 'arm: dts: am335x-pepper: Fix the audio CODEC's
    reset pin' (bnc#1012382).

  - Revert 'arm: dts: omap3-n900: Fix the audio CODEC's
    reset pin' (bnc#1012382).

  - Revert 'ath10k: rebuild crypto header in rx data frames'
    (kabi).

  - Revert 'ath10k: send (re)assoc peer command when NSS
    changed' (bnc#1012382).

  - Revert 'Bluetooth: btusb: Fix quirk for Atheros
    1525/QCA6174' (bnc#1012382).

  - Revert 'cpufreq: Fix governor module removal race'
    (bnc#1012382).

  - Revert 'ip6_vti: adjust vti mtu according to mtu of
    lower device' (bnc#1012382).

  - Revert 'kvm: Fix stack-out-of-bounds read in write_mmio'
    (bnc#1083635).

  - Revert 'mac80211: Add RX flag to indicate ICV stripped'
    (kabi).

  - Revert 'mac80211: allow not sending MIC up from driver
    for HW crypto' (kabi).

  - Revert 'mac80211: allow same PN for AMSDU sub-frames'
    (kabi).

  - Revert 'mtd: cfi: cmdset_0001: Do not allow read/write
    to suspend erase block.' (kabi).

  - Revert 'mtd: cfi: cmdset_0001: Workaround Micron Erase
    suspend bug.' (kabi).

  - Revert 'mtd: cfi: cmdset_0002: Do not allow read/write
    to suspend erase block.' (kabi).

  - Revert 'mtip32xx: use runtime tag to initialize command
    header' (bnc#1012382).

  - Revert 'PCI/MSI: Stop disabling MSI/MSI-X in
    pci_device_shutdown()' (bnc#1012382).

  - Revert 'perf tests: Decompress kernel module before
    objdump' (bnc#1012382).

  - Revert 'xhci: plat: Register shutdown for xhci_plat'
    (bnc#1012382).

  - rfkill: gpio: fix memory leak in probe error path
    (bnc#1012382).

  - rpc_pipefs: fix double-dput() (bnc#1012382).

  - rpm/config.sh: build against SP3 in OBS as well.

  - rtc: interface: Validate alarm-time before handling
    rollover (bnc#1012382).

  - rtc: opal: Handle disabled TPO in opal_get_tpo_time()
    (bnc#1012382).

  - rtc: snvs: fix an incorrect check of return value
    (bnc#1012382).

  - rtl8187: Fix NULL pointer dereference in
    priv->conf_mutex (bnc#1012382).

  - rxrpc: check return value of skb_to_sgvec always
    (bnc#1012382).

  - s390: add automatic detection of the spectre defense
    (bnc#1012382).

  - s390: add optimized array_index_mask_nospec
    (bnc#1012382).

  - s390: add options to change branch prediction behaviour
    for the kernel (bnc#1012382 bsc#1068032).

  - s390: add sysfs attributes for spectre (bnc#1012382).

  - s390/alternative: use a copy of the facility bit mask
    (bnc#1012382).

  - s390/cio: update chpid descriptor after resource
    accessibility event (bnc#1012382).

  - s390: correct module section names for expoline code
    revert (bnc#1012382).

  - s390: correct nospec auto detection init order
    (bnc#1012382).

  - s390/dasd: fix hanging safe offline (bnc#1012382).

  - s390/dasd: fix IO error for newly defined devices
    (bnc#1093144, LTC#167398).

  - s390: do not bypass BPENTER for interrupt system calls
    (bnc#1012382).

  - s390: enable CPU alternatives unconditionally
    (bnc#1012382).

  - s390/entry.S: fix spurious zeroing of r0 (bnc#1012382).

  - s390: introduce execute-trampolines for branches
    (bnc#1012382).

  - s390/ipl: ensure loadparm valid flag is set
    (bnc#1012382).

  - s390: move nobp parameter functions to nospec-branch.c
    (bnc#1012382).

  - s390: move _text symbol to address higher than zero
    (bnc#1012382).

  - s390/qdio: do not merge ERROR output buffers
    (bnc#1012382).

  - s390/qdio: do not retry EQBS after CCQ 96 (bnc#1012382).

  - s390/qeth: consolidate errno translation (bnc#1093144,
    LTC#167507).

  - s390/qeth: fix MAC address update sequence (bnc#1093144,
    LTC#167609).

  - s390/qeth: translate SETVLAN/DELVLAN errors
    (bnc#1093144, LTC#167507).

  - s390: Replace IS_ENABLED(EXPOLINE_*) with
    IS_ENABLED(CONFIG_EXPOLINE_*) (bnc#1012382).

  - s390: report spectre mitigation via syslog
    (bnc#1012382).

  - s390: run user space and KVM guests with modified branch
    prediction (bnc#1012382).

  - s390: scrub registers on kernel entry and KVM exit
    (bnc#1012382).

  - s390/uprobes: implement arch_uretprobe_is_alive()
    (bnc#1012382).

  - sched/numa: Use down_read_trylock() for the mmap_sem
    (bnc#1012382).

  - scsi: bnx2fc: fix race condition in
    bnx2fc_get_host_stats() (bnc#1012382).

  - scsi: libiscsi: Allow sd_shutdown on bad transport
    (bnc#1012382).

  - scsi: libsas: initialize sas_phy status according to
    response of DISCOVER (bnc#1012382).

  - scsi: lpfc: Add per io channel NVME IO statistics
    (bsc#1088865).

  - scsi: lpfc: Correct missing remoteport registration
    during link bounces (bsc#1088865).

  - scsi: lpfc: Correct target queue depth application
    changes (bsc#1088865).

  - scsi: lpfc: Enlarge nvmet asynchronous receive buffer
    counts (bsc#1088865).

  - scsi: lpfc: Fix Abort request WQ selection
    (bsc#1088865).

  - scsi: lpfc: Fix driver not recovering NVME rports during
    target link faults (bsc#1088865).

  - scsi: lpfc: Fix lingering lpfc_wq resource after driver
    unload (bsc#1088865).

  - scsi: lpfc: Fix multiple PRLI completion error path
    (bsc#1088865).

  - scsi: lpfc: Fix NULL pointer access in
    lpfc_nvme_info_show (bsc#1088865).

  - scsi: lpfc: Fix NULL pointer reference when resetting
    adapter (bsc#1088865).

  - scsi: lpfc: Fix nvme remoteport registration race
    conditions (bsc#1088865).

  - scsi: lpfc: Fix WQ/CQ creation for older asic's
    (bsc#1088865).

  - scsi: lpfc: update driver version to 11.4.0.7-2
    (bsc#1088865).

  - scsi: mpt3sas: Proper handling of set/clear of 'ATA
    command pending' flag (bnc#1012382).

  - scsi: mptsas: Disable WRITE SAME (bnc#1012382).

  - scsi: sd: Defer spinning up drive while SANITIZE is in
    progress (bnc#1012382).

  - sctp: do not check port in sctp_inet6_cmp_addr
    (bnc#1012382).

  - sctp: do not leak kernel memory to user space
    (bnc#1012382).

  - sctp: fix recursive locking warning in sctp_do_peeloff
    (bnc#1012382).

  - sctp: sctp_sockaddr_af must check minimal addr length
    for AF_INET6 (bnc#1012382).

  - selftests/powerpc: Fix TM resched DSCR test with some
    compilers (bnc#1012382).

  - selinux: do not check open permission on sockets
    (bnc#1012382).

  - selinux: Remove redundant check for unknown labeling
    behavior (bnc#1012382).

  - selinux: Remove unnecessary check of array base in
    selinux_set_mapping() (bnc#1012382).

  - serial: 8250: omap: Disable DMA for console UART
    (bnc#1012382).

  - serial: mctrl_gpio: Add missing module license
    (bnc#1012382).

  - serial: mctrl_gpio: export mctrl_gpio_disable_ms and
    mctrl_gpio_init (bnc#1012382).

  - serial: sh-sci: Fix race condition causing garbage
    during shutdown (bnc#1012382).

  - sh_eth: Use platform device for printing before
    register_netdev() (bnc#1012382).

  - sit: reload iphdr in ipip6_rcv (bnc#1012382).

  - skbuff: only inherit relevant tx_flags (bnc#1012382).

  - skbuff: return -EMSGSIZE in skb_to_sgvec to prevent
    overflow (bnc#1012382).

  - sky2: Increase D3 delay to sky2 stops working after
    suspend (bnc#1012382).

  - slip: Check if rstate is initialized before
    uncompressing (bnc#1012382).

  - soreuseport: initialise timewait reuseport field
    (bnc#1012382).

  - sparc64: ldc abort during vds iso boot (bnc#1012382).

  - spi: davinci: fix up dma_mapping_error() incorrect patch
    (bnc#1012382).

  - staging: comedi: ni_mio_common: ack ai fifo error
    interrupts (bnc#1012382).

  - staging: ion : Donnot wakeup kswapd in ion system alloc
    (bnc#1012382).

  - staging: wlan-ng: prism2mgmt.c: fixed a double endian
    conversion before calling hfa384x_drvr_setconfig16, also
    fixes relative sparse warning (bnc#1012382).

  - stop_machine, sched: Fix migrate_swap() vs.
    active_balance() deadlock (bsc#1088810).

  - swap: divide-by-zero when zero length swap file on ssd
    (bsc#1082153).

  - tags: honor COMPILED_SOURCE with apart output directory
    (bnc#1012382).

  - target: prefer dbroot of /etc/target over /var/target
    (bsc#1087274).

  - target: transport should handle st FM/EOM/ILI reads
    (bsc#1081599).

  - tcp: better validation of received ack sequences
    (bnc#1012382).

  - tcp: do not read out-of-bounds opsize (bnc#1012382).

  - tcp: fix TCP_REPAIR_QUEUE bound checking (bnc#1012382).

  - tcp: md5: reject TCP_MD5SIG or TCP_MD5SIG_EXT on
    established sockets (bnc#1012382).

  - team: avoid adding twice the same option to the event
    list (bnc#1012382).

  - team: fix netconsole setup over team (bnc#1012382).

  - test_firmware: fix setting old custom fw path back on
    exit, second try (bnc#1012382).

  - thermal: imx: Fix race condition in imx_thermal_probe()
    (bnc#1012382).

  - thermal: power_allocator: fix one race condition issue
    for thermal_instances list (bnc#1012382).

  - thunderbolt: Resume control channel after hibernation
    image is created (bnc#1012382).

  - tipc: add policy for TIPC_NLA_NET_ADDR (bnc#1012382).

  - tracepoint: Do not warn on ENOMEM (bnc#1012382).

  - tracing: Fix regex_match_front() to not over compare the
    test string (bnc#1012382).

  - tracing/uprobe_event: Fix strncpy corner case
    (bnc#1012382).

  - tty: Do not call panic() at tty_ldisc_init()
    (bnc#1012382).

  - tty: make n_tty_read() always abort if hangup is in
    progress (bnc#1012382).

  - tty: n_gsm: Allow ADM response in addition to UA for
    control dlci (bnc#1012382).

  - tty: n_gsm: Fix DLCI handling for ADM mode if debug & 2
    is not set (bnc#1012382).

  - tty: n_gsm: Fix long delays with control frame timeouts
    in ADM mode (bnc#1012382).

  - tty: provide tty_name() even without CONFIG_TTY
    (bnc#1012382).

  - tty: Use __GFP_NOFAIL for tty_ldisc_get() (bnc#1012382).

  - ubi: fastmap: Do not flush fastmap work on detach
    (bnc#1012382).

  - ubi: Fix error for write access (bnc#1012382).

  - ubifs: Check ubifs_wbuf_sync() return code
    (bnc#1012382).

  - ubi: Reject MLC NAND (bnc#1012382).

  - um: Use POSIX ucontext_t instead of struct ucontext
    (bnc#1012382).

  - Update config files, add expoline for s390x
    (bsc#1089393).

  - Update
    patches.fixes/0001-md-raid10-fix-NULL-deference-in-handl
    e_write_complet.patch (bsc#1056415).

  - Update
    patches.fixes/xfs-refactor-log-record-unpack-and-data-pr
    ocessing.patch (bsc#1043598, bsc#1036215).

  - Update
    patches.suse/powerpc-powernv-Support-firmware-disable-of
    -RFI-flus.patch (bsc#1068032, bsc#1075087, bsc#1091041).

  - Update
    patches.suse/powerpc-pseries-Support-firmware-disable-of
    -RFI-flus.patch (bsc#1068032, bsc#1075087, bsc#1091041).

  - Update
    patches.suse/powerpc-rfi-flush-Move-the-logic-to-avoid-a
    -redo-int.patch (bsc#1068032, bsc#1075087, bsc#1091041).

  - Update
    patches.suse/x86-nospectre_v2-means-nospec-too.patch
    (bsc#1075994 bsc#1075091 bnc#1085958).

  - usb: Accept bulk endpoints with 1024-byte maxpacket
    (bnc#1012382 bsc#1092888).

  - usb: Accept bulk endpoints with 1024-byte maxpacket
    (bsc#1092888).

  - usb: chipidea: properly handle host or gadget
    initialization failure (bnc#1012382).

  - usb: core: Add quirk for HP v222w 16GB Mini
    (bnc#1012382).

  - usb: dwc2: Improve gadget state disconnection handling
    (bnc#1012382).

  - usb: dwc3: keystone: check return value (bnc#1012382).

  - usb: dwc3: pci: Properly cleanup resource (bnc#1012382).

  - usb: ene_usb6250: fix first command execution
    (bnc#1012382).

  - usb: ene_usb6250: fix SCSI residue overwriting
    (bnc#1012382).

  - usb:fix USB3 devices behind USB3 hubs not resuming at
    hibernate thaw (bnc#1012382).

  - usb: gadget: align buffer size when allocating for OUT
    endpoint (bnc#1012382).

  - usb: gadget: change len to size_t on alloc_ep_req()
    (bnc#1012382).

  - usb: gadget: define free_ep_req as universal function
    (bnc#1012382).

  - usb: gadget: f_hid: fix: Prevent accessing released
    memory (bnc#1012382).

  - usb: gadget: fix request length error for isoc transfer
    (git-fixes).

  - usb: gadget: fix usb_ep_align_maybe endianness and new
    usb_ep_align (bnc#1012382).

  - usb: Increment wakeup count on remote wakeup
    (bnc#1012382).

  - usbip: usbip_host: fix to hold parent lock for
    device_attach() calls (bnc#1012382).

  - usbip: vhci_hcd: Fix usb device and sockfd leaks
    (bnc#1012382).

  - usb: musb: gadget: misplaced out of bounds check
    (bnc#1012382).

  - usb: musb: host: fix potential NULL pointer dereference
    (bnc#1012382).

  - usb: serial: cp210x: add ELDAT Easywave RX09 id
    (bnc#1012382).

  - usb: serial: cp210x: add ID for NI USB serial console
    (bnc#1012382).

  - usb: serial: ftdi_sio: add RT Systems VX-8 cable
    (bnc#1012382).

  - usb: serial: ftdi_sio: add support for Harman
    FirmwareHubEmulator (bnc#1012382).

  - usb: serial: ftdi_sio: use jtag quirk for Arrow USB
    Blaster (bnc#1012382).

  - usb: serial: option: adding support for ublox R410M
    (bnc#1012382).

  - usb: serial: option: Add support for Quectel EP06
    (bnc#1012382).

  - usb: serial: option: reimplement interface masking
    (bnc#1012382).

  - usb: serial: simple: add libtransistor console
    (bnc#1012382).

  - usb: serial: visor: handle potential invalid device
    configuration (bnc#1012382).

  - vfb: fix video mode and line_length being set when
    loaded (bnc#1012382).

  - vfio/pci: Virtualize Maximum Payload Size (bnc#1012382).

  - vfio/pci: Virtualize Maximum Read Request Size
    (bnc#1012382).

  - vfio-pci: Virtualize PCIe & AF FLR (bnc#1012382).

  - vhost: correctly remove wait queue during poll failure
    (bnc#1012382).

  - virtio: add ability to iterate over vqs (bnc#1012382).

  - virtio_console: free buffers after reset (bnc#1012382).

  - virtio_net: check return value of skb_to_sgvec always
    (bnc#1012382).

  - virtio_net: check return value of skb_to_sgvec in one
    more location (bnc#1012382).

  - vlan: also check phy_driver ts_info for vlan's real
    device (bnc#1012382).

  - vlan: Fix reading memory beyond skb->tail in
    skb_vlan_tagged_multi (bnc#1012382).

  - vmxnet3: ensure that adapter is in proper state during
    force_close (bnc#1012382).

  - vrf: Fix use after free and double free in
    vrf_finish_output (bnc#1012382).

  - vt: change SGR 21 to follow the standards (bnc#1012382).

  - vti6: better validate user provided tunnel names
    (bnc#1012382).

  - vxlan: dont migrate permanent fdb entries during learn
    (bnc#1012382).

  - watchdog: f71808e_wdt: Fix WD_EN register read
    (bnc#1012382).

  - watchdog: hpwdt: Remove legacy NMI sourcing
    (bsc#1085185).

  - watchdog: sbsa: use 32-bit read for WCV (bsc#1085679).

  - wl1251: check return from call to
    wl1251_acx_arp_ip_filter (bnc#1012382).

  - writeback: fix the wrong congested state variable
    definition (bnc#1012382).

  - writeback: safer lock nesting (bnc#1012382).

  - x86/asm: Do not use RBP as a temporary register in
    csum_partial_copy_generic() (bnc#1012382).

  - x86/bugs: correctly force-disable IBRS on !SKL systems
    (bsc#1092497).

  - x86/bugs: Make sure that _TIF_SSBD does not end up in
    _TIF_ALLWORK_MASK (bsc#1093215).

  - x86/bugs: Respect retpoline command line option
    (bsc#1068032).

  - x86/hweight: Do not clobber %rdi (bnc#1012382).

  - x86/hweight: Get rid of the special calling convention
    (bnc#1012382).

  - x86/ipc: Fix x32 version of shmid64_ds and msqid64_ds
    (bnc#1012382).

  - x86/platform/UV: Add references to access fixed UV4A HUB
    MMRs (bsc#1076263 #fate#322814).

  - x86/platform/uv/BAU: Replace hard-coded values with MMR
    definitions (bsc#1076263 #fate#322814).

  - x86/platform/UV: Fix critical UV MMR address error
    (bsc#1076263

  - x86/platform/UV: Fix GAM MMR changes in UV4A
    (bsc#1076263 #fate#322814).

  - x86/platform/UV: Fix GAM MMR references in the UV x2apic
    code (bsc#1076263 #fate#322814).

  - x86/platform/UV: Fix GAM Range Table entries less than
    1GB (bsc#1091325).

  - x86/platform/UV: Fix UV4A BAU MMRs (bsc#1076263
    #fate#322814).

  - x86/platform/UV: Fix UV4A support on new Intel
    Processors (bsc#1076263 #fate#322814).

  - x86/platform/uv: Skip UV runtime services mapping in the
    efi_runtime_disabled case (bsc#1089925).

  - x86/platform/UV: Update uv_mmrs.h to prepare for UV4A
    fixes (bsc#1076263 #fate#322814).

  - x86/smpboot: Do not use mwait_play_dead() on AMD systems
    (bnc#1012382).

  - x86/tsc: Prevent 32bit truncation in calc_hpet_ref()
    (bnc#1012382).

  - x86/tsc: Provide 'tsc=unstable' boot parameter
    (bnc#1012382).

  - xen: avoid type warning in xchg_xen_ulong (bnc#1012382).

  - xen-netfront: Fix hang on device removal (bnc#1012382).

  - xfrm: fix state migration copy replay sequence numbers
    (bnc#1012382).

  - xfrm: Refuse to insert 32 bit userspace socket policies
    on 64 bit systems (bnc#1012382).

  - xfrm_user: fix return value from xfrm_user_rcv_msg
    (bnc#1012382).

  - xfrm_user: uncoditionally validate esn replay attribute
    struct (bnc#1012382).

  - xfs: always verify the log tail during recovery
    (bsc#1036215).

  - xfs: detect and handle invalid iclog size set by mkfs
    (bsc#1043598).

  - xfs: detect and trim torn writes during log recovery
    (bsc#1036215).

  - xfs: fix log recovery corruption error due to tail
    overwrite (bsc#1036215).

  - xfs: fix recovery failure when log record header wraps
    log end (bsc#1036215).

  - xfs: handle -EFSCORRUPTED during head/tail verification
    (bsc#1036215).

  - xfs: prevent creating negative-sized file via
    INSERT_RANGE (bnc#1012382).

  - xfs: refactor and open code log record crc check
    (bsc#1036215).

  - xfs: refactor log record start detection into a new
    helper (bsc#1036215).

  - xfs: return start block of first bad log record during
    recovery (bsc#1036215).

  - xfs: support a crc verification only log record pass
    (bsc#1036215).

  - x86/bugs: make intel_rds_mask() honor X86_FEATURE_SSBD
    (bsc#1094019).

  - watchdog: hpwdt: condition early return of NMI handler
    on iLO5 (bsc#1085185).

  - watchdog: hpwdt: Modify to use watchdog core
    (bsc#1085185).

  - watchdog: hpwdt: Update nmi_panic message (bsc#1085185).

  - watchdog: hpwdt: Update Module info and copyright
    (bsc#1085185)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015340"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060799"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=802154"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993388"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-debuginfo-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-4.4.132-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-debuginfo-4.4.132-53.1") ) flag++;

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
