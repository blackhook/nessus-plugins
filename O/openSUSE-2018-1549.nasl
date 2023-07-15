#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1549.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119709);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-1549)");
  script_summary(english:"Check for the openSUSE-2018-1549 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.165-81.1 to receive
various bugfixes.

The following non-security bugs were fixed :

  - 9p locks: fix glock.client_id leak in do_lock
    (bnc#1012382).

  - 9p: clear dangling pointers in p9stat_free
    (bnc#1012382).

  - ACPI / LPSS: Add alternative ACPI HIDs for Cherry Trail
    DMA controllers (bnc#1012382).

  - ACPI / platform: Add SMB0001 HID to forbidden_id_list
    (bnc#1012382).

  - ALSA: ca0106: Disable IZD on SB0570 DAC to fix audio
    pops (bnc#1012382).

  - ALSA: hda - Add mic quirk for the Lenovo G50-30
    (17aa:3905) (bnc#1012382).

  - ALSA: hda: Check the non-cached stream buffers more
    explicitly (bnc#1012382).

  - ALSA: timer: Fix zero-division by continue of
    uninitialized instance (bnc#1012382).

  - ARM64: PCI: ACPI support for legacy IRQs parsing and
    consolidation with DT code (bsc#985031).

  - ARM: 8799/1: mm: fix pci_ioremap_io() offset check
    (bnc#1012382).

  - ARM: dts: apq8064: add ahci ports-implemented mask
    (bnc#1012382).

  - ARM: dts: imx53-qsb: disable 1.2GHz OPP (bnc#1012382).

  - ASoC: ak4613: Enable cache usage to fix crashes on
    resume (bnc#1012382).

  - ASoC: spear: fix error return code in spdif_in_probe()
    (bnc#1012382).

  - ASoC: wm8940: Enable cache usage to fix crashes on
    resume (bnc#1012382).

  - Bluetooth: SMP: fix crash in unpairing (bnc#1012382).

  - Bluetooth: btbcm: Add entry for BCM4335C0 UART bluetooth
    (bnc#1012382).

  - Btrfs: fix data corruption due to cloning of eof block
    (bnc#1012382).

  - Btrfs: fix NULL pointer dereference on compressed write
    path error (bnc#1012382).

  - Btrfs: fix wrong dentries after fsync of file that got
    its parent replaced (bnc#1012382).

  - CIFS: handle guest access errors to Windows shares
    (bnc#1012382).

  - Cramfs: fix abad comparison when wrap-arounds occur
    (bnc#1012382).

  - Fix kABI for 'Ensure we commit after writeback is
    complete' (bsc#1111809).

  - HID: hiddev: fix potential Spectre v1 (bnc#1012382).

  - HID: uhid: forbid UHID_CREATE under KERNEL_DS or
    elevated privileges (bnc#1012382).

  - IB/ucm: Fix Spectre v1 vulnerability (bnc#1012382).

  - Input: elan_i2c - add ACPI ID for Lenovo IdeaPad
    330-15IGM (bnc#1012382).

  - KEYS: put keyring if install_session_keyring_to_cred()
    fails (bnc#1012382).

  - KVM: nVMX: Always reflect #NM VM-exits to L1
    (bsc#1106240).

  - MD: fix invalid stored role for a disk (bnc#1012382).

  - MD: fix invalid stored role for a disk - try2
    (bnc#1012382).

  - MIPS: DEC: Fix an int-handler.S CPU_DADDI_WORKAROUNDS
    regression (bnc#1012382).

  - MIPS: Fix FCSR Cause bit handling for correct SIGFPE
    issue (bnc#1012382).

  - MIPS: Handle non word sized instructions when examining
    frame (bnc#1012382).

  - MIPS: Loongson-3: Fix BRIDGE irq delivery problem
    (bnc#1012382).

  - MIPS: Loongson-3: Fix CPU UART irq delivery problem
    (bnc#1012382).

  - MIPS: OCTEON: fix out of bounds array access on CN68XX
    (bnc#1012382).

  - MIPS: kexec: Mark CPU offline before disabling local IRQ
    (bnc#1012382).

  - MIPS: microMIPS: Fix decoding of swsp16 instruction
    (bnc#1012382).

  - NFS: Ensure we commit after writeback is complete
    (bsc#1111809).

  - NFSv4.1: Fix the r/wsize checking (bnc#1012382).

  - PCI/ASPM: Do not initialize link state when
    aspm_disabled is set (bsc#1109806).

  - PCI/ASPM: Fix link_state teardown on device removal
    (bsc#1109806).

  - PCI: Add Device IDs for Intel GPU 'spurious interrupt'
    quirk (bnc#1012382).

  - PCI: vmd: Detach resources after stopping root bus
    (bsc#1106105).

  - PM / devfreq: tegra: fix error return code in
    tegra_devfreq_probe() (bnc#1012382).

  - Provide a temporary fix for STIBP on-by-default See
    bsc#1116497 for details.

  - RDMA/ucma: Fix Spectre v1 vulnerability (bnc#1012382).

  - Reorder a few commits in kGraft out of tree section

  - Revert 'Bluetooth: h5: Fix missing dependency on
    BT_HCIUART_SERDEV' (bnc#1012382).

  - Revert 'ceph: fix dentry leak in splice_dentry()'
    (bsc#1114839).

  - Revert 'media: v4l: event: Add subscription to list
    before calling 'add' operation' (kabi).

  - Revert 'media: videobuf2-core: do not call memop
    'finish' when queueing' (bnc#1012382).

  - Revert 'x86/kconfig: Fall back to ticket spinlocks'
    (kabi).

  - SUNRPC: drop pointless static qualifier in
    xdr_get_next_encode_buffer() (bnc#1012382).

  - TC: Set DMA masks for devices (bnc#1012382).

  - USB: fix the usbfs flag sanitization for control
    transfers (bnc#1012382).

  - USB: misc: appledisplay: add 20' Apple Cinema Display
    (bnc#1012382).

  - USB: quirks: Add no-lpm quirk for Raydium touchscreens
    (bnc#1012382).

  - af_iucv: Move sockaddr length checks to before accessing
    sa_family in bind and connect handlers (bnc#1012382).

  - ahci: do not ignore result code of
    ahci_reset_controller() (bnc#1012382).

  - amd/iommu: Fix Guest Virtual APIC Log Tail Address
    Register (bsc#1106105).

  - arch/alpha, termios: implement BOTHER, IBSHIFT and
    termios2 (bnc#1012382).

  - arm64: Disable asm-operand-width warning for clang
    (bnc#1012382).

  - arm64: dts: stratix10: Correct System Manager register
    size (bnc#1012382).

  - arm64: hardcode rodata_enabled=true earlier in the
    series (bsc#1114763). 

  - arm64: percpu: Initialize ret in the default case
    (bnc#1012382).

  - arm: fix mis-applied iommu identity check (bsc#1116924). 

  - asix: Check for supported Wake-on-LAN modes
    (bnc#1012382).

  - ataflop: fix error handling during setup (bnc#1012382).

  - ath10k: schedule hardware restart if WMI command times
    out (bnc#1012382).

  - ax88179_178a: Check for supported Wake-on-LAN modes
    (bnc#1012382).

  - bcache: fix miss key refill->end in writeback
    (bnc#1012382).

  - binfmt_elf: fix calculations for bss padding
    (bnc#1012382).

  - bitops: protect variables in bit_clear_unless() macro
    (bsc#1116285).

  - block: fix inheriting request priority from bio
    (bsc#1116924).

  - block: respect virtual boundary mask in bvecs
    (bsc#1113412).

  - bna: ethtool: Avoid reading past end of buffer
    (bnc#1012382).

  - bpf: generally move prog destruction to RCU deferral
    (bnc#1012382).

  - bridge: do not add port to router list when receives
    query with source 0.0.0.0 (bnc#1012382).

  - btrfs: Handle owner mismatch gracefully when walking up
    tree (bnc#1012382).

  - btrfs: do not attempt to trim devices that do not
    support it (bnc#1012382).

  - btrfs: fix backport error in submit_stripe_bio
    (bsc#1114763).

  - btrfs: fix pinned underflow after transaction aborted
    (bnc#1012382).

  - btrfs: iterate all devices during trim, instead of
    fs_devices::alloc_list (bnc#1012382).

  - btrfs: locking: Add extra check in
    btrfs_init_new_buffer() to avoid deadlock (bnc#1012382).

  - btrfs: make sure we create all new block groups
    (bnc#1012382).

  - btrfs: qgroup: Dirty all qgroups before rescan
    (bnc#1012382).

  - btrfs: reset max_extent_size on clear in a bitmap
    (bnc#1012382).

  - btrfs: set max_extent_size properly (bnc#1012382).

  - btrfs: wait on caching when putting the bg cache
    (bnc#1012382).

  - cachefiles: fix the race between
    cachefiles_bury_object() and rmdir(2) (bnc#1012382).

  - cdc-acm: correct counting of UART states in serial state
    notification (bnc#1012382).

  - ceph: call setattr_prepare from ceph_setattr instead of
    inode_change_ok (bsc#1114763).

  - ceph: fix dentry leak in ceph_readdir_prepopulate
    (bsc#1114839).

  - ceph: quota: fix NULL pointer dereference in quota check
    (bsc#1114839).

  - cfg80211: reg: Init wiphy_idx in regulatory_hint_core()
    (bnc#1012382).

  - clk: s2mps11: Add used attribute to s2mps11_dt_match
    (git-fixes).

  - clk: s2mps11: Fix matching when built as module and DT
    node contains compatible (bnc#1012382).

  - clk: samsung: exynos5420: Enable PERIS clocks for
    suspend (bnc#1012382).

  - clockevents/drivers/i8253: Add support for PIT shutdown
    quirk (bnc#1012382).

  - configfs: replace strncpy with memcpy (bnc#1012382).

  - cpuidle: Do not access cpuidle_devices when
    !CONFIG_CPU_IDLE (bnc#1012382).

  - crypto, x86: aesni - fix token pasting for clang
    (bnc#1012382).

  - crypto: arm64/sha - avoid non-standard inline asm tricks
    (bnc#1012382).

  - crypto: lrw - Fix out-of bounds access on counter
    overflow (bnc#1012382).

  - crypto: shash - Fix a sleep-in-atomic bug in
    shash_setkey_unaligned (bnc#1012382).

  - cxgb4: Add support for new flash parts (bsc#1102439).

  - cxgb4: Fix FW flash errors (bsc#1102439).

  - cxgb4: assume flash part size to be 4MB, if it can't be
    determined (bsc#1102439).

  - cxgb4: fix missing break in switch and indent return
    statements (bsc#1102439).

  - cxgb4: support new ISSI flash parts (bsc#1102439).

  - dm ioctl: harden copy_params()'s copy_from_user() from
    malicious users (bnc#1012382).

  - dm raid: stop using BUG() in __rdev_sectors()
    (bsc#1046264).

  - dmaengine: dma-jz4780: Return error if not probed from
    DT (bnc#1012382).

  - dpaa_eth: fix dpaa_get_stats64 to match prototype
    (bsc#1114763).

  - driver/dma/ioat: Call del_timer_sync() without holding
    prep_lock (bnc#1012382).

  - drivers/misc/sgi-gru: fix Spectre v1 vulnerability
    (bnc#1012382).

  - drm/ast: Remove existing framebuffers before loading
    driver (boo#1112963)

  - drm/dp_mst: Check if primary mstb is null (bnc#1012382).

  - drm/hisilicon: hibmc: Do not carry error code in HiBMC
    framebuffer (bsc#1113766)

  - drm/hisilicon: hibmc: Do not overwrite fb helper surface
    depth (bsc#1113766)

  - drm/i915/hdmi: Add HDMI 2.0 audio clock recovery N
    values (bnc#1012382).

  - drm/nouveau/fbcon: fix oops without fbdev emulation
    (bnc#1012382).

  - drm/omap: fix memory barrier bug in DMM driver
    (bnc#1012382).

  - drm/rockchip: Allow driver to be shutdown on
    reboot/kexec (bnc#1012382).

  - e1000: avoid NULL pointer dereference on invalid stat
    type (bnc#1012382).

  - e1000: fix race condition between e1000_down() and
    e1000_watchdog (bnc#1012382).

  - efi/libstub/arm64: Force 'hidden' visibility for section
    markers (bnc#1012382).

  - efi/libstub/arm64: Set -fpie when building the EFI stub
    (bnc#1012382).

  - ext4: add missing brelse() add_new_gdb_meta_bg()'s error
    path (bnc#1012382).

  - ext4: add missing brelse() in
    set_flexbg_block_bitmap()'s error path (bnc#1012382).

  - ext4: add missing brelse() update_backups()'s error path
    (bnc#1012382).

  - ext4: avoid buffer leak in ext4_orphan_add() after prior
    errors (bnc#1012382).

  - ext4: avoid possible double brelse() in add_new_gdb() on
    error path (bnc#1012382).

  - ext4: avoid potential extra brelse in
    setup_new_flex_group_blocks() (bnc#1012382).

  - ext4: fix argument checking in EXT4_IOC_MOVE_EXT
    (bnc#1012382).

  - ext4: fix buffer leak in __ext4_read_dirblock() on error
    path (bnc#1012382).

  - ext4: fix buffer leak in ext4_xattr_move_to_block() on
    error path (bnc#1012382).

  - ext4: fix missing cleanup if ext4_alloc_flex_bg_array()
    fails while resizing (bnc#1012382).

  - ext4: fix possible inode leak in the retry loop of
    ext4_resize_fs() (bnc#1012382).

  - ext4: fix possible leak of sbi->s_group_desc_leak in
    error path (bnc#1012382).

  - ext4: initialize retries variable in
    ext4_da_write_inline_data_begin() (bnc#1012382).

  - ext4: release bs.bh before re-using in
    ext4_xattr_block_find() (bnc#1012382).

  - fcoe: remove duplicate debugging message in
    fcoe_ctlr_vn_add (bsc#1114763).

  - flow_dissector: do not dissect l4 ports for fragments
    (bnc#1012382).

  - fs, elf: make sure to page align bss in load_elf_library
    (bnc#1012382).

  - fs/exofs: fix potential memory leak in mount option
    parsing (bnc#1012382).

  - fs/fat/fatent.c: add cond_resched() to
    fat_count_free_clusters() (bnc#1012382).

  - fscache: fix race between enablement and dropping of
    object (bsc#1107385).

  - fuse: Dont call set_page_dirty_lock() for ITER_BVEC
    pages for async_dio (bnc#1012382).

  - fuse: Fix use-after-free in fuse_dev_do_read()
    (bnc#1012382).

  - fuse: Fix use-after-free in fuse_dev_do_write()
    (bnc#1012382).

  - fuse: fix blocked_waitq wakeup (bnc#1012382).

  - fuse: fix leaked notify reply (bnc#1012382).

  - fuse: set FR_SENT while locked (bnc#1012382).

  - genirq: Fix race on spurious interrupt detection
    (bnc#1012382).

  - gfs2: Put bitmap buffers in put_super (bnc#1012382).

  - gfs2_meta: ->mount() can get NULL dev_name
    (bnc#1012382).

  - gpio: msic: fix error return code in
    platform_msic_gpio_probe() (bnc#1012382).

  - gpu: host1x: fix error return code in host1x_probe()
    (bnc#1012382).

  - hfs: prevent btree data loss on root split
    (bnc#1012382).

  - hfsplus: prevent btree data loss on root split
    (bnc#1012382).

  - hugetlbfs: dirty pages as they are added to pagecache
    (bnc#1012382).

  - hugetlbfs: fix kernel BUG at fs/hugetlbfs/inode.c:444!
    (bnc#1012382).

  - hwmon: (ibmpowernv) Remove bogus __init annotations
    (bnc#1012382).

  - hwmon: (pmbus) Fix page count auto-detection
    (bnc#1012382).

  - ibmvnic: Fix RX queue buffer cleanup (bsc#1115440,
    bsc#1115433).

  - ibmvnic: fix accelerated VLAN handling ().

  - ibmvnic: fix index in release_rx_pools (bsc#1115440).

  - ibmvnic: remove ndo_poll_controller ().

  - igb: Remove superfluous reset to PHY and page 0
    selection (bnc#1012382).

  - iio: adc: at91: fix acking DRDY irq on simple
    conversions (bnc#1012382).

  - iio: adc: at91: fix wrong channel number in triggered
    buffer mode (bnc#1012382).

  - ima: fix showing large 'violations' or
    'runtime_measurements_count' (bnc#1012382).

  - iommu/arm-smmu: Ensure that page-table updates are
    visible before TLBI (bsc#1106237).

  - iommu/ipmmu-vmsa: Fix crash on early domain free
    (bsc#1106105).

  - iommu/vt-d: Fix NULL pointer dereference in
    prq_event_thread() (bsc#1106105).

  - iommu/vt-d: Use memunmap to free memremap (bsc#1106105).

  - ip_tunnel: do not force DF when MTU is locked
    (bnc#1012382).

  - ipmi: Fix timer race with module unload (bnc#1012382).

  - ipv6/ndisc: Preserve IPv6 control buffer if protocol
    error handlers are called (bnc#1012382).

  - ipv6: Fix PMTU updates for UDP/raw sockets in presence
    of VRF (bnc#1012382).

  - ipv6: mcast: fix a use-after-free in inet6_mc_check
    (bnc#1012382).

  - ipv6: orphan skbs in reassembly unit (bnc#1012382).

  - ipv6: set rt6i_protocol properly in the route when it is
    installed (bsc#1114190).

  - ipv6: suppress sparse warnings in IP6_ECN_set_ce()
    (bnc#1012382).

  - jbd2: fix use after free in jbd2_log_do_checkpoint()
    (bnc#1012382).

  - jffs2: free jffs2_sb_info through jffs2_kill_sb()
    (bnc#1012382).

  - kABI: protect struct azx (kabi).

  - kABI: protect struct cfs_bandwidth (kabi).

  - kABI: protect struct esp (kabi).

  - kABI: protect struct fuse_io_priv (kabi).

  - kabi: revert sig change on pnfs_read_resend_pnfs
    (git-fixes).

  - kbuild, LLVMLinux: Add -Werror to cc-option to support
    clang (bnc#1012382).

  - kbuild: Add __cc-option macro (bnc#1012382).

  - kbuild: Add better clang cross build support
    (bnc#1012382).

  - kbuild: Add support to generate LLVM assembly files
    (bnc#1012382).

  - kbuild: Consolidate header generation from ASM offset
    information (bnc#1012382).

  - kbuild: Set KBUILD_CFLAGS before incl. arch Makefile
    (bnc#1012382).

  - kbuild: allow to use GCC toolchain not in Clang search
    path (bnc#1012382).

  - kbuild: clang: Disable 'address-of-packed-member'
    warning (bnc#1012382).

  - kbuild: clang: add -no-integrated-as to KBUILD_[AC]FLAGS
    (bnc#1012382).

  - kbuild: clang: disable unused variable warnings only
    when constant (bnc#1012382).

  - kbuild: clang: fix build failures with sparse check
    (bnc#1012382).

  - kbuild: clang: remove crufty HOSTCFLAGS (bnc#1012382).

  - kbuild: consolidate redundant sed script ASM offset
    generation (bnc#1012382).

  - kbuild: drop -Wno-unknown-warning-option from clang
    options (bnc#1012382).

  - kbuild: fix asm-offset generation to work with clang
    (bnc#1012382).

  - kbuild: fix kernel/bounds.c 'W=1' warning (bnc#1012382).

  - kbuild: fix linker feature test macros when cross
    compiling with Clang (bnc#1012382).

  - kbuild: move cc-option and cc-disable-warning after
    incl. arch Makefile (bnc#1012382).

  - kbuild: set no-integrated-as before incl. arch Makefile
    (bnc#1012382).

  - kbuild: use -Oz instead of -Os when using clang
    (bnc#1012382).

  - kernel-source.spec: Align source numbering.

  - kgdboc: Passing ekgdboc to command line causes panic
    (bnc#1012382).

  - kprobes: Return error if we fail to reuse kprobe instead
    of BUG_ON() (bnc#1012382).

  - lan78xx: Check for supported Wake-on-LAN modes
    (bnc#1012382).

  - lib/raid6: Fix arm64 test build (bnc#1012382).

  - libceph: bump CEPH_MSG_MAX_DATA_LEN (bsc#1114839).

  - libfc: sync strings with upstream versions
    (bsc#1114763).

  - libnvdimm: Hold reference on parent while scheduling
    async init (bnc#1012382).

  - lockd: fix access beyond unterminated strings in prints
    (bnc#1012382).

  - locking/lockdep: Fix debug_locks off performance problem
    (bnc#1012382).

  - mac80211: Always report TX status (bnc#1012382).

  - mac80211_hwsim: do not omit multicast announce of first
    added radio (bnc#1012382).

  - mach64: fix display corruption on big endian machines
    (bnc#1012382).

  - mach64: fix image corruption due to reading accelerator
    registers (bnc#1012382).

  - media: em28xx: fix input name for Terratec AV 350
    (bnc#1012382).

  - media: em28xx: make v4l2-compliance happier by starting
    sequence on zero (bnc#1012382).

  - media: em28xx: use a default format if TRY_FMT fails
    (bnc#1012382).

  - media: pci: cx23885: handle adding to list failure
    (bnc#1012382).

  - media: tvp5150: fix width alignment during
    set_selection() (bnc#1012382).

  - media: v4l: event: Add subscription to list before
    calling 'add' operation (bnc#1012382).

  - misc: atmel-ssc: Fix section annotation on
    atmel_ssc_get_driver_data (bnc#1012382).

  - mm, elf: handle vm_brk error (bnc#1012382).

  - mm: do not bug_on on incorrect length in __mm_populate()
    (bnc#1012382).

  - mm: migration: fix migration of huge PMD shared pages
    (bnc#1012382).

  - mm: refuse wrapped vm_brk requests (bnc#1012382).

  - mm: thp: relax __GFP_THISNODE for MADV_HUGEPAGE mappings
    (bnc#1012382).

  - mmc: sdhci-pci-o2micro: Add quirk for O2 Micro dev
    0x8620 rev 0x01 (bnc#1012382).

  - modules: mark __inittest/__exittest as __maybe_unused
    (bnc#1012382).

  - mount: Do not allow copying MNT_UNBINDABLE|MNT_LOCKED
    mounts (bnc#1012382).

  - mount: Prevent MNT_DETACH from disconnecting locked
    mounts (bnc#1012382).

  - mount: Retest MNT_LOCKED in do_umount (bnc#1012382).

  - mtd: docg3: do not set conflicting BCH_CONST_PARAMS
    option (bnc#1012382).

  - mtd: spi-nor: Add support for is25wp series chips
    (bnc#1012382).

  - net-gro: reset skb->pkt_type in napi_reuse_skb()
    (bnc#1012382).

  - net/af_iucv: drop inbound packets with invalid flags
    (bnc#1114475, LTC#172679).

  - net/af_iucv: fix skb handling on HiperTransport xmit
    error (bnc#1114475, LTC#172679).

  - net/ibmnvic: Fix deadlock problem in reset ().

  - net/ipv4: defensive cipso option parsing (bnc#1012382).

  - net/ipv6: Fix index counter for unicast addresses in
    in6_dump_addrs (bnc#1012382).

  - net: bridge: remove ipv6 zero address check in mcast
    queries (bnc#1012382).

  - net: cxgb3_main: fix a missing-check bug (bnc#1012382).

  - net: drop skb on failure in ip_check_defrag()
    (bnc#1012382).

  - net: drop write-only stack variable (bnc#1012382).

  - net: ena: Fix Kconfig dependency on X86 (bsc#1117562).

  - net: ena: add functions for handling Low Latency Queues
    in ena_com (bsc#1117562).

  - net: ena: add functions for handling Low Latency Queues
    in ena_netdev (bsc#1117562).

  - net: ena: change rx copybreak default to reduce kernel
    memory pressure (bsc#1117562).

  - net: ena: complete host info to match latest ENA spec
    (bsc#1117562).

  - net: ena: enable Low Latency Queues (bsc#1117562).

  - net: ena: explicit casting and initialization, and
    clearer error handling (bsc#1117562).

  - net: ena: fix NULL dereference due to untimely napi
    initialization (bsc#1117562).

  - net: ena: fix auto casting to boolean (bsc#1117562).

  - net: ena: fix compilation error in xtensa architecture
    (bsc#1117562).

  - net: ena: fix crash during failed resume from
    hibernation (bsc#1117562).

  - net: ena: fix indentations in ena_defs for better
    readability (bsc#1117562).

  - net: ena: fix rare bug when failed restart/resume is
    followed by driver removal (bsc#1117562).

  - net: ena: fix warning in rmmod caused by double iounmap
    (bsc#1117562).

  - net: ena: introduce Low Latency Queues data structures
    according to ENA spec (bsc#1117562).

  - net: ena: limit refill Rx threshold to 256 to avoid
    latency issues (bsc#1117562).

  - net: ena: minor performance improvement (bsc#1117562).

  - net: ena: remove ndo_poll_controller (bsc#1117562).

  - net: ena: remove redundant parameter in
    ena_com_admin_init() (bsc#1117562).

  - net: ena: update driver version to 2.0.1 (bsc#1117562).

  - net: ena: use CSUM_CHECKED device indication to report
    skb's checksum status (bsc#1117562).

  - net: ibm: fix return type of ndo_start_xmit function ().

  - net: qla3xxx: Remove overflowing shift statement
    (bnc#1012382).

  - net: sched: gred: pass the right attribute to
    gred_change_table_def() (bnc#1012382).

  - net: socket: fix a missing-check bug (bnc#1012382).

  - net: stmmac: Fix stmmac_mdio_reset() when building
    stmmac as modules (bnc#1012382).

  - netfilter: ipset: Correct rcu_dereference() call in
    ip_set_put_comment() (bnc#1012382).

  - netfilter: ipset: actually allow allowable CIDR 0 in
    hash:net,port,net (bnc#1012382).

  - netfilter: xt_IDLETIMER: add sysfs filename checking
    routine (bnc#1012382).

  - new helper: uaccess_kernel() (bnc#1012382).

  - nfsd: Fix an Oops in free_session() (bnc#1012382).

  - ocfs2: fix a misuse a of brelse after failing
    ocfs2_check_dir_entry (bnc#1012382).

  - pNFS/flexfiles: Fix up the ff_layout_write_pagelist
    failure path (git-fixes).

  - pNFS/flexfiles: When checking for available DSes,
    conditionally check for MDS io (git-fixes).

  - pNFS: Fix a deadlock between read resends and
    layoutreturn (git-fixes).

  - parisc: Fix address in HPMC IVA (bnc#1012382).

  - parisc: Fix map_pages() to not overwrite existing pte
    entries (bnc#1012382).

  - pcmcia: Implement CLKRUN protocol disabling for Ricoh
    bridges (bnc#1012382).

  - perf tools: Cleanup trace-event-info 'tdata' leak
    (bnc#1012382).

  - perf tools: Disable parallelism for 'make clean'
    (bnc#1012382).

  - perf tools: Free temporary 'sys' string in
    read_event_files() (bnc#1012382).

  - perf/core: Do not leak event in the syscall error path
    (bnc#1012382).

  - perf/ring_buffer: Prevent concurent ring buffer access
    (bnc#1012382).

  - pinctrl: qcom: spmi-mpp: Fix drive strength setting
    (bnc#1012382).

  - pinctrl: qcom: spmi-mpp: Fix err handling of
    pmic_mpp_set_mux (bnc#1012382).

  - pinctrl: spmi-mpp: Fix pmic_mpp_config_get() to be
    compliant (bnc#1012382).

  - pinctrl: ssbi-gpio: Fix pm8xxx_pin_config_get() to be
    compliant (bnc#1012382).

  - platform/x86: acerhdf: Add BIOS entry for Gateway LT31
    v1.3307 (bnc#1012382).

  - pnfs: set NFS_IOHDR_REDO in pnfs_read_resend_pnfs
    (git-fixes).

  - powerpc/boot: Ensure _zimage_start is a weak symbol
    (bnc#1012382).

  - powerpc/msi: Fix compile error on mpc83xx (bnc#1012382).

  - powerpc/nohash: fix undefined behaviour when testing
    page size support (bnc#1012382).

  - powerpc/powernv/pci: Work around races in PCI bridge
    enabling (bsc#1066223).

  - powerpc/powernv: Do not select the cpufreq governors
    (bsc#1066223).

  - powerpc/powernv: Fix opal_event_shutdown() called with
    interrupts disabled (bsc#1066223).

  - powerpc/pseries/mobility: Extend start/stop topology
    update scope (bsc#1116950, bsc#1115709).

  - powerpc/pseries: Fix DTL buffer registration
    (bsc#1066223).

  - powerpc/pseries: Fix how we iterate over the DTL entries
    (bsc#1066223).

  - printk: Fix panic caused by passing log_buf_len to
    command line (bnc#1012382).

  - ptp: fix Spectre v1 vulnerability (bnc#1012382).

  - pxa168fb: prepare the clock (bnc#1012382).

  - r8152: Check for supported Wake-on-LAN Modes
    (bnc#1012382).

  - r8169: fix NAPI handling under high load (bnc#1012382).

  - reiserfs: propagate errors from fill_with_dentries()
    properly (bnc#1012382).

  - rpcrdma: Add RPCRDMA_HDRLEN_ERR (git-fixes).

  - rps: flow_dissector: Fix uninitialized flow_keys used in
    __skb_get_hash possibly (bsc#1042286 bsc#1108145).

  - rtc: hctosys: Add missing range error reporting
    (bnc#1012382).

  - rtnetlink: Disallow FDB configuration for non-Ethernet
    device (bnc#1012382).

  - s390/mm: Fix ERROR: '__node_distance' undefined!
    (bnc#1012382).

  - s390/qeth: fix HiperSockets sniffer (bnc#1114475,
    LTC#172953).

  - s390/vdso: add missing FORCE to build targets
    (bnc#1012382).

  - s390: qeth: Fix potential array overrun in cmd/rc lookup
    (bnc#1114475, LTC#172682).

  - s390: qeth_core_mpc: Use ARRAY_SIZE instead of
    reimplementing its function (bnc#1114475, LTC#172682).

  - sc16is7xx: Fix for multi-channel stall (bnc#1012382).

  - sch_red: update backlog as well (bnc#1012382).

  - sched/cgroup: Fix cgroup entity load tracking tear-down
    (bnc#1012382).

  - sched/fair: Fix throttle_list starvation with low CFS
    quota (bnc#1012382).

  - scsi: aacraid: Fix typo in blink status (bnc#1012382).

  - scsi: core: Allow state transitions from OFFLINE to
    BLOCKED (bsc#1112246).

  - scsi: esp_scsi: Track residual for PIO transfers
    (bnc#1012382).

  - scsi: libfc: check fc_frame_payload_get() return value
    for null (bsc#1103624, bsc#1104731).

  - scsi: libfc: retry PRLI if we cannot analyse the payload
    (bsc#1104731).

  - scsi: lpfc: Correct soft lockup when running mds
    diagnostics (bnc#1012382).

  - scsi: megaraid_sas: fix a missing-check bug
    (bnc#1012382).

  - scsi: qla2xxx: Fix crashes in qla2x00_probe_one on probe
    failure (bsc#1094973).

  - scsi: qla2xxx: Fix incorrect port speed being set for FC
    adapters (bnc#1012382).

  - scsi: qla2xxx: Fix small memory leak in
    qla2x00_probe_one on probe failure (bsc#1094973).

  - sctp: fix race on sctp_id2asoc (bnc#1012382).

  - selftests: ftrace: Add synthetic event syntax testcase
    (bnc#1012382).

  - ser_gigaset: use container_of() instead of detour
    (bnc#1012382).

  - signal/GenWQE: Fix sending of SIGKILL (bnc#1012382).

  - signal: Always deliver the kernel's SIGKILL and SIGSTOP
    to a pid namespace init (bnc#1012382).

  - smb3: allow stats which track session and share
    reconnects to be reset (bnc#1012382).

  - smb3: do not attempt cifs operation in smb3 query info
    error path (bnc#1012382).

  - smb3: on kerberos mount if server does not specify auth
    type use krb5 (bnc#1012382).

  - smsc75xx: Check for Wake-on-LAN modes (bnc#1012382).

  - smsc95xx: Check for Wake-on-LAN modes (bnc#1012382).

  - soc/tegra: pmc: Fix child-node lookup (bnc#1012382).

  - sparc/pci: Refactor dev_archdata initialization into
    pci_init_dev_archdata (bnc#1012382).

  - sparc64 mm: Fix more TSB sizing issues (bnc#1012382).

  - sparc64: Fix exception handling in UltraSPARC-III memcpy
    (bnc#1012382).

  - sparc: Fix single-pcr perf event counter management
    (bnc#1012382).

  - spi/bcm63xx-hspi: fix error return code in
    bcm63xx_hsspi_probe() (bnc#1012382).

  - spi/bcm63xx: fix error return code in
    bcm63xx_spi_probe() (bnc#1012382).

  - spi: xlp: fix error return code in xlp_spi_probe()
    (bnc#1012382).

  - sr9800: Check for supported Wake-on-LAN modes
    (bnc#1012382).

  - sunrpc: correct the computation for page_ptr when
    truncating (bnc#1012382).

  - svcrdma: Remove unused variable in rdma_copy_tail()
    (git-fixes).

  - swim: fix cleanup on setup error (bnc#1012382).

  - termios, tty/tty_baudrate.c: fix buffer overrun
    (bnc#1012382).

  - tg3: Add PHY reset for 5717/5719/5720 in change ring and
    flow control paths (bnc#1012382).

  - thermal: allow spear-thermal driver to be a module
    (bnc#1012382).

  - thermal: allow u8500-thermal driver to be a module
    (bnc#1012382).

  - tpm: suppress transmit cmd error logs when TPM 1.2 is
    disabled/deactivated (bnc#1012382).

  - tracing: Skip more functions when doing stack tracing of
    events (bnc#1012382).

  - tty: check name length in tty_find_polling_driver()
    (bnc#1012382).

  - tty: serial: sprd: fix error return code in sprd_probe()
    (bnc#1012382).

  - tun: Consistently configure generic netdev params via
    rtnetlink (bnc#1012382).

  - uio: Fix an Oops on load (bnc#1012382).

  - uio: ensure class is registered before devices
    (bnc#1012382).

  - uio: make symbol 'uio_class_registered' static
    (git-fixes).

  - um: Avoid longjmp/setjmp symbol clashes with
    libpthread.a (bnc#1012382).

  - um: Give start_idle_thread() a return code
    (bnc#1012382).

  - usb-storage: fix bogus hardware error messages for ATA
    pass-thru devices (bnc#1012382).

  - usb: cdc-acm: add entry for Hiro (Conexant) modem
    (bnc#1012382).

  - usb: chipidea: Prevent unbalanced IRQ disable
    (bnc#1012382).

  - usb: dwc3: omap: fix error return code in
    dwc3_omap_probe() (bnc#1012382).

  - usb: ehci-omap: fix error return code in
    ehci_hcd_omap_probe() (bnc#1012382).

  - usb: gadget: storage: Fix Spectre v1 vulnerability
    (bnc#1012382).

  - usb: imx21-hcd: fix error return code in imx21_probe()
    (bnc#1012382).

  - usb: quirks: Add delay-init quirk for Corsair K70 LUX
    RGB (bnc#1012382).

  - vhost/scsi: truncate T10 PI iov_iter to prot_bytes
    (bnc#1012382).

  - vhost: Fix Spectre V1 vulnerability (bnc#1012382).

  - video: fbdev: pxa3xx_gcu: fix error return code in
    pxa3xx_gcu_probe() (bnc#1012382).

  - vti6: flush x-netns xfrm cache when vti interface is
    removed (bnc#1012382).

  - w1: omap-hdq: fix missing bus unregister at removal
    (bnc#1012382).

  - x86/boot: #undef memcpy() et al in string.c
    (bnc#1012382).

  - x86/build: Fix stack alignment for CLang (bnc#1012382).

  - x86/build: Specify stack alignment for clang
    (bnc#1012382).

  - x86/build: Use __cc-option for boot code compiler
    options (bnc#1012382).

  - x86/build: Use cc-option to validate stack alignment
    parameter (bnc#1012382).

  - x86/corruption-check: Fix panic in
    memory_corruption_check() when boot option without value
    is provided (bnc#1012382).

  - x86/kbuild: Use cc-option to enable
    -falign-(jumps/loops) (bnc#1012382).

  - x86/kconfig: Fall back to ticket spinlocks
    (bnc#1012382).

  - x86/mm/kaslr: Use the _ASM_MUL macro for multiplication
    to work around Clang incompatibility (bnc#1012382).

  - x86/mm/pat: Prevent hang during boot when mapping pages
    (bnc#1012382).

  - x86: boot: Fix EFI stub alignment (bnc#1012382).

  - xen-swiotlb: use actually allocated size on check
    physical continuous (bnc#1012382).

  - xen/blkfront: avoid NULL blkfront_info dereference on
    device removal (bsc#1111062).

  - xen: fix race in xen_qlock_wait() (bnc#1012382).

  - xen: fix xen_qlock_wait() (bnc#1012382).

  - xen: make xen_qlock_wait() nestable (bnc#1012382).

  - xfrm6: call kfree_skb when skb is toobig (bnc#1012382).

  - xfrm: Clear sk_dst_cache when applying per-socket policy
    (bnc#1012382).

  - xfrm: Validate address prefix lengths in the xfrm
    selector (bnc#1012382).

  - xfrm: use complete IPv6 addresses for hash
    (bsc#1109330).

  - xfrm: validate template mode (bnc#1012382).

  - xfs/dmapi: restore event in xfs_getbmap (bsc#1114763).

  - xfs: Fix error code in 'xfs_ioc_getbmap()' (git-fixes).

  - xprtrdma: Disable RPC/RDMA backchannel debugging
    messages (git-fixes).

  - xprtrdma: Disable pad optimization by default
    (git-fixes).

  - xprtrdma: Fix Read chunk padding (git-fixes).

  - xprtrdma: Fix additional uses of
    spin_lock_irqsave(rb_lock) (git-fixes).

  - xprtrdma: Fix backchannel allocation of extra
    rpcrdma_reps (git-fixes).

  - xprtrdma: Fix receive buffer accounting (git-fixes).

  - xprtrdma: Serialize credit accounting again (git-fixes).

  - xprtrdma: checking for NULL instead of IS_ERR()
    (git-fixes).

  - xprtrdma: rpcrdma_bc_receive_call() should init
    rq_private_buf.len (git-fixes).

  - xprtrdma: xprt_rdma_free() must not release backchannel
    reqs (git-fixes).

  - xtensa: add NOTES section to the linker script
    (bnc#1012382).

  - xtensa: fix boot parameters address translation
    (bnc#1012382).

  - xtensa: make sure bFLT stack is 16 byte aligned
    (bnc#1012382).

  - zram: close udev startup race condition as default
    groups (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985031"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.165-81.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.165-81.1") ) flag++;

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
