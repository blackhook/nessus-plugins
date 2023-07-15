#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1016.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117523);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-10940", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-9363");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-1016)");
  script_summary(english:"Check for the openSUSE-2018-1016 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.155 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-13093: Prevent NULL pointer dereference and
    panic in lookup_slow() on a NULL inode->i_ops pointer
    when doing pathwalks on a corrupted xfs image. This
    occured because of a lack of proper validation that
    cached inodes are free during allocation (bnc#1100001).

  - CVE-2018-13095: Prevent denial of service (memory
    corruption and BUG) that could have occured for a
    corrupted xfs image upon encountering an inode that is
    in extent format, but has more extents than fit in the
    inode fork (bnc#1099999).

  - CVE-2018-13094: Prevent OOPS that might have occured for
    a corrupted xfs image after xfs_da_shrink_inode() is
    called with a NULL bp (bnc#1100000).

  - CVE-2018-12896: Prevent integer overflow in the POSIX
    timer code is caused by the way the overrun accounting
    works. Depending on interval and expiry time values, the
    overrun could have been larger than INT_MAX, but the
    accounting is int based. This basically made the
    accounting values, which are visible to user space via
    timer_getoverrun(2) and siginfo::si_overrun, random. For
    example, a local user could have caused a denial of
    service (signed integer overflow) via crafted mmap,
    futex, timer_create, and timer_settime system calls
    (bnc#1099922).

  - CVE-2018-16658: Prevent information leak in
    cdrom_ioctl_drive_status that could have been used by
    local attackers to read kernel memory because a cast
    from unsigned long to int interferes with bounds
    checking (bnc#1107689).

  - CVE-2018-10940: The cdrom_ioctl_media_changed function
    allowed local attackers to use a incorrect bounds check
    in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read
    out kernel memory (bsc#1092903).

  - CVE-2018-6555: The irda_setsockopt function allowed
    local users to cause a denial of service (ias_object
    use-after-free and system crash) or possibly have
    unspecified other impact via an AF_IRDA socket
    (bnc#1106511).

  - CVE-2018-6554: Prevent memory leak in the irda_bind
    function that allowed local users to cause a denial of
    service (memory consumption) by repeatedly binding an
    AF_IRDA socket (bnc#1106509).

  - CVE-2018-1129: A flaw was found in the way signature
    calculation was handled by cephx authentication
    protocol. An attacker having access to ceph cluster
    network who is able to alter the message payload was
    able to bypass signature checks done by cephx protocol
    (bnc#1096748).

  - CVE-2018-1128: It was found that cephx authentication
    protocol did not verify ceph clients correctly and was
    vulnerable to replay attack. Any attacker having access
    to ceph cluster network who is able to sniff packets on
    network can use this vulnerability to authenticate with
    ceph service and perform actions allowed by ceph service
    (bnc#1096748).

  - CVE-2018-10938: A crafted network packet sent remotely
    by an attacker could have forced the kernel to enter an
    infinite loop in the cipso_v4_optptr() function leading
    to a denial-of-service (bnc#1106016).

  - CVE-2018-15572: The spectre_v2_select_mitigation
    function did not always fill RSB upon a context switch,
    which made it easier for attackers to conduct
    userspace-userspace spectreRSB attacks (bnc#1102517).

  - CVE-2018-10902: The raw midi kernel driver did not
    protect against concurrent access which lead to a double
    realloc (double free) in snd_rawmidi_input_params() and
    snd_rawmidi_output_status(), allowing a malicious local
    attacker to use this for privilege escalation
    (bnc#1105322).

  - CVE-2018-9363: Prevent buffer overflow in
    hidp_process_report (bsc#1105292).

The following non-security bugs were fixed :

  - 9p/net: Fix zero-copy path in the 9p virtio transport
    (bnc#1012382).

  - 9p/virtio: fix off-by-one error in sg list bounds check
    (bnc#1012382).

  - 9p: fix multiple NULL-pointer-dereferences
    (bnc#1012382).

  - ACPI / LPSS: Add missing prv_offset setting for byt/cht
    PWM devices (bnc#1012382).

  - ACPI / PCI: Bail early in acpi_pci_add_bus() if there is
    no ACPI handle (bnc#1012382).

  - ACPI / PM: save NVS memory for ASUS 1025C laptop
    (bnc#1012382).

  - ACPI: save NVS memory for Lenovo G50-45 (bnc#1012382).

  - ALSA: cs5535audio: Fix invalid endian conversion
    (bnc#1012382).

  - ALSA: emu10k1: Rate-limit error messages about page
    errors (bnc#1012382).

  - ALSA: emu10k1: add error handling for snd_ctl_add
    (bnc#1012382).

  - ALSA: fm801: add error handling for snd_ctl_add
    (bnc#1012382).

  - ALSA: hda - Sleep for 10ms after entering D3 on Conexant
    codecs (bnc#1012382).

  - ALSA: hda - Turn CX8200 into D3 as well upon reboot
    (bnc#1012382).

  - ALSA: hda/ca0132: fix build failure when a local macro
    is defined (bnc#1012382).

  - ALSA: hda: Correct Asrock B85M-ITX power_save blacklist
    entry (bnc#1012382).

  - ALSA: memalloc: Do not exceed over the requested size
    (bnc#1012382).

  - ALSA: rawmidi: Change resized buffers atomically
    (bnc#1012382).

  - ALSA: snd-aoa: add of_node_put() in error path
    (bsc#1099810).

  - ALSA: usb-audio: Apply rate limit to warning messages in
    URB complete callback (bnc#1012382).

  - ALSA: virmidi: Fix too long output trigger loop
    (bnc#1012382).

  - ALSA: vx222: Fix invalid endian conversions
    (bnc#1012382).

  - ALSA: vxpocket: Fix invalid endian conversions
    (bnc#1012382).

  - ARC: Enable machine_desc->init_per_cpu for !CONFIG_SMP
    (bnc#1012382).

  - ARC: Explicitly add -mmedium-calls to CFLAGS
    (bnc#1012382).

  - ARC: Fix CONFIG_SWAP (bnc#1012382).

  - ARC: mm: allow mprotect to make stack mappings
    executable (bnc#1012382).

  - ARM: 8780/1: ftrace: Only set kernel memory back to
    read-only after boot (bnc#1012382).

  - ARM: dts: Cygnus: Fix I2C controller interrupt type
    (bnc#1012382).

  - ARM: dts: am3517.dtsi: Disable reference to OMAP3 OTG
    controller (bnc#1012382).

  - ARM: dts: am437x: make edt-ft5x06 a wakeup source
    (bnc#1012382).

  - ARM: dts: da850: Fix interrups property for gpio
    (bnc#1012382).

  - ARM: dts: imx6sx: fix irq for pcie bridge (bnc#1012382).

  - ARM: fix put_user() for gcc-8 (bnc#1012382).

  - ARM: imx_v4_v5_defconfig: Select ULPI support
    (bnc#1012382).

  - ARM: imx_v6_v7_defconfig: Select ULPI support
    (bnc#1012382).

  - ARM: pxa: irq: fix handling of ICMR registers in
    suspend/resume (bnc#1012382).

  - ARM: tegra: Fix Tegra30 Cardhu PCA954x reset
    (bnc#1012382).

  - ASoC: Intel: cht_bsw_max98090: remove useless code,
    align with ChromeOS driver (git-fixes).

  - ASoC: Intel: cht_bsw_max98090_ti: Fix jack
    initialization (bnc#1012382).

  - ASoC: dpcm: do not merge format from invalid codec dai
    (bnc#1012382).

  - ASoC: dpcm: fix BE dai not hw_free and shutdown
    (bnc#1012382).

  - ASoC: pxa: Fix module autoload for platform drivers
    (bnc#1012382).

  - ASoC: sirf: Fix potential NULL pointer dereference
    (bnc#1012382).

  - Add reference to bsc#1091171 (bnc#1012382; bsc#1091171).

  - Bluetooth: avoid killing an already killed socket
    (bnc#1012382).

  - Bluetooth: btusb: Add a new Realtek 8723DE ID 2ff8:b011
    (bnc#1012382).

  - Bluetooth: btusb: Remove Yoga 920 from the
    btusb_needs_reset_resume_table (bsc#1087092).

  - Bluetooth: btusb: Use DMI matching for QCA reset_resume
    quirking (bsc#1087092).

  - Bluetooth: hci_qca: Fix 'Sleep inside atomic section'
    warning (bnc#1012382).

  - Documentation/spec_ctrl: Do some minor cleanups
    (bnc#1012382).

  - HID: hid-plantronics: Re-resend Update to map button for
    PTT products (bnc#1012382).

  - HID: i2c-hid: check if device is there before really
    probing (bnc#1012382).

  - HID: wacom: Correct touch maximum XY of 2nd-gen Intuos
    (bnc#1012382).

  - IB/core: Make testing MR flags for writability a static
    inline function (bnc#1012382).

  - IB/core: Remove duplicate declaration of gid_cache_wq
    (bsc#1056596).

  - IB/iser: Do not reduce max_sectors (bsc#1063646).

  - IB/mlx4: Fix an error handling path in
    'mlx4_ib_rereg_user_mr()' (git-fixes).

  - IB/mlx4: Mark user MR as writable if actual virtual
    memory is writable (bnc#1012382).

  - IB/mlx5: Fetch soft WQE's on fatal error state
    (bsc#1015342 bsc#1015343).

  - IB/mlx5: Use 'kvfree()' for memory allocated by
    'kvzalloc()' (bsc#1015342 bsc#1015343).

  - IB/ocrdma: fix out of bounds access to local buffer
    (bnc#1012382).

  - Input: elan_i2c - add ACPI ID for lenovo ideapad 330
    (bnc#1012382).

  - Input: elan_i2c - add another ACPI ID for Lenovo Ideapad
    330-15AST (bnc#1012382).

  - Input: i8042 - add Lenovo LaVie Z to the i8042 reset
    list (bnc#1012382).

  - KVM/Eventfd: Avoid crash when assign and deassign
    specific eventfd in parallel (bnc#1012382).

  - KVM: MMU: always terminate page walks at level 1
    (bsc#1062604).

  - KVM: MMU: simplify last_pte_bitmap (bsc#1062604).

  - KVM: VMX: Work around kABI breakage in 'enum
    vmx_l1d_flush_state' (bsc#1106369).

  - KVM: VMX: fixes for vmentry_l1d_flush module parameter
    (bsc#1106369).

  - KVM: arm/arm64: Skip updating PMD entry if no change
    (bnc#1012382).

  - KVM: arm/arm64: Skip updating PTE entry if no change
    (bnc#1012382).

  - KVM: irqfd: fix race between EPOLLHUP and
    irq_bypass_register_consumer (bnc#1012382).

  - KVM: nVMX: update last_nonleaf_level when initializing
    nested EPT (bsc#1062604).

  - MIPS: Correct the 64-bit DSP accumulator register size
    (bnc#1012382).

  - MIPS: Fix off-by-one in pci_resource_to_user()
    (bnc#1012382).

  - MIPS: ath79: fix register address in
    ath79_ddr_wb_flush() (bnc#1012382).

  - MIPS: lib: Provide MIPS64r6 __multi3() for GCC lower
    than 7 (bnc#1012382).

  - NET: stmmac: align DMA stuff to largest cache line
    length (bnc#1012382).

  - PCI: Prevent sysfs disable of device while driver is
    attached (bnc#1012382).

  - PCI: Skip MPS logic for Virtual Functions (VFs)
    (bnc#1012382).

  - PCI: hotplug: Do not leak pci_slot on registration
    failure (bnc#1012382).

  - PCI: pciehp: Fix use-after-free on unplug (bnc#1012382).

  - PCI: pciehp: Request control of native hotplug only if
    supported (bnc#1012382).

  - PM / sleep: wakeup: Fix build error caused by missing
    SRCU support (bnc#1012382).

  - RDMA/i40iw: Avoid panic when objects are being created
    and destroyed (bsc#969476 bsc#969477).

  - RDMA/i40iw: Avoid panic when reading back the IRQ
    affinity hint (bsc#969476 bsc#969477).

  - RDMA/i40iw: Avoid reference leaks when processing the
    AEQ (bsc#969476 bsc#969477).

  - RDMA/i40w: Hold read semaphore while looking after VMA
    (bsc#1024376).

  - RDMA/mad: Convert BUG_ONs to error flows (bnc#1012382).

  - RDMA/mlx5: Use proper spec flow label type (bsc#1015342
    bsc#1015343).

  - Revert 'MIPS: BCM47XX: Enable 74K Core ExternalSync for
    PCIe erratum' (bnc#1012382).

  - Revert 'UBIFS: Fix potential integer overflow in
    allocation' (bnc#1012382).

  - Revert 'f2fs: handle dirty segments inside
    refresh_sit_entry' (bsc#1106281).

  - Revert 'mm: page_alloc: skip over regions of invalid
    pfns where possible' (bnc#1107078).

  - Smack: Mark inode instant in smack_task_to_inode
    (bnc#1012382).

  - USB: musb: fix external abort on suspend (bsc#1085536).

  - USB: option: add support for DW5821e (bnc#1012382).

  - USB: serial: metro-usb: stop I/O after failed open
    (bsc#1085539).

  - USB: serial: sierra: fix potential deadlock at close
    (bnc#1012382).

  - Workaround kABI breakage by __must_check drop of
    strscpy() (bsc#1107319).

  - afs: Fix directory permissions check (bsc#1106283).

  - arc: fix build errors in arc/include/asm/delay.h
    (bnc#1012382).

  - arc: fix type warnings in arc/mm/cache.c (bnc#1012382).

  - arm64: make secondary_start_kernel() notrace
    (bnc#1012382).

  - arm64: mm: check for upper PAGE_SHIFT bits in
    pfn_valid() (bnc#1012382).

  - ath: Add regulatory mapping for APL13_WORLD
    (bnc#1012382).

  - ath: Add regulatory mapping for APL2_FCCA (bnc#1012382).

  - ath: Add regulatory mapping for Bahamas (bnc#1012382).

  - ath: Add regulatory mapping for Bermuda (bnc#1012382).

  - ath: Add regulatory mapping for ETSI8_WORLD
    (bnc#1012382).

  - ath: Add regulatory mapping for FCC3_ETSIC
    (bnc#1012382).

  - ath: Add regulatory mapping for Serbia (bnc#1012382).

  - ath: Add regulatory mapping for Tanzania (bnc#1012382).

  - ath: Add regulatory mapping for Uganda (bnc#1012382).

  - atl1c: reserve min skb headroom (bnc#1012382).

  - atm: Preserve value of skb->truesize when accounting to
    vcc (bsc#1089066).

  - audit: allow not equal op for audit by executable
    (bnc#1012382).

  - backlight: as3711_bl: Fix Device Tree node leaks
    (bsc#1106929).

  - backlight: lm3630a: Bump REG_MAX value to 0x50 instead
    of 0x1F (bsc#1106929).

  - bcache: avoid unncessary cache prefetch
    bch_btree_node_get() (bsc#1064232).

  - bcache: calculate the number of incremental GC nodes
    according to the total of btree nodes (bsc#1064232).

  - bcache: display rate debug parameters to 0 when
    writeback is not running (bsc#1064232).

  - bcache: do not check return value of
    debugfs_create_dir() (bsc#1064232).

  - bcache: finish incremental GC (bsc#1064232).

  - bcache: fix I/O significant decline while backend
    devices registering (bsc#1064232).

  - bcache: fix error setting writeback_rate through sysfs
    interface (bsc#1064232).

  - bcache: free heap cache_set->flush_btree in
    bch_journal_free (bsc#1064232).

  - bcache: make the pr_err statement used for ENOENT only
    in sysfs_attatch section (bsc#1064232).

  - bcache: release dc->writeback_lock properly in
    bch_writeback_thread() (bsc#1064232).

  - bcache: set max writeback rate when I/O request is idle
    (bsc#1064232).

  - bcache: simplify the calculation of the total amount of
    flash dirty data (bsc#1064232).

  - be2net: remove unused old custom busy-poll fields
    (bsc#1021121 ).

  - blkdev: __blkdev_direct_IO_simple: fix leak in error
    case (bsc#1083663).

  - block: bio_iov_iter_get_pages: fix size of last iovec
    (bsc#1083663).

  - block: bio_iov_iter_get_pages: pin more pages for
    multi-segment IOs (bsc#1083663).

  - block: do not use interruptible wait anywhere
    (bnc#1012382).

  - bnx2x: Fix invalid memory access in rss hash config path
    (bnc#1012382).

  - bnx2x: Fix receiving tx-timeout in error or recovery
    state (bnc#1012382).

  - bnxt_en: Always set output parameters in
    bnxt_get_max_rings() (bsc#963575).

  - bnxt_en: Fix for system hang if request_irq fails
    (bnc#1012382).

  - bnxt_en: Fix inconsistent BNXT_FLAG_AGG_RINGS logic
    (bsc#1020412 ).

  - bpf: fix references to free_bpf_prog_info() in comments
    (bnc#1012382).

  - brcmfmac: Add support for bcm43364 wireless chipset
    (bnc#1012382).

  - brcmfmac: stop watchdog before detach and free
    everything (bnc#1012382).

  - bridge: Propagate vlan add failure to user
    (bnc#1012382).

  - btrfs: add barriers to btrfs_sync_log before
    log_commit_wait wakeups (bnc#1012382).

  - btrfs: do not leak ret from do_chunk_alloc
    (bnc#1012382).

  - btrfs: qgroup: Finish rescan when hit the last leaf of
    extent tree (bnc#1012382).

  - btrfs: quota: Set rescan progress to (u64)-1 if we hit
    last leaf (git-fixes).

  - btrfs: round down size diff when shrinking/growing
    device (bsc#1097105).

  - can: ems_usb: Fix memory leak on ems_usb_disconnect()
    (bnc#1012382).

  - can: mpc5xxx_can: check of_iomap return before use
    (bnc#1012382).

  - can: xilinx_can: fix RX loop if RXNEMP is asserted
    without RXOK (bnc#1012382).

  - can: xilinx_can: fix RX overflow interrupt not being
    enabled (bnc#1012382).

  - can: xilinx_can: fix device dropping off bus on RX
    overrun (bnc#1012382).

  - can: xilinx_can: fix incorrect clear of non-processed
    interrupts (bnc#1012382).

  - can: xilinx_can: fix recovery from error states not
    being propagated (bnc#1012382).

  - can: xilinx_can: keep only 1-2 frames in TX FIFO to fix
    TX accounting (bnc#1012382).

  - cdrom: Fix info leak/OOB read in
    cdrom_ioctl_drive_status (bnc#1012382).

  - ceph: fix incorrect use of strncpy (bsc#1107319).

  - ceph: return errors from posix_acl_equiv_mode()
    correctly (bsc#1107320).

  - cifs: Fix stack out-of-bounds in
    smb(2,3)_create_lease_buf() (bsc#1012382).

  - cifs: add missing debug entries for kconfig options
    (bnc#1012382).

  - cifs: check kmalloc before use (bsc#1012382).

  - cifs: store the leaseKey in the fid on SMB2_open
    (bsc#1012382).

  - clk: tegra: Fix PLL_U post divider and initial rate on
    Tegra30 (bnc#1012382).

  - crypto: ablkcipher - fix crash flushing dcache in error
    path (bnc#1012382).

  - crypto: authenc - do not leak pointers to authenc keys
    (bnc#1012382).

  - crypto: authencesn - do not leak pointers to authenc
    keys (bnc#1012382).

  - crypto: blkcipher - fix crash flushing dcache in error
    path (bnc#1012382).

  - crypto: padlock-aes - Fix Nano workaround data
    corruption (bnc#1012382).

  - crypto: vmac - require a block cipher with 128-bit block
    size (bnc#1012382).

  - crypto: vmac - separate tfm and request context
    (bnc#1012382).

  - crypto: vmx - Fix sleep-in-atomic bugs (bsc#1048317).

  - cxgb4: when disabling dcb set txq dcb priority to 0
    (bnc#1012382).

  - cxl: Fix wrong comparison in cxl_adapter_context_get()
    (bsc#1055014.

  - dccp: fix undefined behavior with 'cwnd' shift in
    ccid2_cwnd_restart() (bnc#1012382).

  - disable loading f2fs module on PAGE_SIZE > 4KB
    (bnc#1012382).

  - dm cache metadata: save in-core policy_hint_size to
    on-disk superblock (bnc#1012382).

  - dma-iommu: Fix compilation when !CONFIG_IOMMU_DMA
    (bnc#1012382).

  - dmaengine: k3dma: Off by one in k3_of_dma_simple_xlate()
    (bnc#1012382).

  - dmaengine: pxa_dma: remove duplicate const qualifier
    (bnc#1012382).

  - driver core: Partially revert 'driver core: correct
    device's shutdown order' (bnc#1012382).

  - drivers: net: lmc: fix case value for target abort error
    (bnc#1012382).

  - drm/armada: fix colorkey mode property (bnc#1012382).

  - drm/atmel-hlcdc: check stride values in the first plane
    (bsc#1106929).

  - drm/atomic: Handling the case when setting old crtc for
    plane (bnc#1012382).

  - drm/bridge: adv7511: Reset registers on hotplug
    (bnc#1012382).

  - drm/cirrus: Use drm_framebuffer_put to avoid kernel oops
    in clean-up (bsc#1101822).

  - drm/drivers: add support for using the arch wc mapping
    API (git-fixes).

  - drm/exynos/dsi: mask frame-done interrupt (bsc#1106929).

  - drm/exynos: decon5433: Fix WINCONx reset value
    (bnc#1012382).

  - drm/exynos: decon5433: Fix per-plane global alpha for
    XRGB modes (bnc#1012382).

  - drm/exynos: gsc: Fix support for NV16/61, YUV420/YVU420
    and YUV422 modes (bnc#1012382).

  - drm/gma500: fix psb_intel_lvds_mode_valid()'s return
    type (bnc#1012382).

  - drm/i915/userptr: reject zero user_size (bsc#1090888).

  - drm/i915: Correctly handle limited range YCbCr data on
    VLV/CHV (bsc#1087092).

  - drm/imx: fix typo in ipu_plane_formats (bsc#1106929).

  - drm/imx: imx-ldb: check if channel is enabled before
    printing warning (bnc#1012382).

  - drm/imx: imx-ldb: disable LDB on driver bind
    (bnc#1012382).

  - drm/msm/hdmi: Use bitwise operators when building
    register values (bsc#1106929).

  - drm/nouveau/gem: off by one bugs in
    nouveau_gem_pushbuf_reloc_apply() (bnc#1012382).

  - drm/panel: type promotion bug in s6e8aa0_read_mtp_id()
    (bsc#1105769).

  - drm/radeon: fix mode_valid's return type (bnc#1012382).

  - drm: Add DP PSR2 sink enable bit (bnc#1012382).

  - drm: Reject getfb for multi-plane framebuffers
    (bsc#1106929).

  - enic: do not call enic_change_mtu in enic_probe
    (git-fixes).

  - enic: handle mtu change for vf properly (bnc#1012382).

  - enic: initialize enic->rfs_h.lock in enic_probe
    (bnc#1012382).

  - ext4: check for NUL characters in extended attribute's
    name (bnc#1012382).

  - ext4: fix spectre gadget in ext4_mb_regular_allocator()
    (bnc#1012382).

  - ext4: reset error code in ext4_find_entry in fallback
    (bnc#1012382).

  - ext4: sysfs: print ext4_super_block fields as
    little-endian (bsc#1106229).

  - f2fs: fix to do not trigger writeback during recovery
    (bnc#1012382).

  - fat: fix memory allocation failure handling of
    match_strdup() (bnc#1012382).

  - fb: fix lost console when the user unplugs a USB adapter
    (bnc#1012382).

  - fbdev: omapfb: off by one in omapfb_register_client()
    (bsc#1106929).

  - fix __legitimize_mnt()/mntput() race (bnc#1012382).

  - fix mntput/mntput race (bnc#1012382).

  - fork: unconditionally clear stack on fork (bnc#1012382).

  - fs/9p/xattr.c: catch the error of p9_client_clunk when
    setting xattr failed (bnc#1012382).

  - fs/dax.c: fix inefficiency in
    dax_writeback_mapping_range() (bsc#1106185).

  - fs/quota: Fix spectre gadget in do_quotactl
    (bnc#1012382).

  - fs: aio: fix the increment of aio-nr and counting
    against aio-max-nr (bsc#1068075, bsc#1078921).

  - fuse: Add missed unlock_page() to fuse_readpages_fill()
    (bnc#1012382).

  - fuse: Do not access pipe->buffers without pipe_lock()
    (bnc#1012382).

  - fuse: Fix oops at process_init_reply() (bnc#1012382).

  - fuse: fix double request_end() (bnc#1012382).

  - fuse: fix unlocked access to processing queue
    (bnc#1012382).

  - fuse: umount should wait for all requests (bnc#1012382).

  - genirq/proc: Return proper error code when
    irq_set_affinity() fails (bnc#1105392).

  - getxattr: use correct xattr length (bnc#1012382).

  - hfsplus: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - hvc_opal: do not set tb_ticks_per_usec in
    udbg_init_opal_common() (bnc#1012382).

  - hwrng: exynos - Disable runtime PM on driver unbind
    (git-fixes).

  - i2c: davinci: Avoid zero value of CLKH (bnc#1012382).

  - i2c: imx: Fix race condition in dma read (bnc#1012382).

  - i2c: imx: Fix reinit_completion() use (bnc#1012382).

  - i2c: ismt: fix wrong device address when unmap the data
    buffer (bnc#1012382).

  - i40e: use cpumask_copy instead of direct assignment
    (bsc#1053685).

  - i40iw: Fix memory leak in error path of create QP
    (bsc#969476 bsc#969477).

  - i40iw: Use correct address in dst_neigh_lookup for IPv6
    (bsc#969476 bsc#969477).

  - ibmvnic: Include missing return code checks in reset
    function (bnc#1107966).

  - ieee802154: at86rf230: switch from BUG_ON() to WARN_ON()
    on problem (bnc#1012382).

  - ieee802154: at86rf230: use __func__ macro for debug
    messages (bnc#1012382).

  - ieee802154: fakelb: switch from BUG_ON() to WARN_ON() on
    problem (bnc#1012382).

  - igb: Fix not adding filter elements to the list
    (bsc#1024361 bsc#1024365).

  - iio: ad9523: Fix displayed phase (bnc#1012382).

  - iio: ad9523: Fix return value for ad952x_store()
    (bnc#1012382).

  - inet: frag: enforce memory limits earlier (bnc#1012382
    bsc#970506).

  - iommu/amd: make sure TLB to be flushed before IOVA freed
    (bsc#1106105).

  - iommu/vt-d: Add definitions for PFSID (bnc#1012382).

  - iommu/vt-d: Fix dev iotlb pfsid use (bnc#1012382).

  - iommu/vt-d: Ratelimit each dmar fault printing
    (bsc#1106105).

  - ioremap: Update pgtable free interfaces with addr
    (bnc#1012382).

  - ip: hash fragments consistently (bnc#1012382).

  - ip: in cmsg IP(V6)_ORIGDSTADDR call pskb_may_pull
    (bnc#1012382).

  - ipconfig: Correctly initialise ic_nameservers
    (bnc#1012382).

  - ipv4+ipv6: Make INET*_ESP select CRYPTO_ECHAINIV
    (bnc#1012382).

  - ipv4: Return EINVAL when ping_group_range sysctl does
    not map to user ns (bnc#1012382).

  - ipv4: remove BUG_ON() from fib_compute_spec_dst
    (bnc#1012382).

  - ipv6: fix useless rol32 call on hash (bnc#1012382).

  - ipv6: mcast: fix unsolicited report interval after
    receiving querys (bnc#1012382).

  - ipvlan: use ETH_MAX_MTU as max mtu (bsc#1033962).

  - iscsi target: fix session creation failure handling
    (bnc#1012382).

  - isdn: Disable IIOCDBGVAR (bnc#1012382).

  - iw_cxgb4: remove duplicate memcpy() in
    c4iw_create_listen() (bsc#969476 bsc#969477).

  - iwlwifi: pcie: fix race in Rx buffer allocator
    (bnc#1012382).

  - ixgbe: Be more careful when modifying MAC filters
    (bnc#1012382).

  - jfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - jump_label: Add RELEASE barrier after text changes
    (bsc#1105271).

  - jump_label: Fix concurrent static_key_enable/disable()
    (bsc#1105271).

  - jump_label: Move CPU hotplug locking (bsc#1105271).

  - jump_label: Provide hotplug context variants
    (bsc#1105271).

  - jump_label: Reduce the size of struct static_key
    (bsc#1105271).

  - jump_label: Reorder hotplug lock and jump_label_lock
    (bsc#1105271).

  - jump_label: Split out code under the hotplug lock
    (bsc#1105271).

  - jump_label: remove bug.h, atomic.h dependencies for
    HAVE_JUMP_LABEL (bsc#1105271).

  - kabi/severities: Ignore missing cpu_tss_tramp
    (bsc#1099597)

  - kabi: x86/speculation/l1tf: Increase l1tf memory limit
    for Nehalem+ (bnc#1105536).

  - kasan: do not emit builtin calls when sanitization is
    off (bnc#1012382).

  - kasan: fix shadow_size calculation error in
    kasan_module_alloc (bnc#1012382).

  - kbuild: verify that $DEPMOD is installed (bnc#1012382).

  - kernel: improve spectre mitigation (bnc#1106934,
    LTC#171029).

  - kprobes/x86: Fix %p uses in error messages
    (bnc#1012382).

  - kprobes: Make list and blacklist root user read only
    (bnc#1012382).

  - kthread, tracing: Do not expose half-written comm when
    creating kthreads (bsc#1104897).

  - kvm: x86: vmx: fix vpid leak (bnc#1012382).

  - l2tp: use sk_dst_check() to avoid race on
    sk->sk_dst_cache (bnc#1012382).

  - lib/rhashtable: consider param->min_size when setting
    initial table size (bnc#1012382).

  - libata: Fix command retry decision (bnc#1012382).

  - libceph: check authorizer reply/challenge length before
    reading (bsc#1096748).

  - libceph: factor out __ceph_x_decrypt() (bsc#1096748).

  - libceph: factor out __prepare_write_connect()
    (bsc#1096748).

  - libceph: factor out encrypt_authorizer() (bsc#1096748).

  - libceph: store ceph_auth_handshake pointer in
    ceph_connection (bsc#1096748).

  - libceph: weaken sizeof check in
    ceph_x_verify_authorizer_reply() (bsc#1096748).

  - llc: use refcount_inc_not_zero() for llc_sap_find()
    (bnc#1012382).

  - locking/lockdep: Do not record IRQ state within lockdep
    code (bnc#1012382).

  - locks: pass inode pointer to locks_free_lock_context
    (bsc@1099832).

  - locks: prink more detail when there are leaked locks
    (bsc#1099832).

  - locks: restore a warn for leaked locks on close
    (bsc#1099832).

  - m68k: fix 'bad page state' oops on ColdFire boot
    (bnc#1012382).

  - mac80211: add stations tied to AP_VLANs during hw
    reconfig (bnc#1012382).

  - md/raid10: fix that replacement cannot complete recovery
    after reassemble (bnc#1012382).

  - md: fix NULL dereference of mddev->pers in
    remove_and_add_spares() (bnc#1012382).

  - media: omap3isp: fix unbalanced dma_iommu_mapping
    (bnc#1012382).

  - media: rcar_jpu: Add missing clk_disable_unprepare() on
    error in jpu_open() (bnc#1012382).

  - media: rtl28xxu: be sure that it won't go past the array
    size (bsc#1050431).

  - media: s5p-jpeg: fix number of components macro
    (bsc#1050431).

  - media: saa7164: Fix driver name in debug output
    (bnc#1012382).

  - media: si470x: fix __be16 annotations (bnc#1012382).

  - media: siano: get rid of __le32/__le16 cast warnings
    (bnc#1012382).

  - media: staging: omap4iss: Include asm/cacheflush.h after
    generic includes (bnc#1012382).

  - media: videobuf2-core: do not call memop 'finish' when
    queueing (bnc#1012382).

  - memory: tegra: Apply interrupts mask per SoC
    (bnc#1012382).

  - memory: tegra: Do not handle spurious interrupts
    (bnc#1012382).

  - mfd: cros_ec: Fail early if we cannot identify the EC
    (bnc#1012382).

  - microblaze: Fix simpleImage format generation
    (bnc#1012382).

  - mm/hugetlb: filter out hugetlb pages if HUGEPAGE
    migration is not supported (bnc#1106697).

  - mm/memory.c: check return value of ioremap_prot
    (bnc#1012382).

  - mm/slub.c: add __printf verification to slab_err()
    (bnc#1012382).

  - mm/tlb: Remove tlb_remove_table() non-concurrent
    condition (bnc#1012382).

  - mm: Add vm_insert_pfn_prot() (bnc#1012382).

  - mm: fix cache mode tracking in vm_insert_mixed()
    (bnc#1012382).

  - mm: memcg: fix use after free in mem_cgroup_iter()
    (bnc#1012382).

  - mm: vmalloc: avoid racy handling of debugobjects in
    vunmap (bnc#1012382).

  - mm: x86: move _PAGE_SWP_SOFT_DIRTY from bit 7 to bit 1
    (bnc#1012382).

  - mtd: rawnand: fsl_ifc: fix FSL NAND driver to read all
    ONFI parameter pages (bnc#1012382).

  - mtd: ubi: wl: Fix error return code in ubi_wl_init()
    (git-fixes).

  - mwifiex: correct histogram data with appropriate index
    (bnc#1012382).

  - mwifiex: handle race during mwifiex_usb_disconnect
    (bnc#1012382).

  - net/9p/client.c: version pointer uninitialized
    (bnc#1012382).

  - net/9p/trans_fd.c: fix race-condition by flushing
    workqueue before the kfree() (bnc#1012382).

  - net/ethernet/freescale/fman: fix cross-build error
    (bnc#1012382).

  - net/ipv4: Set oif in fib_compute_spec_dst (bnc#1012382).

  - net/mlx4_core: Save the qpn from the input modifier in
    RST2INIT wrapper (bnc#1012382).

  - net/mlx5: Add missing SET_DRIVER_VERSION command
    translation (bsc#1015342 bsc#1015343).

  - net/mlx5: E-Switch, Include VF RDMA stats in vport
    statistics (bsc#966170 bsc#966172).

  - net/mlx5: Eswitch, Use 'kvfree()' for memory allocated
    by 'kvzalloc()' (bsc#1015342 bsc#1015343).

  - net/mlx5: Fix wrong size allocation for QoS ETC TC
    regitster (bsc#966170 bsc#966172).

  - net/mlx5: Vport, Use 'kvfree()' for memory allocated by
    'kvzalloc()' (bsc#966170 bsc#966172).

  - net/mlx5e: Do not allow aRFS for encapsulated packets
    (bsc#1015342 bsc#1015343).

  - net/mlx5e: Err if asked to offload TC match on frag
    being first (bsc#1015342 bsc#1015343).

  - net/mlx5e: Fix quota counting in aRFS expire flow
    (bsc#1015342 bsc#1015343).

  - net/mlx5e: Refine ets validation function (bsc#966170
    bsc#966172).

  - net: 6lowpan: fix reserved space for single frames
    (bnc#1012382).

  - net: Do not copy pfmemalloc flag in __copy_skb_header()
    (bnc#1012382).

  - net: add skb_condense() helper (bsc#1089066).

  - net: adjust skb->truesize in ___pskb_trim()
    (bsc#1089066).

  - net: adjust skb->truesize in pskb_expand_head()
    (bsc#1089066).

  - net: axienet: Fix double deregister of mdio
    (bnc#1012382).

  - net: caif: Add a missing rcu_read_unlock() in
    caif_flow_cb (bnc#1012382).

  - net: davinci_emac: match the mdio device against its
    compatible if possible (bnc#1012382).

  - net: dsa: Do not suspend/resume closed slave_dev
    (bnc#1012382).

  - net: ena: Fix use of uninitialized DMA address bits
    field (bsc#1027968).

  - net: fix amd-xgbe flow-control issue (bnc#1012382).

  - net: hamradio: use eth_broadcast_addr (bnc#1012382).

  - net: lan78xx: Fix misplaced tasklet_schedule() call
    (bnc#1012382).

  - net: lan78xx: fix rx handling before first packet is
    send (bnc#1012382).

  - net: mac802154: tx: expand tailroom if necessary
    (bnc#1012382).

  - net: phy: fix flag masking in __set_phy_supported
    (bnc#1012382).

  - net: prevent ISA drivers from building on PPC32
    (bnc#1012382).

  - net: propagate dev_get_valid_name return code
    (bnc#1012382).

  - net: qca_spi: Avoid packet drop during initial sync
    (bnc#1012382).

  - net: qca_spi: Fix log level if probe fails
    (bnc#1012382).

  - net: qca_spi: Make sure the QCA7000 reset is triggered
    (bnc#1012382).

  - net: socket: fix potential spectre v1 gadget in
    socketcall (bnc#1012382).

  - net: usb: rtl8150: demote allmulti message to dev_dbg()
    (bnc#1012382).

  - net: vmxnet3: use new api
    ethtool_(get|set)_link_ksettings (bsc#1091860
    bsc#1098253).

  - net_sched: Fix missing res info when create new tc_index
    filter (bnc#1012382).

  - net_sched: fix NULL pointer dereference when delete
    tcindex filter (bnc#1012382).

  - netfilter: conntrack: dccp: treat SYNC/SYNCACK as
    invalid if no prior state (bnc#1012382).

  - netfilter: ipset: List timing out entries with 'timeout
    1' instead of zero (bnc#1012382).

  - netfilter: ipv6: nf_defrag: reduce struct net memory
    waste (bnc#1012382).

  - netfilter: ipvs: do not create conn for ABORT packet in
    sctp_conn_schedule (bsc#1102797).

  - netfilter: ipvs: fix the issue that sctp_conn_schedule
    drops non-INIT packet (bsc#1102797).

  - netfilter: x_tables: set module owner for icmp(6)
    matches (bnc#1012382).

  - netlink: Do not shift on 64 for ngroups (bnc#1012382).

  - netlink: Do not shift with UB on nlk->ngroups
    (bnc#1012382).

  - netlink: Do not subscribe to non-existent groups
    (bnc#1012382).

  - netlink: Fix spectre v1 gadget in netlink_create()
    (bnc#1012382).

  - netlink: do not enter direct reclaim from netlink_trim()
    (bsc#1042286).

  - nfsd: fix potential use-after-free in
    nfsd4_decode_getdeviceinfo (bnc#1012382).

  - nl80211: Add a missing break in parse_station_flags
    (bnc#1012382).

  - nohz: Fix local_timer_softirq_pending() (bnc#1012382).

  - nvme-fc: release io queues to allow fast fail
    (bsc#1102486).

  - nvme: if_ready checks to fail io to deleting controller
    (bsc#1102486).

  - nvme: kABI-compliant version of
    nvmf_fail_nonready_command() (bsc#1102486).

  - nvmet-fc: fix target sgl list on large transfers
    (bsc#1102486).

  - osf_getdomainname(): use copy_to_user() (bnc#1012382).

  - ovl: Do d_type check only if work dir creation was
    successful (bnc#1012382).

  - ovl: Ensure upper filesystem supports d_type
    (bnc#1012382).

  - ovl: warn instead of error if d_type is not supported
    (bnc#1012382).

  - packet: refine ring v3 block size test to hold one frame
    (bnc#1012382).

  - packet: reset network header if packet shorter than ll
    reserved space (bnc#1012382).

  - parisc: Define mb() and add memory barriers to assembler
    unlock sequences (bnc#1012382).

  - parisc: Enable CONFIG_MLONGCALLS by default
    (bnc#1012382).

  - parisc: Remove ordered stores from syscall.S
    (bnc#1012382).

  - parisc: Remove unnecessary barriers from spinlock.h
    (bnc#1012382).

  - perf auxtrace: Fix queue resize (bnc#1012382).

  - perf llvm-utils: Remove bashism from kernel include
    fetch script (bnc#1012382).

  - perf report powerpc: Fix crash if callchain is empty
    (bnc#1012382).

  - perf test session topology: Fix test on s390
    (bnc#1012382).

  - perf/x86/intel/uncore: Correct fixed counter index check
    for NHM (bnc#1012382).

  - perf/x86/intel/uncore: Correct fixed counter index check
    in generic code (bnc#1012382).

  - perf: fix invalid bit in diagnostic entry (bnc#1012382).

  - pinctrl: at91-pio4: add missing of_node_put
    (bnc#1012382).

  - pinctrl: freescale: off by one in
    imx1_pinconf_group_dbg_show() (bnc#1012382).

  - pnfs/blocklayout: off by one in bl_map_stripe()
    (bnc#1012382).

  - powerpc/32: Add a missing include header (bnc#1012382).

  - powerpc/64s: Default l1d_size to 64K in RFI fallback
    flush (bsc#1068032.

  - powerpc/64s: Fix compiler store ordering to SLB shadow
    area (bnc#1012382).

  - powerpc/8xx: fix invalid register expression in
    head_8xx.S (bnc#1012382).

  - powerpc/chrp/time: Make some functions static, add
    missing header include (bnc#1012382).

  - powerpc/embedded6xx/hlwd-pic: Prevent interrupts from
    being handled by Starlet (bnc#1012382).

  - powerpc/lib: Fix the feature fixup tests to actually
    work (bsc#1066223).

  - powerpc/powermac: Add missing prototype for
    note_bootable_part() (bnc#1012382).

  - powerpc/powermac: Mark variable x as unused
    (bnc#1012382).

  - powerpc/pseries: Fix endianness while restoring of r3 in
    MCE handler (bnc#1012382).

  - powerpc/topology: Get topology for shared processors at
    boot (bsc#1104683).

  - powerpc64s: Show ori31 availability in spectre_v1 sysfs
    file not v2 (bsc#1068032, bsc#1080157.

  - powerpc: Avoid code patching freed init sections
    (bnc#1107735).

  - powerpc: make feature-fixup tests fortify-safe
    (bsc#1066223).

  - provide special timeout module parameters for EC2
    (bsc#1065364).

  - ptp: fix missing break in switch (bnc#1012382).

  - pwm: tiehrpwm: Fix disabling of output of PWMs
    (bnc#1012382).

  - qed: Add sanity check for SIMD fastpath handler
    (bnc#1012382).

  - qed: Correct Multicast API to reflect existence of 256
    approximate buckets (bsc#1019695 bsc#1019699
    bsc#1022604).

  - qed: Do not advertise DCBX_LLD_MANAGED capability
    (bsc#1019695 bsc#1019699 bsc#1022604).

  - qed: Fix possible memory leak in Rx error path handling
    (bsc#1019695 bsc#1019699 bsc#1022604 ).

  - qed: Fix possible race for the link state value
    (bnc#1012382).

  - qed: Fix setting of incorrect eswitch mode (bsc#1019695
    bsc#1019699 bsc#1022604).

  - qed: Fix use of incorrect size in memcpy call
    (bsc#1019695 bsc#1019699 bsc#1022604).

  - qede: Adverstise software timestamp caps when PHC is not
    available (bsc#1019695 bsc#1019699 bsc#1022604).

  - qlge: Fix netdev features configuration (bsc#1098822).

  - qlogic: check kstrtoul() for errors (bnc#1012382).

  - random: mix rdrand with entropy sent in from userspace
    (bnc#1012382).

  - readahead: stricter check for bdi io_pages (VM
    Functionality).

  - regulator: pfuze100: add .is_enable() for
    pfuze100_swb_regulator_ops (bnc#1012382).

  - reiserfs: fix broken xattr handling (heap corruption,
    bad retval) (bnc#1012382).

  - ring_buffer: tracing: Inherit the tracing setting to
    next ring buffer (bnc#1012382).

  - root dentries need RCU-delayed freeing (bnc#1012382).

  - rsi: Fix 'invalid vdd' warning in mmc (bnc#1012382).

  - rtc: ensure rtc_set_alarm fails when alarms are not
    supported (bnc#1012382).

  - rtnetlink: add rtnl_link_state check in
    rtnl_configure_link (bnc#1012382).

  - s390/cpum_sf: Add data entry sizes to sampling trailer
    entry (bnc#1012382).

  - s390/kvm: fix deadlock when killed by oom (bnc#1012382).

  - s390/lib: use expoline for all bcr instructions
    (bnc#1106934, LTC#171029).

  - s390/pci: fix out of bounds access during irq setup
    (bnc#1012382).

  - s390/qdio: reset old sbal_state flags (bnc#1012382).

  - s390/qeth: do not clobber buffer on async TX completion
    (bnc#1104485, LTC#170349).

  - s390/qeth: fix race when setting MAC address
    (bnc#1104485, LTC#170726).

  - s390: add explicit linux/stringify.h for jump label
    (bsc#1105271).

  - s390: detect etoken facility (bnc#1106934, LTC#171029).

  - s390: fix br_r1_trampoline for machines without exrl
    (bnc#1012382 bnc#1106934 LTC#171029).

  - sched/fair: Avoid divide by zero when rebalancing
    domains (bsc#1096254).

  - scripts/tar-up.sh: Do not package gitlog-excludes file
    Also fix the evaluation of gitlog-excludes file, too

  - scsi: 3w-9xxx: fix a missing-check bug (bnc#1012382).

  - scsi: 3w-xxxx: fix a missing-check bug (bnc#1012382).

  - scsi: core: Avoid that SCSI device removal through sysfs
    triggers a deadlock (bnc#1012382).

  - scsi: fcoe: drop frames in ELS LOGO error path
    (bnc#1012382).

  - scsi: hpsa: limit transfer length to 1MB, not 512kB
    (bsc#1102346).

  - scsi: libiscsi: fix possible NULL pointer dereference in
    case of TMF (bnc#1012382).

  - scsi: megaraid: silence a static checker bug
    (bnc#1012382).

  - scsi: megaraid_sas: Increase timeout by 1 sec for
    non-RAID fastpath IOs (bnc#1012382).

  - scsi: qla2xxx: Fix ISP recovery on unload (bnc#1012382).

  - scsi: qla2xxx: Return error when TMF returns
    (bnc#1012382).

  - scsi: scsi_dh: replace too broad 'TP9' string with the
    exact models (bnc#1012382).

  - scsi: sr: Avoid that opening a CD-ROM hangs with runtime
    power management enabled (bnc#1012382).

  - scsi: sysfs: Introduce
    sysfs_(un,)break_active_protection() (bnc#1012382).

  - scsi: ufs: fix exception event handling (bnc#1012382).

  - scsi: vmw_pvscsi: Return DID_RESET for status
    SAM_STAT_COMMAND_TERMINATED (bnc#1012382).

  - scsi: xen-scsifront: add error handling for
    xenbus_printf (bnc#1012382).

  - scsi_debug: call resp_XXX function after setting
    host_scribble (bsc#1069138).

  - scsi_debug: reset injection flags for every_nth > 0
    (bsc#1069138).

  - selftest/seccomp: Fix the flag name
    SECCOMP_FILTER_FLAG_TSYNC (bnc#1012382).

  - selftest/seccomp: Fix the seccomp(2) signature
    (bnc#1012382).

  - selftests/ftrace: Add snapshot and tracing_on test case
    (bnc#1012382).

  - selftests/x86/sigreturn/64: Fix spurious failures on AMD
    CPUs (bnc#1012382).

  - selftests: pstore: return Kselftest Skip code for
    skipped tests (bnc#1012382).

  - selftests: static_keys: return Kselftest Skip code for
    skipped tests (bnc#1012382).

  - selftests: sync: add config fragment for testing sync
    framework (bnc#1012382).

  - selftests: user: return Kselftest Skip code for skipped
    tests (bnc#1012382).

  - selftests: zram: return Kselftest Skip code for skipped
    tests (bnc#1012382).

  - serial: 8250_dw: always set baud rate in
    dw8250_set_termios (bnc#1012382).

  - sfc: stop the TX queue before pushing new buffers
    (bsc#1017967 ).

  - skbuff: Unconditionally copy pfmemalloc in __skb_clone()
    (bnc#1012382).

  - slab: __GFP_ZERO is incompatible with a constructor
    (bnc#1107060).

  - smb3: Do not send SMB3 SET_INFO if nothing changed
    (bnc#1012382).

  - smb3: do not request leases in symlink creation and
    query (bnc#1012382).

  - spi: davinci: fix a NULL pointer dereference
    (bnc#1012382).

  - squashfs: be more careful about metadata corruption
    (bnc#1012382).

  - squashfs: more metadata hardening (bnc#1012382).

  - squashfs: more metadata hardenings (bnc#1012382).

  - staging: android: ion: check for kref overflow
    (bnc#1012382).

  - string: drop __must_check from strscpy() and restore
    strscpy() usages in cgroup (bsc#1107319).

  - sys: do not hold uts_sem while accessing userspace
    memory (bnc#1106995).

  - target_core_rbd: use RCU in free_device (bsc#1105524).

  - tcp: Fix missing range_truesize enlargement in the
    backport (bnc#1012382).

  - tcp: add max_quickacks param to tcp_incr_quickack and
    tcp_enter_quickack_mode (bnc#1012382).

  - tcp: add one more quick ack after after ECN events
    (bnc#1012382).

  - tcp: do not aggressively quick ack after ECN events
    (bnc#1012382).

  - tcp: do not cancel delay-AcK on DCTCP special ACK
    (bnc#1012382).

  - tcp: do not delay ACK in DCTCP upon CE status change
    (bnc#1012382).

  - tcp: do not force quickack when receiving out-of-order
    packets (bnc#1012382).

  - tcp: fix dctcp delayed ACK schedule (bnc#1012382).

  - tcp: helpers to send special DCTCP ack (bnc#1012382).

  - tcp: identify cryptic messages as TCP seq # bugs
    (bnc#1012382).

  - tcp: refactor tcp_ecn_check_ce to remove sk type cast
    (bnc#1012382).

  - tcp: remove DELAYED ACK events in DCTCP (bnc#1012382).

  - tg3: Add higher cpu clock for 5762 (bnc#1012382).

  - thermal: exynos: fix setting rising_threshold for
    Exynos5433 (bnc#1012382).

  - timekeeping: Eliminate the stale declaration of
    ktime_get_raw_and_real_ts64() (bsc#969470).

  - tools/power turbostat: Read extended processor family
    from CPUID (bnc#1012382).

  - tools/power turbostat: fix -S on UP systems
    (bnc#1012382).

  - tools: usb: ffs-test: Fix build on big endian systems
    (bnc#1012382).

  - tpm: fix race condition in tpm_common_write()
    (bnc#1012382).

  - tracing/blktrace: Fix to allow setting same value
    (bnc#1012382).

  - tracing/kprobes: Fix trace_probe flags on
    enable_trace_kprobe() failure (bnc#1012382).

  - tracing: Do not call start/stop() functions when
    tracing_on does not change (bnc#1012382).

  - tracing: Fix double free of event_trigger_data
    (bnc#1012382).

  - tracing: Fix possible double free in
    event_enable_trigger_func() (bnc#1012382).

  - tracing: Quiet gcc warning about maybe unused link
    variable (bnc#1012382).

  - tracing: Use __printf markup to silence compiler
    (bnc#1012382).

  - tty: Fix data race in tty_insert_flip_string_fixed_flag
    (bnc#1012382).

  - turn off -Wattribute-alias (bnc#1012382).

  - ubi: Be more paranoid while seaching for the most recent
    Fastmap (bnc#1012382).

  - ubi: Fix Fastmap's update_vol() (bnc#1012382).

  - ubi: Fix races around ubi_refill_pools() (bnc#1012382).

  - ubi: Introduce vol_ignored() (bnc#1012382).

  - ubi: Rework Fastmap attach base code (bnc#1012382).

  - ubi: fastmap: Erase outdated anchor PEBs during attach
    (bnc#1012382).

  - ubifs: Check data node size before truncate
    (bsc#1106276).

  - ubifs: Fix memory leak in lprobs self-check
    (bsc#1106278).

  - ubifs: Fix synced_i_size calculation for xattr inodes
    (bsc#1106275).

  - ubifs: xattr: Do not operate on deleted inodes
    (bsc#1106271).

  - udl-kms: change down_interruptible to down
    (bnc#1012382).

  - udl-kms: fix crash due to uninitialized memory
    (bnc#1012382).

  - udl-kms: handle allocation failure (bnc#1012382).

  - udlfb: set optimal write delay (bnc#1012382).

  - uprobes: Use synchronize_rcu() not synchronize_sched()
    (bnc#1012382).

  - usb/phy: fix PPC64 build errors in phy-fsl-usb.c
    (bnc#1012382).

  - usb: audio-v2: Correct the comment for struct
    uac_clock_selector_descriptor (bsc#1099810).

  - usb: cdc_acm: Add quirk for Castles VEGA3000
    (bnc#1012382).

  - usb: dwc2: debugfs: Do not touch RX FIFO during register
    dump (bsc#1100132).

  - usb: dwc2: fix isoc split in transfer with no data
    (bnc#1012382).

  - usb: gadget: composite: fix delayed_status race
    condition when set_interface (bnc#1012382).

  - usb: gadget: dwc2: fix memory leak in gadget_init()
    (bnc#1012382).

  - usb: gadget: f_fs: Only return delayed status when len
    is 0 (bnc#1012382).

  - usb: gadget: f_uac2: fix endianness of 'struct
    cntrl_*_lay3' (bnc#1012382).

  - usb: gadget: r8a66597: Fix a possible
    sleep-in-atomic-context bugs in r8a66597_queue()
    (bnc#1012382).

  - usb: gadget: r8a66597: Fix two possible
    sleep-in-atomic-context bugs in init_controller()
    (bnc#1012382).

  - usb: hub: Do not wait for connect state at resume for
    powered-off ports (bnc#1012382).

  - usb: renesas_usbhs: gadget: fix spin_lock_init() for
    uep->lock (bsc#1085536).

  - usb: xhci: increase CRS timeout value (bnc#1012382).

  - usbip: usbip_detach: Fix memory, udev context and udev
    leak (bnc#1012382).

  - userns: move user access out of the mutex (bnc#1012382).

  - virtio_balloon: fix another race between migration and
    ballooning (bnc#1012382).

  - virtio_console: fix uninitialized variable use
    (git-fixes).

  - vmw_balloon: VMCI_DOORBELL_SET does not check status
    (bnc#1012382).

  - vmw_balloon: do not use 2MB without batching
    (bnc#1012382).

  - vmw_balloon: fix VMCI use when balloon built into kernel
    (bnc#1012382).

  - vmw_balloon: fix inflation of 64-bit GFNs (bnc#1012382).

  - vmxnet3: Replace msleep(1) with usleep_range()
    (bsc#1091860 bsc#1098253).

  - vmxnet3: add receive data ring support (bsc#1091860
    bsc#1098253).

  - vmxnet3: add support for get_coalesce, set_coalesce
    ethtool operations (bsc#1091860 bsc#1098253).

  - vmxnet3: allow variable length transmit data ring buffer
    (bsc#1091860 bsc#1098253).

  - vmxnet3: avoid assumption about invalid dma_pa in
    vmxnet3_set_mc() (bsc#1091860 bsc#1098253).

  - vmxnet3: avoid format strint overflow warning
    (bsc#1091860 bsc#1098253).

  - vmxnet3: avoid xmit reset due to a race in vmxnet3
    (bsc#1091860 bsc#1098253).

  - vmxnet3: fix incorrect dereference when rxvlan is
    disabled (bsc#1091860 bsc#1098253).

  - vmxnet3: fix non static symbol warning (bsc#1091860
    bsc#1098253).

  - vmxnet3: fix tx data ring copy for variable size
    (bsc#1091860 bsc#1098253).

  - vmxnet3: increase default rx ring sizes (bsc#1091860
    bsc#1098253).

  - vmxnet3: introduce command to register memory region
    (bsc#1091860 bsc#1098253).

  - vmxnet3: introduce generalized command interface to
    configure the device (bsc#1091860 bsc#1098253).

  - vmxnet3: prepare for version 3 changes (bsc#1091860
    bsc#1098253).

  - vmxnet3: remove redundant initialization of pointer 'rq'
    (bsc#1091860 bsc#1098253).

  - vmxnet3: remove unused flag 'rxcsum' from struct
    vmxnet3_adapter (bsc#1091860 bsc#1098253).

  - vmxnet3: set the DMA mask before the first DMA map
    operation (bsc#1091860 bsc#1098253).

  - vmxnet3: update to version 3 (bsc#1091860 bsc#1098253).

  - vmxnet3: use DMA memory barriers where required
    (bsc#1091860 bsc#1098253).

  - vmxnet3: use correct flag to indicate LRO feature
    (bsc#1091860 bsc#1098253).

  - vsock: split dwork to avoid reinitializations
    (bnc#1012382).

  - vti6: Fix dev->max_mtu setting (bsc#1033962).

  - vti6: fix PMTU caching and reporting on xmit
    (bnc#1012382).

  - wlcore: sdio: check for valid platform device data
    before suspend (bnc#1012382).

  - x86/MCE: Remove min interval polling limitation
    (bnc#1012382).

  - x86/amd: do not set X86_BUG_SYSRET_SS_ATTRS when running
    under Xen (bnc#1012382).

  - x86/asm/entry/32: Simplify pushes of zeroed
    pt_regs->REGs (bnc#1012382).

  - x86/bugs: Move the l1tf function and define pr_fmt
    properly (bnc#1012382).

  - x86/bugs: Respect nospec command line option
    (bsc#1068032).

  - x86/cpu/AMD: Fix erratum 1076 (CPB bit) (bnc#1012382).

  - x86/cpu: Make alternative_msr_write work for 32-bit code
    (bnc#1012382).

  - x86/cpu: Re-apply forced caps every time CPU caps are
    re-read (bnc#1012382).

  - x86/cpufeature: preserve numbers (kabi).

  - x86/cpufeatures: Add CPUID_7_EDX CPUID leaf
    (bnc#1012382).

  - x86/cpufeatures: Clean up Spectre v2 related CPUID flags
    (bnc#1012382).

  - x86/entry/64/compat: Clear registers for compat
    syscalls, to reduce speculation attack surface
    (bnc#1012382).

  - x86/entry/64: Remove %ebx handling from error_entry/exit
    (bnc#1102715).

  - x86/init: fix build with CONFIG_SWAP=n (bnc#1012382).

  - x86/irqflags: Mark native_restore_fl extern inline
    (bnc#1012382).

  - x86/irqflags: Provide a declaration for native_save_fl
    (git-fixes).

  - x86/mm/kmmio: Make the tracer robust against L1TF
    (bnc#1012382).

  - x86/mm/pat: Fix L1TF stable backport for CPA
    (bnc#1012382).

  - x86/mm/pat: Fix L1TF stable backport for CPA, 2nd call
    (bnc#1012382).

  - x86/mm/pat: Make set_memory_np() L1TF safe
    (bnc#1012382).

  - x86/mm: Add TLB purge to free pmd/pte page interfaces
    (bnc#1012382).

  - x86/mm: Disable ioremap free page handling on x86-PAE
    (bnc#1012382).

  - x86/mm: Give each mm TLB flush generation a unique ID
    (bnc#1012382).

  - x86/paravirt: Fix spectre-v2 mitigations for paravirt
    guests (bnc#1012382).

  - x86/paravirt: Make native_save_fl() extern inline
    (bnc#1012382).

  - x86/process: Correct and optimize TIF_BLOCKSTEP switch
    (bnc#1012382).

  - x86/process: Optimize TIF checks in __switch_to_xtra()
    (bnc#1012382).

  - x86/process: Optimize TIF_NOTSC switch (bnc#1012382).

  - x86/process: Re-export start_thread() (bnc#1012382).

  - x86/spectre: Add missing family 6 check to microcode
    check (bnc#1012382).

  - x86/spectre_v2: Do not check microcode versions when
    running under hypervisors (bnc#1012382).

  - x86/speculation/l1tf: Exempt zeroed PTEs from inversion
    (bnc#1012382).

  - x86/speculation/l1tf: Extend 64bit swap file size limit
    (bnc#1012382).

  - x86/speculation/l1tf: Fix off-by-one error when warning
    that system has too much RAM (bnc#1105536).

  - x86/speculation/l1tf: Fix overflow in l1tf_pfn_limit()
    on 32bit (bnc#1012382).

  - x86/speculation/l1tf: Fix up CPU feature flags
    (bnc#1012382).

  - x86/speculation/l1tf: Fix up pte->pfn conversion for PAE
    (bnc#1012382).

  - x86/speculation/l1tf: Increase l1tf memory limit for
    Nehalem+ (bnc#1105536).

  - x86/speculation/l1tf: Invert all not present mappings
    (bnc#1012382).

  - x86/speculation/l1tf: Make pmd/pud_mknotpresent() invert
    (bnc#1012382).

  - x86/speculation/l1tf: Protect PAE swap entries against
    L1TF (bnc#1012382).

  - x86/speculation/l1tf: Suggest what to do on systems with
    too much RAM (bnc#1105536).

  - x86/speculation/l1tf: Unbreak
    !__HAVE_ARCH_PFN_MODIFY_ALLOWED architectures
    (bnc#1012382).

  - x86/speculation: Add asm/msr-index.h dependency
    (bnc#1012382).

  - x86/speculation: Add basic IBPB (Indirect Branch
    Prediction Barrier) support (bnc#1012382).

  - x86/speculation: Clean up various Spectre related
    details (bnc#1012382).

  - x86/speculation: Correct Speculation Control microcode
    blacklist again (bnc#1012382).

  - x86/speculation: Move
    firmware_restrict_branch_speculation_*() from C to CPP
    (bnc#1012382).

  - x86/speculation: Update Speculation Control microcode
    blacklist (bnc#1012382).

  - x86/speculation: Use ARCH_CAPABILITIES to skip L1D flush
    on vmentry (bsc#1106369).

  - x86/speculation: Use IBRS if available before calling
    into firmware (bnc#1012382).

  - x86/speculation: Use Indirect Branch Prediction Barrier
    in context switch (bnc#1012382).

  - x86/xen: Add call of speculative_store_bypass_ht_init()
    to PV paths (bnc#1012382).

  - xen-netfront: wait xenbus state change when load module
    manually (bnc#1012382).

  - xen/blkback: do not keep persistent grants too long
    (bsc#1085042).

  - xen/blkback: move persistent grants flags to bool
    (bsc#1085042).

  - xen/blkfront: cleanup stale persistent grants
    (bsc#1085042).

  - xen/blkfront: reorder tests in xlblk_init()
    (bsc#1085042).

  - xen/netfront: do not cache skb_shinfo() (bnc#1012382).

  - xen: set cpu capabilities from xen_start_kernel()
    (bnc#1012382).

  - xfrm: fix missing dst_release() after policy blocking
    lbcast and multicast (bnc#1012382).

  - xfrm: free skb if nlsk pointer is NULL (bnc#1012382).

  - xfrm_user: prevent leaking 2 bytes of kernel memory
    (bnc#1012382).

  - xfs: Remove dead code from inode recover function
    (bsc#1105396).

  - xfs: repair malformed inode items during log recovery
    (bsc#1105396).

  - xhci: Fix perceived dead host due to runtime suspend
    race with event handler (bnc#1012382).

  - zswap: re-check zswap_is_full() after do zswap_shrink()
    (bnc#1012382)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017967"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065364"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083663"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089066"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963575"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969470"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970506"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.155-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.155-68.1") ) flag++;

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
