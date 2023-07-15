#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-65.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121289);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-2547", "CVE-2018-12232", "CVE-2018-14625", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-18397", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19854", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-9568");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-65)");
  script_summary(english:"Check for the openSUSE-2019-65 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-19407: The vcpu_scan_ioapic function in
    arch/x86/kvm/x86.c allowed local users to cause a denial
    of service (NULL pointer dereference and BUG) via
    crafted system calls that reach a situation where ioapic
    is uninitialized (bnc#1116841).

  - CVE-2018-14625: An attacker might have bene able to have
    an uncontrolled read to kernel-memory from within a vm
    guest. A race condition between connect() and close()
    function may allow an attacker using the AF_VSOCK
    protocol to gather a 4 byte information leak or possibly
    intercept or corrupt AF_VSOCK messages destined to other
    clients (bnc#1106615).

  - CVE-2018-19985: The function hso_probe read if_num from
    the USB device (as an u8) and used it without a length
    check to index an array, resulting in an OOB memory read
    in hso_probe or hso_get_config_data that could be used
    by local attackers (bsc#1120743).

  - CVE-2018-16884: NFS41+ shares mounted in different
    network namespaces at the same time can make
    bc_svc_process() use wrong back-channel IDs and cause a
    use-after-free vulnerability. Thus a malicious container
    user can cause a host kernel memory corruption and a
    system panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out (bnc#1119946).

  - CVE-2018-20169: The USB subsystem mishandled size checks
    during the reading of an extra descriptor, related to
    __usb_get_extra_descriptor in drivers/usb/core/usb.c
    (bnc#1119714).

  - CVE-2018-18397: The userfaultfd implementation
    mishandled access control for certain UFFDIO_ ioctl
    calls, as demonstrated by allowing local users to write
    data into holes in a tmpfs file (if the user has
    read-only access to that file, and that file contains
    holes), related to fs/userfaultfd.c and mm/userfaultfd.c
    (bnc#1117656).

  - CVE-2018-12232: In net/socket.c there was a race
    condition between fchownat and close in cases where they
    target the same socket file descriptor, related to the
    sock_close and sockfs_setattr functions. fchownat did
    not increment the file descriptor reference count, which
    allowed close to set the socket to NULL during
    fchownat's execution, leading to a NULL pointer
    dereference and system crash (bnc#1097593).

  - CVE-2018-9568: In sk_clone_lock of sock.c, there is a
    possible memory corruption due to type confusion. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User interaction
    is not needed for exploitation. (bnc#1118319).

  - CVE-2018-16862: A security flaw was found in the way
    that the cleancache subsystem clears an inode after the
    final file truncation (removal). The new file created
    with the same inode may contain leftover pages from
    cleancache and the old file data instead of the new one
    (bnc#1117186).

  - CVE-2018-19854: An issue was discovered in the
    crypto_report_one() and related functions in
    crypto/crypto_user.c (the crypto user configuration API)
    do not fully initialize structures that are copied to
    userspace, potentially leaking sensitive memory to user
    programs. NOTE: this is a CVE-2013-2547 regression but
    with easier exploitability because the attacker did not
    need a capability (however, the system must have the
    CONFIG_CRYPTO_USER kconfig option) (bnc#1118428).

  - CVE-2018-19824: A local user could exploit a
    use-after-free in the ALSA driver by supplying a
    malicious USB Sound device (with zero interfaces) that
    is mishandled in usb_audio_probe in sound/usb/card.c
    (bnc#1118152).

The following non-security bugs were fixed :

  - ACPI / CPPC: Check for valid PCC subspace only if PCC is
    used (bsc#1117115).

  - ACPI / CPPC: Update all pr_(debug/err) messages to log
    the susbspace id (bsc#1117115).

  - aio: fix spectre gadget in lookup_ioctx (bsc#1120594).

  - alsa: cs46xx: Potential NULL dereference in probe
    (bsc#1051510).

  - alsa: emu10k1: Fix potential Spectre v1 vulnerabilities
    (bsc#1051510).

  - alsa: emux: Fix potential Spectre v1 vulnerabilities
    (bsc#1051510).

  - alsa: fireface: fix for state to fetch PCM frames
    (bsc#1051510).

  - alsa: fireface: fix reference to wrong register for
    clock configuration (bsc#1051510).

  - alsa: firewire-lib: fix wrong assignment for
    'out_packet_without_header' tracepoint (bsc#1051510).

  - alsa: firewire-lib: fix wrong handling payload_length as
    payload_quadlet (bsc#1051510).

  - alsa: firewire-lib: use the same print format for
    'without_header' tracepoints (bsc#1051510).

  - alsa: hda: add mute LED support for HP EliteBook 840 G4
    (bsc#1051510).

  - alsa: hda: Add support for AMD Stoney Ridge
    (bsc#1051510).

  - alsa: hda/ca0132 - make pci_iounmap() call conditional
    (bsc#1051510).

  - alsa: hda: fix front speakers on Huawei MBXP
    (bsc#1051510).

  - alsa: hda/realtek - Add support for Acer Aspire C24-860
    headset mic (bsc#1051510).

  - alsa: hda/realtek - Add unplug function into unplug
    state of Headset Mode for ALC225 (bsc#1051510).

  - alsa: hda/realtek: ALC286 mic and headset-mode fixups
    for Acer Aspire U27-880 (bsc#1051510).

  - alsa: hda/realtek: ALC294 mic and headset-mode fixups
    for ASUS X542UN (bsc#1051510).

  - alsa: hda/realtek - Disable headset Mic VREF for headset
    mode of ALC225 (bsc#1051510).

  - alsa: hda/realtek: Enable audio jacks of ASUS UX391UA
    with ALC294 (bsc#1051510).

  - alsa: hda/realtek: Enable audio jacks of ASUS
    UX433FN/UX333FA with ALC294 (bsc#1051510).

  - alsa: hda/realtek: Enable audio jacks of ASUS UX533FD
    with ALC294 (bsc#1051510).

  - alsa: hda/realtek: Enable the headset mic auto detection
    for ASUS laptops (bsc#1051510).

  - alsa: hda/realtek - Fixed headphone issue for ALC700
    (bsc#1051510).

  - alsa: hda/realtek: Fix mic issue on Acer AIO Veriton
    Z4660G (bsc#1051510).

  - alsa: hda/realtek: Fix mic issue on Acer AIO Veriton
    Z4860G/Z6860G (bsc#1051510).

  - alsa: hda/realtek - Fix speaker output regression on
    Thinkpad T570 (bsc#1051510).

  - alsa: hda/realtek - Fix the mute LED regresion on Lenovo
    X1 Carbon (bsc#1051510).

  - alsa: hda/realtek - Support Dell headset mode for New
    AIO platform (bsc#1051510).

  - alsa: hda/tegra: clear pending irq handlers
    (bsc#1051510).

  - alsa: pcm: Call snd_pcm_unlink() conditionally at
    closing (bsc#1051510).

  - alsa: pcm: Fix interval evaluation with openmin/max
    (bsc#1051510).

  - alsa: pcm: Fix potential Spectre v1 vulnerability
    (bsc#1051510).

  - alsa: pcm: Fix starvation on down_write_nonblock()
    (bsc#1051510).

  - alsa: rme9652: Fix potential Spectre v1 vulnerability
    (bsc#1051510).

  - alsa: trident: Suppress gcc string warning
    (bsc#1051510).

  - alsa: usb-audio: Add SMSL D1 to quirks for native DSD
    support (bsc#1051510).

  - alsa: usb-audio: Add support for Encore mDSD USB DAC
    (bsc#1051510).

  - alsa: usb-audio: Avoid access before bLength check in
    build_audio_procunit() (bsc#1051510).

  - alsa: usb-audio: Fix an out-of-bound read in
    create_composite_quirks (bsc#1051510).

  - alsa: x86: Fix runtime PM for hdmi-lpe-audio
    (bsc#1051510).

  - apparmor: do not try to replace stale label in ptrace
    access check (git-fixes).

  - apparmor: do not try to replace stale label in ptraceme
    check (git-fixes).

  - apparmor: Fix uninitialized value in aa_split_fqname
    (git-fixes).

  - arm64: Add work around for Arm Cortex-A55 Erratum
    1024718 (bsc#1120612).

  - arm64: atomics: Remove '&' from '+&' asm constraint in
    lse atomics (bsc#1120613).

  - arm64: cpu_errata: include required headers
    (bsc#1120615).

  - arm64: dma-mapping: Fix FORCE_CONTIGUOUS buffer clearing
    (bsc#1120633).

  - arm64: Fix /proc/iomem for reserved but not memory
    regions (bsc#1120632).

  - arm64: lse: Add early clobbers to some input/output asm
    operands (bsc#1120614).

  - arm64: lse: remove -fcall-used-x0 flag (bsc#1120618).

  - arm64: mm: always enable CONFIG_HOLES_IN_ZONE
    (bsc#1120617).

  - arm64/numa: Report correct memblock range for the dummy
    node (bsc#1120620).

  - arm64/numa: Unify common error path in numa_init()
    (bsc#1120621).

  - arm64: remove no-op -p linker flag (bsc#1120616).

  - ASoC: dapm: Recalculate audio map forcely when card
    instantiated (bsc#1051510).

  - ASoC: intel: cht_bsw_max98090_ti: Add pmc_plt_clk_0
    quirk for Chromebook Clapper (bsc#1051510).

  - ASoC: intel: cht_bsw_max98090_ti: Add pmc_plt_clk_0
    quirk for Chromebook Gnawty (bsc#1051510).

  - ASoC: intel: mrfld: fix uninitialized variable access
    (bsc#1051510).

  - ASoC: omap-abe-twl6040: Fix missing audio card caused by
    deferred probing (bsc#1051510).

  - ASoC: omap-dmic: Add pm_qos handling to avoid overruns
    with CPU_IDLE (bsc#1051510).

  - ASoC: omap-mcbsp: Fix latency value calculation for
    pm_qos (bsc#1051510).

  - ASoC: omap-mcpdm: Add pm_qos handling to avoid
    under/overruns with CPU_IDLE (bsc#1051510).

  - ASoC: rsnd: fixup clock start checker (bsc#1051510).

  - ASoC: wm_adsp: Fix dma-unsafe read of scratch registers
    (bsc#1051510).

  - ath10k: do not assume this is a PCI dev in generic code
    (bsc#1051510).

  - ath6kl: Only use match sets when firmware supports it
    (bsc#1051510).

  - b43: Fix error in cordic routine (bsc#1051510).

  - bcache: fix miss key refill->end in writeback
    (Git-fixes).

  - bcache: trace missed reading by cache_missed
    (Git-fixes).

  - blk-mq: remove synchronize_rcu() from
    blk_mq_del_queue_tag_set() (Git-fixes).

  - block: allow max_discard_segments to be stacked
    (Git-fixes).

  - block: blk_init_allocated_queue() set q->fq as NULL in
    the fail case (Git-fixes).

  - block: really disable runtime-pm for blk-mq (Git-fixes).

  - block: reset bi_iter.bi_done after splitting bio
    (Git-fixes).

  - block/swim: Fix array bounds check (Git-fixes).

  - bnxt_en: do not try to offload VLAN 'modify' action
    (bsc#1050242 ).

  - bnxt_en: Fix enables field in HWRM_QUEUE_COS2BW_CFG
    request (bsc#1086282).

  - bnxt_en: Fix VNIC reservations on the PF (bsc#1086282 ).

  - bnxt_en: get the reduced max_irqs by the ones used by
    RDMA (bsc#1050242).

  - bpf: fix check of allowed specifiers in bpf_trace_printk
    (bsc#1083647).

  - bpf: use per htab salt for bucket hash (git-fixes).

  - btrfs: Always try all copies when reading extent buffers
    (git-fixes).

  - btrfs: delete dead code in btrfs_orphan_add()
    (bsc#1111469).

  - btrfs: delete dead code in btrfs_orphan_commit_root()
    (bsc#1111469).

  - btrfs: do not BUG_ON() in btrfs_truncate_inode_items()
    (bsc#1111469).

  - btrfs: do not check inode's runtime flags under
    root->orphan_lock (bsc#1111469).

  - btrfs: do not return ino to ino cache if inode item
    removal fails (bsc#1111469).

  - btrfs: fix ENOSPC caused by orphan items reservations
    (bsc#1111469).

  - btrfs: Fix error handling in
    btrfs_cleanup_ordered_extents (git-fixes).

  - btrfs: fix error handling in btrfs_truncate()
    (bsc#1111469).

  - btrfs: fix error handling in
    btrfs_truncate_inode_items() (bsc#1111469).

  - btrfs: fix fsync of files with multiple hard links in
    new directories (1120173).

  - btrfs: Fix memory barriers usage with device stats
    counters (git-fixes).

  - btrfs: fix use-after-free on root->orphan_block_rsv
    (bsc#1111469).

  - btrfs: get rid of BTRFS_INODE_HAS_ORPHAN_ITEM
    (bsc#1111469).

  - btrfs: get rid of unused orphan infrastructure
    (bsc#1111469).

  - btrfs: move btrfs_truncate_block out of trans handle
    (bsc#1111469).

  - btrfs: qgroup: Dirty all qgroups before rescan
    (bsc#1120036).

  - btrfs: refactor btrfs_evict_inode() reserve refill dance
    (bsc#1111469).

  - btrfs: renumber BTRFS_INODE_ runtime flags and switch to
    enums (bsc#1111469).

  - btrfs: reserve space for O_TMPFILE orphan item deletion
    (bsc#1111469).

  - btrfs: run delayed items before dropping the snapshot
    (bsc#1121263, bsc#1111188).

  - btrfs: stop creating orphan items for truncate
    (bsc#1111469).

  - btrfs: tree-checker: Do not check max block group size
    as current max chunk size limit is unreliable (fixes for
    bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877,
    bsc#1102875).

  - btrfs: update stale comments referencing vmtruncate()
    (bsc#1111469).

  - can: flexcan: flexcan_irq(): fix indention
    (bsc#1051510).

  - cdrom: do not attempt to fiddle with cdo->capability
    (bsc#1051510).

  - ceph: do not update importing cap's mseq when handing
    cap export (bsc#1121273).

  - char_dev: extend dynamic allocation of majors into a
    higher range (bsc#1121058).

  - char_dev: Fix off-by-one bugs in find_dynamic_major()
    (bsc#1121058).

  - clk: mmp: Off by one in mmp_clk_add() (bsc#1051510).

  - clk: mvebu: Off by one bugs in cp110_of_clk_get()
    (bsc#1051510).

  - compiler-gcc.h: Add __attribute__((gnu_inline)) to all
    inline declarations (git-fixes).

  - config: arm64: enable erratum 1024718

  - cpufeature: avoid warning when compiling with clang
    (Git-fixes).

  - cpufreq / CPPC: Add cpuinfo_cur_freq support for CPPC
    (bsc#1117115).

  - cpufreq: CPPC: fix build in absence of v3 support
    (bsc#1117115).

  - cpupower: remove stringop-truncation waring (git-fixes).

  - crypto: bcm - fix normal/non key hash algorithm failure
    (bsc#1051510).

  - crypto: ccp - Add DOWNLOAD_FIRMWARE SEV command ().

  - crypto: ccp - Add GET_ID SEV command ().

  - crypto: ccp - Add psp enabled message when
    initialization succeeds ().

  - crypto: ccp - Add support for new CCP/PSP device ID ().

  - crypto: ccp - Allow SEV firmware to be chosen based on
    Family and Model ().

  - crypto: ccp - Fix static checker warning ().

  - crypto: ccp - Remove unused #defines ().

  - crypto: ccp - Support register differences between PSP
    devices ().

  - dasd: fix deadlock in dasd_times_out (bsc#1121477,
    LTC#174111).

  - dax: Check page->mapping isn't NULL (bsc#1120054).

  - dax: Do not access a freed inode (bsc#1120055).

  - device property: Define type of PROPERTY_ENRTY_*()
    macros (bsc#1051510).

  - device property: fix fwnode_graph_get_next_endpoint()
    documentation (bsc#1051510).

  - disable stringop truncation warnings for now
    (git-fixes).

  - dm: allocate struct mapped_device with kvzalloc
    (Git-fixes).

  - dm cache: destroy migration_cache if cache target
    registration failed (Git-fixes).

  - dm cache: fix resize crash if user does not reload cache
    table (Git-fixes).

  - dm cache metadata: ignore hints array being too small
    during resize (Git-fixes).

  - dm cache metadata: save in-core policy_hint_size to
    on-disk superblock (Git-fixes).

  - dm cache metadata: set dirty on all cache blocks after a
    crash (Git-fixes).

  - dm cache: only allow a single io_mode cache feature to
    be requested (Git-fixes).

  - dm crypt: do not decrease device limits (Git-fixes).

  - dm: fix report zone remapping to account for partition
    offset (Git-fixes).

  - dm integrity: change 'suspending' variable from bool to
    int (Git-fixes).

  - dm ioctl: harden copy_params()'s copy_from_user() from
    malicious users (Git-fixes).

  - dm linear: eliminate linear_end_io call if
    CONFIG_DM_ZONED disabled (Git-fixes).

  - dm linear: fix linear_end_io conditional definition
    (Git-fixes).

  - dm thin: handle running out of data space vs concurrent
    discard (Git-fixes).

  - dm thin metadata: remove needless work from
    __commit_transaction (Git-fixes).

  - dm thin: stop no_space_timeout worker when switching to
    write-mode (Git-fixes).

  - dm writecache: fix a crash due to reading past end of
    dirty_bitmap (Git-fixes).

  - dm writecache: report start_sector in status line
    (Git-fixes).

  - dm zoned: fix metadata block ref counting (Git-fixes).

  - dm zoned: fix various dmz_get_mblock() issues
    (Git-fixes).

  - doc/README.SUSE: correct GIT url No more gitorious,
    github we use.

  - drivers/net/usb: add device id for TP-LINK UE300 USB 3.0
    Ethernet (bsc#1119749).

  - drivers/net/usb/r8152: remove the unneeded variable
    'ret' in rtl8152_system_suspend (bsc#1119749).

  - drm/amdgpu/gmc8: update MC firmware for polaris
    (bsc#1113722)

  - drm/amdgpu: update mc firmware image for polaris12
    variants (bsc#1113722)

  - drm/amdgpu: update SMC firmware image for polaris10
    variants (bsc#1113722)

  - drm/i915/execlists: Apply a full mb before execution for
    Braswell (bsc#1113722)

  - drm/ioctl: Fix Spectre v1 vulnerabilities (bsc#1113722)

  - drm/nouveau/kms: Fix memory leak in nv50_mstm_del()
    (bsc#1113722)

  - drm: rcar-du: Fix external clock error checks
    (bsc#1113722)

  - drm: rcar-du: Fix vblank initialization (bsc#1113722)

  - drm/rockchip: psr: do not dereference encoder before it
    is null (bsc#1113722)

  - drm: set is_master to 0 upon drm_new_set_master()
    failure (bsc#1113722)

  - drm/vc4: Set ->is_yuv to false when num_planes == 1
    (bsc#1113722)

  - drm/vc4: ->x_scaling[1] should never be set to
    VC4_SCALING_NONE (bsc#1113722)

  - dt-bindings: add compatible string for Allwinner V3s SoC
    (git-fixes).

  - dt-bindings: arm: Document SoC compatible value for
    Armadillo-800 EVA (git-fixes).

  - dt-bindings: clock: add rk3399 DDR3 standard speed bins
    (git-fixes).

  - dt-bindings: clock: mediatek: add binding for
    fixed-factor clock axisel_d4 (git-fixes).

  - dt-bindings: mfd: axp20x: Add AXP806 to supported list
    of chips (git-fixes).

  - dt-bindings: net: Remove duplicate NSP Ethernet MAC
    binding document (git-fixes).

  - dt-bindings: panel: lvds: Fix path to display timing
    bindings (git-fixes).

  - dt-bindings: phy: sun4i-usb-phy: Add property
    descriptions for H3 (git-fixes).

  - dt-bindings: pwm: renesas: tpu: Fix 'compatible' prop
    description (git-fixes).

  - dt-bindings: rcar-dmac: Document missing error interrupt
    (git-fixes).

  - edac, (i7core,sb,skx)_edac: Fix uncorrected error
    counting (bsc#1114279).

  - edac, skx_edac: Fix logical channel intermediate
    decoding (bsc#1114279).

  - efi: Move some sysfs files to be read-only by root
    (bsc#1051510).

  - ethernet: fman: fix wrong of_node_put() in probe
    function (bsc#1119017).

  - exportfs: fix 'passing zero to ERR_PTR()' warning
    (bsc#1118773).

  - ext2: fix potential use after free (bsc#1118775).

  - ext4: avoid possible double brelse() in add_new_gdb() on
    error path (bsc#1118760).

  - ext4: fix EXT4_IOC_GROUP_ADD ioctl (bsc#1120604).

  - ext4: fix possible use after free in ext4_quota_enable
    (bsc#1120602).

  - ext4: missing unlock/put_page() in
    ext4_try_to_write_inline_data() (bsc#1120603).

  - extable: Consolidate *kernel_text_address() functions
    (bsc#1120092).

  - extable: Enable RCU if it is not watching in
    kernel_text_address() (bsc#1120092).

  - fbdev: fbcon: Fix unregister crash when more than one
    framebuffer (bsc#1113722)

  - fbdev: fbmem: behave better with small rotated displays
    and many CPUs (bsc#1113722)

  - firmware: add firmware_request_nowarn() - load firmware
    without warnings ().

  - Fix the breakage of KMP build on x86_64 (bsc#1121017)

  - fscache: Fix race in fscache_op_complete() due to split
    atomic_sub & read (Git-fixes).

  - fscache: Pass the correct cancelled indications to
    fscache_op_complete() (Git-fixes).

  - fs: fix lost error code in dio_complete (bsc#1118762).

  - fs/xfs: Use %pS printk format for direct addresses
    (git-fixes).

  - fuse: fix blocked_waitq wakeup (git-fixes).

  - fuse: fix leaked notify reply (git-fixes).

  - fuse: fix possibly missed wake-up after abort
    (git-fixes).

  - fuse: Fix use-after-free in fuse_dev_do_read()
    (git-fixes).

  - fuse: Fix use-after-free in fuse_dev_do_write()
    (git-fixes).

  - fuse: fix use-after-free in fuse_direct_IO()
    (git-fixes).

  - fuse: set FR_SENT while locked (git-fixes).

  - gcc-plugins: Add include required by GCC release 8
    (git-fixes).

  - gcc-plugins: Use dynamic initializers (git-fixes).

  - gfs2: Do not leave s_fs_info pointing to freed memory in
    init_sbd (bsc#1118769).

  - gfs2: Fix loop in gfs2_rbm_find (bsc#1120601).

  - gfs2: Get rid of potential double-freeing in
    gfs2_create_inode (bsc#1120600).

  - gfs2_meta: ->mount() can get NULL dev_name
    (bsc#1118768).

  - gfs2: Put bitmap buffers in put_super (bsc#1118772).

  - git_sort.py: Remove non-existent remote tj/libata

  - gpio: davinci: Remove unused member of
    davinci_gpio_controller (git-fixes).

  - gpiolib-acpi: Only defer request_irq for GpioInt ACPI
    event handlers (bsc#1051510).

  - gpiolib: Fix return value of gpio_to_desc() stub if
    !GPIOLIB (bsc#1051510).

  - gpio: max7301: fix driver for use with CONFIG_VMAP_STACK
    (bsc#1051510).

  - gpio: mvebu: only fail on missing clk if pwm is actually
    to be used (bsc#1051510).

  - HID: Add quirk for Primax PIXART OEM mice (bsc#1119410).

  - HID: input: Ignore battery reported by Symbol DS4308
    (bsc#1051510).

  - HID: multitouch: Add pointstick support for Cirque
    Touchpad (bsc#1051510).

  - hwpoison, memory_hotplug: allow hwpoisoned pages to be
    offlined (bnc#1116336).

  - i2c: axxia: properly handle master timeout
    (bsc#1051510).

  - i2c: scmi: Fix probe error on devices with an empty
    SMB0001 ACPI device node (bsc#1051510).

  - ib/hfi1: Add mtu check for operational data VLs
    (bsc#1060463 ).

  - ibmvnic: Convert reset work item mutex to spin lock ().

  - ibmvnic: Fix non-atomic memory allocation in IRQ context
    ().

  - ib/rxe: support for 802.1q VLAN on the listener
    (bsc#1082387).

  - ieee802154: 6lowpan: set IFLA_LINK (bsc#1051510).

  - ieee802154: at86rf230: switch from BUG_ON() to WARN_ON()
    on problem (bsc#1051510).

  - ieee802154: at86rf230: use __func__ macro for debug
    messages (bsc#1051510).

  - ieee802154: fakelb: switch from BUG_ON() to WARN_ON() on
    problem (bsc#1051510).

  - Include modules.fips in kernel-binary as well as
    kernel-binary-base ().

  - initramfs: fix initramfs rebuilds w/ compression after
    disabling (git-fixes).

  - input: add official Raspberry Pi's touchscreen driver
    ().

  - input: cros_ec_keyb - fix button/switch capability
    reports (bsc#1051510).

  - input: elan_i2c - add ACPI ID for Lenovo IdeaPad
    330-15ARR (bsc#1051510).

  - input: elan_i2c - add ELAN0620 to the ACPI table
    (bsc#1051510).

  - input: elan_i2c - add support for ELAN0621 touchpad
    (bsc#1051510).

  - input: hyper-v - fix wakeup from suspend-to-idle
    (bsc#1051510).

  - input: matrix_keypad - check for errors from
    of_get_named_gpio() (bsc#1051510).

  - input: nomadik-ske-keypad - fix a loop timeout test
    (bsc#1051510).

  - input: omap-keypad - fix keyboard debounce configuration
    (bsc#1051510).

  - input: synaptics - add PNP ID for ThinkPad P50 to SMBus
    (bsc#1051510).

  - input: synaptics - enable SMBus for HP 15-ay000
    (bsc#1051510).

  - input: xpad - quirk all PDP Xbox One gamepads
    (bsc#1051510).

  - integrity/security: fix digsig.c build error with header
    file (bsc#1051510).

  - intel_th: msu: Fix an off-by-one in attribute store
    (bsc#1051510).

  - iommu/amd: Fix amd_iommu=force_isolation (bsc#1106105).

  - iommu/vt-d: Handle domain agaw being less than iommu
    agaw (bsc#1106105).

  - iwlwifi: add new cards for 9560, 9462, 9461 and killer
    series (bsc#1051510).

  - iwlwifi: fix LED command capability bit (bsc#1119086).

  - iwlwifi: nvm: get num of hw addresses from firmware
    (bsc#1119086).

  - iwlwifi: pcie: do not reset TXQ write pointer
    (bsc#1051510).

  - jffs2: free jffs2_sb_info through jffs2_kill_sb()
    (bsc#1118767).

  - jump_label: Split out code under the hotplug lock
    (bsc#1106913).

  - kabi: hwpoison, memory_hotplug: allow hwpoisoned pages
    to be offlined (bnc#1116336).

  - kabi protect hnae_ae_ops (bsc#1104353).

  - kbuild: allow to use GCC toolchain not in Clang search
    path (git-fixes).

  - kbuild: fix linker feature test macros when cross
    compiling with Clang (git-fixes).

  - kbuild: make missing $DEPMOD a Warning instead of an
    Error (git-fixes).

  - kbuild: rpm-pkg: keep spec file until make mrproper
    (git-fixes).

  - kbuild: suppress packed-not-aligned warning for default
    setting only (git-fixes).

  - kbuild: verify that $DEPMOD is installed (git-fixes).

  - kernfs: Replace strncpy with memcpy (bsc#1120053).

  - keys: Fix the use of the C++ keyword 'private' in
    uapi/linux/keyctl.h (Git-fixes).

  - kobject: Replace strncpy with memcpy (git-fixes).

  - kprobes: Make list and blacklist root user read only
    (git-fixes).

  - kvm: PPC: Book3S PR: Enable use on POWER9 inside
    HPT-mode guests (bsc#1118484).

  - kvm: svm: Ensure an IBPB on all affected CPUs when
    freeing a vmcb (bsc#1114279).

  - libata: whitelist all SAMSUNG MZ7KM* solid-state disks
    (bsc#1051510).

  - libceph: fall back to sendmsg for slab pages
    (bsc#1118316).

  - libnvdimm, pfn: Pad pfn namespaces relative to other
    regions (bsc#1118962).

  - lib/raid6: Fix arm64 test build (bsc#1051510).

  - lib/ubsan.c: do not mark
    __ubsan_handle_builtin_unreachable as noreturn
    (bsc#1051510).

  - Limit max FW API version for QCA9377 (bsc#1121714,
    bsc#1121715).

  - linux/bitmap.h: fix type of nbits in
    bitmap_shift_right() (bsc#1051510).

  - locking/barriers: Convert users of
    lockless_dereference() to READ_ONCE() (Git-fixes).

  - locking/static_keys: Improve uninitialized key warning
    (bsc#1106913).

  - mac80211: Clear beacon_int in ieee80211_do_stop
    (bsc#1051510).

  - mac80211: fix reordering of buffered broadcast packets
    (bsc#1051510).

  - mac80211_hwsim: fix module init error paths for netlink
    (bsc#1051510).

  - mac80211_hwsim: Timer should be initialized before
    device registered (bsc#1051510).

  - mac80211: ignore NullFunc frames in the duplicate
    detection (bsc#1051510).

  - mac80211: ignore tx status for PS stations in
    ieee80211_tx_status_ext (bsc#1051510).

  - Mark HI and TASKLET softirq synchronous (git-fixes).

  - media: em28xx: Fix use-after-free when disconnecting
    (bsc#1051510).

  - media: em28xx: make v4l2-compliance happier by starting
    sequence on zero (bsc#1051510).

  - media: omap3isp: Unregister media device as first
    (bsc#1051510).

  - mmc: bcm2835: reset host on timeout (bsc#1051510).

  - mmc: core: Allow BKOPS and CACHE ctrl even if no HPI
    support (bsc#1051510).

  - mmc: core: Reset HPI enabled state during re-init and in
    case of errors (bsc#1051510).

  - mmc: core: Use a minimum 1600ms timeout when enabling
    CACHE ctrl (bsc#1051510).

  - mmc: dw_mmc-bluefield: Add driver extension
    (bsc#1118752).

  - mmc: dw_mmc-k3: add sd support for hi3660 (bsc#1118752).

  - MMC: OMAP: fix broken MMC on OMAP15XX/OMAP5910/OMAP310
    (bsc#1051510).

  - mmc: omap_hsmmc: fix DMA API warning (bsc#1051510).

  - mmc: sdhci: fix the timeout check window for clock and
    reset (bsc#1051510).

  - mm: do not miss the last page because of round-off error
    (bnc#1118798).

  - mm: do not warn about large allocations for slab (git
    fixes (slab)).

  - mm/huge_memory.c: reorder operations in
    __split_huge_page_tail() (VM Functionality bsc#1119962).

  - mm: hugetlb: yield when prepping struct pages (git fixes
    (memory initialisation)).

  - mm: lower the printk loglevel for __dump_page messages
    (generic hotplug debugability).

  - mm, memory_hotplug: be more verbose for memory offline
    failures (generic hotplug debugability).

  - mm, memory_hotplug: drop pointless block alignment
    checks from __offline_pages (generic hotplug
    debugability).

  - mm, memory_hotplug: print reason for the offlining
    failure (generic hotplug debugability).

  - mm: migration: fix migration of huge PMD shared pages
    (bnc#1086423).

  - mm: only report isolation failures when offlining memory
    (generic hotplug debugability).

  - mm: print more information about mapping in __dump_page
    (generic hotplug debugability).

  - mm: put_and_wait_on_page_locked() while page is migrated
    (bnc#1109272).

  - mm: sections are not offlined during memory hotremove
    (bnc#1119968).

  - mm: shmem.c: Correctly annotate new inodes for lockdep
    (Git fixes: shmem).

  - mm/vmstat.c: fix NUMA statistics updates (git fixes).

  - Move dell_rbu fix to sorted section (bsc#1087978).

  - mtd: cfi: convert inline functions to macros
    (git-fixes).

  - mtd: Fix comparison in map_word_andequal() (git-fixes).

  - namei: allow restricted O_CREAT of FIFOs and regular
    files (bsc#1118766).

  - nbd: do not allow invalid blocksize settings
    (Git-fixes).

  - net: bgmac: Fix endian access in
    bgmac_dma_tx_ring_free() (bsc#1051510).

  - net: dsa: mv88e6xxx: Fix binding documentation for MDIO
    busses (git-fixes).

  - net: dsa: qca8k: Add QCA8334 binding documentation
    (git-fixes).

  - net: ena: fix crash during ena_remove() (bsc#1111696
    bsc#1117561).

  - net: ena: update driver version from 2.0.1 to 2.0.2
    (bsc#1111696 bsc#1117561).

  - net: hns3: Add nic state check before calling
    netif_tx_wake_queue (bsc#1104353).

  - net: hns3: Add support for
    hns3_nic_netdev_ops.ndo_do_ioctl (bsc#1104353).

  - net: hns3: bugfix for buffer not free problem during
    resetting (bsc#1104353).

  - net: hns3: bugfix for handling mailbox while the command
    queue reinitialized (bsc#1104353).

  - net: hns3: bugfix for hclge_mdio_write and
    hclge_mdio_read (bsc#1104353).

  - net: hns3: bugfix for is_valid_csq_clean_head()
    (bsc#1104353 ).

  - net: hns3: bugfix for reporting unknown vector0
    interrupt repeatly problem (bsc#1104353).

  - net: hns3: bugfix for rtnl_lock's range in the
    hclgevf_reset() (bsc#1104353).

  - net: hns3: bugfix for the initialization of command
    queue's spin lock (bsc#1104353).

  - net: hns3: Check hdev state when getting link status
    (bsc#1104353).

  - net: hns3: Clear client pointer when initialize client
    failed or unintialize finished (bsc#1104353).

  - net: hns3: Fix cmdq registers initialization issue for
    vf (bsc#1104353).

  - net: hns3: Fix error of checking used vlan id
    (bsc#1104353 ).

  - net: hns3: Fix ets validate issue (bsc#1104353).

  - net: hns3: Fix for netdev not up problem when setting
    mtu (bsc#1104353).

  - net: hns3: Fix for out-of-bounds access when setting pfc
    back pressure (bsc#1104353).

  - net: hns3: Fix for packet buffer setting bug
    (bsc#1104353 ).

  - net: hns3: Fix for rx vlan id handle to support Rev 0x21
    hardware (bsc#1104353).

  - net: hns3: Fix for setting speed for phy failed problem
    (bsc#1104353).

  - net: hns3: Fix for vf vlan delete failed problem
    (bsc#1104353 ).

  - net: hns3: Fix loss of coal configuration while doing
    reset (bsc#1104353).

  - net: hns3: Fix parameter type for q_id in
    hclge_tm_q_to_qs_map_cfg() (bsc#1104353).

  - net: hns3: Fix ping exited problem when doing lp
    selftest (bsc#1104353).

  - net: hns3: Preserve vlan 0 in hardware table
    (bsc#1104353 ).

  - net: hns3: remove unnecessary queue reset in the
    hns3_uninit_all_ring() (bsc#1104353).

  - net: hns3: Set STATE_DOWN bit of hdev state when
    stopping net (bsc#1104353).

  - net/mlx4_core: Correctly set PFC param if global pause
    is turned off (bsc#1046299).

  - net: usb: r8152: constify usb_device_id (bsc#1119749).

  - net: usb: r8152: use irqsave() in USB's complete
    callback (bsc#1119749).

  - nospec: Allow index argument to have const-qualified
    type (git-fixes)

  - nospec: Kill array_index_nospec_mask_check()
    (git-fixes).

  - nvme-fc: resolve io failures during connect
    (bsc#1116803).

  - nvme-multipath: zero out ANA log buffer (bsc#1105168).

  - nvme: validate controller state before rescheduling keep
    alive (bsc#1103257).

  - objtool: Detect RIP-relative switch table references
    (bsc#1058115).

  - objtool: Detect RIP-relative switch table references,
    part 2 (bsc#1058115).

  - objtool: Fix another switch table detection issue
    (bsc#1058115).

  - objtool: Fix double-free in .cold detection error path
    (bsc#1058115).

  - objtool: Fix GCC 8 cold subfunction detection for
    aliased functions (bsc#1058115).

  - objtool: Fix 'noreturn' detection for recursive sibling
    calls (bsc#1058115).

  - objtool: Fix segfault in .cold detection with
    -ffunction-sections (bsc#1058115).

  - objtool: Support GCC 8's cold subfunctions
    (bsc#1058115).

  - objtool: Support GCC 8 switch tables (bsc#1058115).

  - panic: avoid deadlocks in re-entrant console drivers
    (bsc#1088386).

  - PCI: Add ACS quirk for Ampere root ports (bsc#1120058).

  - PCI: Add ACS quirk for APM X-Gene devices (bsc#1120058).

  - PCI: Convert device-specific ACS quirks from NULL
    termination to ARRAY_SIZE (bsc#1120058).

  - PCI: Delay after FLR of Intel DC P3700 NVMe
    (bsc#1120058).

  - PCI: Disable Samsung SM961/PM961 NVMe before FLR
    (bsc#1120058).

  - PCI: Export pcie_has_flr() (bsc#1120058).

  - PCI: iproc: Activate PAXC bridge quirk for more devices
    (bsc#1120058).

  - PCI: Mark Ceton InfiniTV4 INTx masking as broken
    (bsc#1120058).

  - PCI: Mark fall-through switch cases before enabling
    -Wimplicit-fallthrough (bsc#1120058).

  - PCI: Mark Intel XXV710 NIC INTx masking as broken
    (bsc#1120058).

  - perf tools: Fix tracing_path_mount proper path
    (git-fixes).

  - platform-msi: Free descriptors in
    platform_msi_domain_free() (bsc#1051510).

  - powerpc/64s: consolidate MCE counter increment
    (bsc#1094244).

  - powerpc/64s/radix: Fix process table entry cache
    invalidation (bsc#1055186, git-fixes).

  - powerpc/boot: Expose Kconfig symbols to wrapper
    (bsc#1065729).

  - powerpc/boot: Fix build failures with -j 1
    (bsc#1065729).

  - powerpc/pkeys: Fix handling of pkey state across fork()
    (bsc#1078248, git-fixes).

  - powerpc/powernv: Fix save/restore of SPRG3 on entry/exit
    from stop (idle) (bsc#1055121).

  - powerpc/pseries: Track LMB nid instead of using device
    tree (bsc#1108270).

  - powerpc/traps: restore recoverability of machine_check
    interrupts (bsc#1094244).

  - power: supply: olpc_battery: correct the temperature
    units (bsc#1051510).

  - ptrace: Remove unused ptrace_may_access_sched() and
    MODE_IBRS (bsc#1106913).

  - qed: Add driver support for 20G link speed
    (bsc#1110558).

  - qed: Add support for virtual link (bsc#1111795).

  - qede: Add driver support for 20G link speed
    (bsc#1110558).

  - r8152: add byte_enable for ocp_read_word function
    (bsc#1119749).

  - r8152: add Linksys USB3GIGV1 id (bsc#1119749).

  - r8152: add r8153_phy_status function (bsc#1119749).

  - r8152: adjust lpm settings for RTL8153 (bsc#1119749).

  - r8152: adjust rtl8153_runtime_enable function
    (bsc#1119749).

  - r8152: adjust the settings about MAC clock speed down
    for RTL8153 (bsc#1119749).

  - r8152: adjust U2P3 for RTL8153 (bsc#1119749).

  - r8152: avoid rx queue more than 1000 packets
    (bsc#1119749).

  - r8152: check if disabling ALDPS is finished
    (bsc#1119749).

  - r8152: correct the definition (bsc#1119749).

  - r8152: disable RX aggregation on Dell TB16 dock
    (bsc#1119749).

  - r8152: disable RX aggregation on new Dell TB16 dock
    (bsc#1119749).

  - r8152: fix wrong checksum status for received IPv4
    packets (bsc#1119749).

  - r8152: move calling delay_autosuspend function
    (bsc#1119749).

  - r8152: move the default coalesce setting for RTL8153
    (bsc#1119749).

  - r8152: move the initialization to reset_resume function
    (bsc#1119749).

  - r8152: move the setting of rx aggregation (bsc#1119749).

  - r8152: replace napi_complete with napi_complete_done
    (bsc#1119749).

  - r8152: set rx mode early when linking on (bsc#1119749).

  - r8152: split rtl8152_resume function (bsc#1119749).

  - r8152: support new chip 8050 (bsc#1119749).

  - r8152: support RTL8153B (bsc#1119749).

  - rbd: whitelist RBD_FEATURE_OPERATIONS feature bit
    (Git-fixes).

  - rcu: Allow for page faults in NMI handlers
    (bsc#1120092).

  - rdma/bnxt_re: Add missing spin lock initialization
    (bsc#1050244 ).

  - rdma/bnxt_re: Avoid accessing the device structure after
    it is freed (bsc#1050244).

  - rdma/bnxt_re: Avoid NULL check after accessing the
    pointer (bsc#1086283).

  - rdma/bnxt_re: Fix system hang when registration with L2
    driver fails (bsc#1086283).

  - rdma/hns: Bugfix pbl configuration for rereg mr
    (bsc#1104427 ).

  - rdma_rxe: make rxe work over 802.1q VLAN devices
    (bsc#1082387).

  - reset: remove remaining WARN_ON() in <linux/reset.h>
    (Git-fixes).

  - Revert commit ef9209b642f 'staging: rtl8723bs: Fix
    indenting errors and an off-by-one mistake in
    core/rtw_mlme_ext.c' (bsc#1051510).

  - Revert 'iommu/io-pgtable-arm: Check for v7s-incapable
    systems' (bsc#1106105).

  - Revert 'PCI/ASPM: Do not initialize link state when
    aspm_disabled is set' (bsc#1051510).

  - Revert 'scsi: lpfc: ls_rjt erroneus FLOGIs'
    (bsc#1119322).

  - ring-buffer: Allow for rescheduling when removing pages
    (bsc#1120238).

  - ring-buffer: Do no reuse reader page if still in use
    (bsc#1120096).

  - ring-buffer: Mask out the info bits when returning
    buffer page length (bsc#1120094).

  - rtc: hctosys: Add missing range error reporting
    (bsc#1051510).

  - rtc: m41t80: Correct alarm month range with RTC reads
    (bsc#1051510).

  - rtc: pcf2127: fix a kmemleak caused in
    pcf2127_i2c_gather_write (bsc#1051510).

  - rtc: snvs: Add timeouts to avoid kernel lockups
    (bsc#1051510).

  - rtl8xxxu: Fix missing break in switch (bsc#1051510).

  - s390/dasd: simplify locking in dasd_times_out
    (bsc#1104967,).

  - s390/kdump: Fix elfcorehdr size calculation
    (bsc#1117953, LTC#171112).

  - s390/kdump: Make elfcorehdr size calculation ABI
    compliant (bsc#1117953, LTC#171112).

  - s390/qeth: fix length check in SNMP processing
    (bsc#1117953, LTC#173657).

  - s390/qeth: remove outdated portname debug msg
    (bsc#1117953, LTC#172960).

  - s390/qeth: sanitize strings in debug messages
    (bsc#1117953, LTC#172960).

  - sbitmap: fix race in wait batch accounting (Git-fixes).

  - sched/core: Fix cpu.max vs. cpuhotplug deadlock
    (bsc#1106913).

  - sched/fair: Fix infinite loop in
    update_blocked_averages() by reverting a9e7f6544b9c (Git
    fixes (scheduler)).

  - sched/smt: Expose sched_smt_present static key
    (bsc#1106913).

  - sched/smt: Make sched_smt_present track topology
    (bsc#1106913).

  - sched, tracing: Fix trace_sched_pi_setprio() for
    deboosting (bsc#1120228).

  - scripts/git-pre-commit: make executable.

  - scripts/git_sort/git_sort.py: change SCSI git repos to
    make series sorting more failsafe.

  - scsi: lpfc: Cap NPIV vports to 256 (bsc#1118215).

  - scsi: lpfc: Correct code setting non existent bits in
    sli4 ABORT WQE (bsc#1118215).

  - scsi: lpfc: Correct topology type reporting on G7
    adapters (bsc#1118215).

  - scsi: lpfc: Defer LS_ACC to FLOGI on point to point
    logins (bsc#1118215).

  - scsi: lpfc: Enable Management features for IF_TYPE=6
    (bsc#1119322).

  - scsi: lpfc: Fix a duplicate 0711 log message number
    (bsc#1118215).

  - scsi: lpfc: fix block guard enablement on SLI3 adapters
    (bsc#1079935).

  - scsi: lpfc: Fix dif and first burst use in write
    commands (bsc#1118215).

  - scsi: lpfc: Fix discovery failures during port failovers
    with lots of vports (bsc#1118215).

  - scsi: lpfc: Fix driver release of fw-logging buffers
    (bsc#1118215).

  - scsi: lpfc: Fix kernel Oops due to null pring pointers
    (bsc#1118215).

  - scsi: lpfc: Fix panic when FW-log buffsize is not
    initialized (bsc#1118215).

  - scsi: lpfc: ls_rjt erroneus FLOGIs (bsc#1118215).

  - scsi: lpfc: refactor mailbox structure context fields
    (bsc#1118215).

  - scsi: lpfc: rport port swap discovery issue
    (bsc#1118215).

  - scsi: lpfc: update driver version to 12.0.0.9
    (bsc#1118215).

  - scsi: lpfc: update manufacturer attribute to reflect
    Broadcom (bsc#1118215).

  - scsi: target: add emulate_pr backstore attr to toggle PR
    support (bsc#1091405).

  - scsi: target: drop unused pi_prot_format attribute
    storage (bsc#1091405).

  - scsi: zfcp: fix posting too many status read buffers
    leading to adapter shutdown (bsc#1121483, LTC#174588).

  - skd: Avoid that module unloading triggers a
    use-after-free (Git-fixes).

  - skd: Submit requests to firmware before triggering the
    doorbell (Git-fixes).

  - soc: bcm2835: sync firmware properties with downstream
    ()

  - spi: bcm2835: Avoid finishing transfer prematurely in
    IRQ mode (bsc#1051510).

  - spi: bcm2835: Fix book-keeping of DMA termination
    (bsc#1051510).

  - spi: bcm2835: Fix race on DMA termination (bsc#1051510).

  - spi: bcm2835: Unbreak the build of esoteric configs
    (bsc#1051510).

  - splice: do not read more than available pipe space
    (bsc#1119212).

  - staging: bcm2835-camera: Abort probe if there is no
    camera (bsc#1051510).

  - staging: rtl8712: Fix possible buffer overrun
    (bsc#1051510).

  - staging: rtl8723bs: Add missing return for
    cfg80211_rtw_get_station (bsc#1051510).

  - staging: rts5208: fix gcc-8 logic error warning
    (bsc#1051510).

  - staging: wilc1000: fix missing read_write setting when
    reading data (bsc#1051510).

  - Stop building F2FS (boo#1109665) As per the information
    in the bugzilla issue f2fs is no longer supported on
    opensuse distributions.

  - supported.conf: add raspberrypi-ts driver

  - supported.conf: whitelist bluefield eMMC driver

  - target/iscsi: avoid NULL dereference in CHAP auth error
    path (bsc#1117165).

  - target: se_dev_attrib.emulate_pr ABI stability
    (bsc#1091405).

  - team: no need to do team_notify_peers or
    team_mcast_rejoin when disabling port (bsc#1051510).

  - termios, tty/tty_baudrate.c: fix buffer overrun
    (bsc#1051510).

  - test_hexdump: use memcpy instead of strncpy
    (bsc#1051510).

  - tmpfs: make lseek(SEEK_DATA/SEK_HOLE) return ENXIO with
    a negative offset (bsc#1051510).

  - tools: hv: fcopy: set 'error' in case an unknown
    operation was requested (git-fixes).

  - tools: hv: include string.h in hv_fcopy_daemon
    (git-fixes).

  - tools/power/cpupower: fix compilation with STATIC=true
    (git-fixes).

  - tools/power turbostat: fix possible sprintf buffer
    overflow (git-fixes).

  - tracing/blktrace: Fix to allow setting same value
    (Git-fixes).

  - tracing: Fix bad use of igrab in trace_uprobe.c
    (bsc#1120046).

  - tracing: Fix crash when freeing instances with event
    triggers (bsc#1120230).

  - tracing: Fix crash when it fails to alloc ring buffer
    (bsc#1120097).

  - tracing: Fix double free of event_trigger_data
    (bsc#1120234).

  - tracing: Fix missing return symbol in function_graph
    output (bsc#1120232).

  - tracing: Fix possible double free in
    event_enable_trigger_func() (bsc#1120235).

  - tracing: Fix possible double free on failure of
    allocating trace buffer (bsc#1120214).

  - tracing: Fix regex_match_front() to not over compare the
    test string (bsc#1120223).

  - tracing: Fix trace_pipe behavior for instance traces
    (bsc#1120088).

  - tracing: Remove RCU work arounds from stack tracer
    (bsc#1120092).

  - tracing/samples: Fix creation and deletion of
    simple_thread_fn creation (git-fixes).

  - tty: Do not return -EAGAIN in blocking read
    (bsc#1116040).

  - tty: do not set TTY_IO_ERROR flag if console port
    (bsc#1051510).

  - tty: serial: 8250_mtk: always resume the device in probe
    (bsc#1051510).

  - ubifs: Handle re-linking of inodes correctly while
    recovery (bsc#1120598).

  - udf: Allow mounting volumes with incorrect
    identification strings (bsc#1118774).

  - unifdef: use memcpy instead of strncpy (bsc#1051510).

  - usb: appledisplay: Add 27' Apple Cinema Display
    (bsc#1051510).

  - usb: core: quirks: add RESET_RESUME quirk for Cherry
    G230 Stream series (bsc#1051510).

  - usb: dwc2: host: use hrtimer for NAK retries
    (git-fixes).

  - usb: hso: Fix OOB memory access in
    hso_probe/hso_get_config_data (bsc#1051510).

  - usbip: vhci_hcd: check rhport before using in
    vhci_hub_control() (bsc#1090888).

  - usb: omap_udc: fix crashes on probe error and module
    removal (bsc#1051510).

  - usb: omap_udc: fix omap_udc_start() on 15xx machines
    (bsc#1051510).

  - usb: omap_udc: fix USB gadget functionality on Palm
    Tungsten E (bsc#1051510).

  - usb: omap_udc: use devm_request_irq() (bsc#1051510).

  - usb: quirk: add no-LPM quirk on SanDisk Ultra Flair
    device (bsc#1051510).

  - usb: serial: option: add Fibocom NL668 series
    (bsc#1051510).

  - usb: serial: option: add GosunCn ZTE WeLink ME3630
    (bsc#1051510).

  - usb: serial: option: add HP lt4132 (bsc#1051510).

  - usb: serial: option: add Simcom SIM7500/SIM7600 (MBIM
    mode) (bsc#1051510).

  - usb: serial: option: add Telit LN940 series
    (bsc#1051510).

  - usb: usbip: Fix BUG: KASAN: slab-out-of-bounds in
    vhci_hub_control() (bsc#1106110).

  - usb: usb-storage: Add new IDs to ums-realtek
    (bsc#1051510).

  - usb: xhci: fix uninitialized completion when USB3 port
    got wrong status (bsc#1051510).

  - usb: xhci: Prevent bus suspend if a port connect change
    or polling state is detected (bsc#1051510).

  - userfaultfd: clear the vma->vm_userfaultfd_ctx if
    UFFD_EVENT_FORK fails (bsc#1118761).

  - userfaultfd: remove uffd flags from vma->vm_flags if
    UFFD_EVENT_FORK fails (bsc#1118809).

  - v9fs_dir_readdir: fix double-free on p9stat_read error
    (bsc#1118771).

  - watchdog/core: Add missing prototypes for weak functions
    (git-fixes).

  - wireless: airo: potential buffer overflow in sprintf()
    (bsc#1051510).

  - wlcore: Fix the return value in case of error in
    'wlcore_vendor_cmd_smart_config_start()' (bsc#1051510).

  - x86/bugs: Add AMD's SPEC_CTRL MSR usage (bsc#1106913).

  - x86/bugs: Fix the AMD SSBD usage of the SPEC_CTRL MSR
    (bsc#1106913).

  - x86/bugs: Switch the selection of mitigation from CPU
    vendor to CPU features (bsc#1106913).

  - x86/decoder: Fix and update the opcodes map
    (bsc#1058115).

  - x86/kabi: Fix cpu_tlbstate issue (bsc#1106913).

  - x86/l1tf: Show actual SMT state (bsc#1106913).

  - x86/MCE/AMD: Fix the thresholding machinery
    initialization order (bsc#1114279).

  - x86/mm: Fix decoy address handling vs 32-bit builds
    (bsc#1120606).

  - x86/PCI: Add additional VMD device root ports to VMD AER
    quirk (bsc#1120058).

  - x86/PCI: Add 'pci=big_root_window' option for AMD 64-bit
    windows (bsc#1120058).

  - x86/PCI: Apply VMD's AERSID fixup generically
    (bsc#1120058).

  - x86/PCI: Avoid AMD SB7xx EHCI USB wakeup defect
    (bsc#1120058).

  - x86/PCI: Enable a 64bit BAR on AMD Family 15h (Models
    00-1f, 30-3f, 60-7f) (bsc#1120058).

  - x86/PCI: Enable AMD 64-bit window on resume
    (bsc#1120058).

  - x86/PCI: Fix infinite loop in search for 64bit BAR
    placement (bsc#1120058).

  - x86/PCI: Move and shrink AMD 64-bit window to avoid
    conflict (bsc#1120058).

  - x86/PCI: Move VMD quirk to x86 fixups (bsc#1120058).

  - x86/PCI: Only enable a 64bit BAR on single-socket AMD
    Family 15h (bsc#1120058).

  - x86/PCI: Use is_vmd() rather than relying on the domain
    number (bsc#1120058).

  - x86/process: Consolidate and simplify switch_to_xtra()
    code (bsc#1106913).

  - x86/pti: Document fix wrong index (git-fixes).

  - x86/retpoline: Make CONFIG_RETPOLINE depend on compiler
    support (bsc#1106913).

  - x86/retpoline: Remove minimal retpoline support
    (bsc#1106913).

  - x86/speculataion: Mark command line parser data
    __initdata (bsc#1106913).

  - x86/speculation: Add command line control for indirect
    branch speculation (bsc#1106913).

  - x86/speculation: Add prctl() control for indirect branch
    speculation (bsc#1106913).

  - x86/speculation: Add seccomp Spectre v2 user space
    protection mode (bsc#1106913).

  - x86/speculation: Apply IBPB more strictly to avoid
    cross-process data leak (bsc#1106913).

  - x86/speculation: Avoid __switch_to_xtra() calls
    (bsc#1106913).

  - x86/speculation: Clean up spectre_v2_parse_cmdline()
    (bsc#1106913).

  - x86/speculation: Disable STIBP when enhanced IBRS is in
    use (bsc#1106913).

  - x86/speculation: Enable cross-hyperthread spectre v2
    STIBP mitigation (bsc#1106913).

  - x86/speculation: Enable prctl mode for spectre_v2_user
    (bsc#1106913).

  - x86/speculation/l1tf: Drop the swap storage limit
    restriction when l1tf=off (bnc#1114871).

  - x86/speculation: Mark string arrays const correctly
    (bsc#1106913).

  - x86/speculation: Move STIPB/IBPB string conditionals out
    of cpu_show_common() (bsc#1106913).

  - x86/speculation: Prepare arch_smt_update() for PRCTL
    mode (bsc#1106913).

  - x86/speculation: Prepare for conditional IBPB in
    switch_mm() (bsc#1106913).

  - x86/speculation: Prepare for per task indirect branch
    speculation control (bsc#1106913).

  - x86/speculation: Prevent stale SPEC_CTRL msr content
    (bsc#1106913).

  - x86/speculation: Propagate information about RSB filling
    mitigation to sysfs (bsc#1106913).

  - x86/speculation: Provide IBPB always command line
    options (bsc#1106913).

  - x86/speculation: Remove unnecessary ret variable in
    cpu_show_common() (bsc#1106913).

  - x86/speculation: Rename SSBD update functions
    (bsc#1106913).

  - x86/speculation: Reorder the spec_v2 code (bsc#1106913).

  - x86/speculation: Reorganize speculation control MSRs
    update (bsc#1106913).

  - x86/speculation: Rework SMT state change (bsc#1106913).

  - x86/speculation: Split out TIF update (bsc#1106913).

  - x86/speculation: Unify conditional spectre v2 print
    functions (bsc#1106913).

  - x86/speculation: Update the TIF_SSBD comment
    (bsc#1106913).

  - xen/netfront: tolerate frags with no data (bnc#1119804).

  - xen/x86: add diagnostic printout to xen_mc_flush() in
    case of error (bnc#1116183).

  - xfs: Align compat attrlist_by_handle with native
    implementation (git-fixes).

  - xfs: Fix xqmstats offsets in /proc/fs/xfs/xqmstat
    (git-fixes).

  - xfs: xfs_buf: drop useless LIST_HEAD (git-fixes).

  - xhci: Add quirk to workaround the errata seen on Cavium
    Thunder-X2 Soc (bsc#1117162).

  - xhci: Do not prevent USB2 bus suspend in state check
    intended for USB3 only (bsc#1051510).

  - xhci: Prevent U1/U2 link pm states if exit latency is
    too long (bsc#1051510).

  - xfs: fix quotacheck dquot id overflow infinite loop
    (bsc#1121621)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121715"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9568");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.45.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.45.1") ) flag++;

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
