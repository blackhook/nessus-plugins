#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-292.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108577);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13166", "CVE-2017-15951", "CVE-2017-16644", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-17975", "CVE-2017-18174", "CVE-2017-18208", "CVE-2018-1000026", "CVE-2018-1068", "CVE-2018-8087");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-292)");
  script_summary(english:"Check for the openSUSE-2018-292 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.120 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-8087: Memory leak in the hwsim_new_radio_nl
    function in drivers/net/wireless/mac80211_hwsim.c
    allowed local users to cause a denial of service (memory
    consumption) by triggering an out-of-array error case
    (bnc#1085053).

  - CVE-2017-13166: An elevation of privilege vulnerability
    in the v4l2 video driver was fixed. (bnc#1072865).

  - CVE-2017-18208: The madvise_willneed function in
    mm/madvise.c in the Linux kernel allowed local users to
    cause a denial of service (infinite loop) by triggering
    use of MADVISE_WILLNEED for a DAX mapping (bnc#1083494).

  - CVE-2017-17975: Use-after-free in the usbtv_probe
    function in drivers/media/usb/usbtv/usbtv-core.c allowed
    attackers to cause a denial of service (system crash) or
    possibly have unspecified other impact by triggering
    failure of audio registration, because a kfree of the
    usbtv data structure occurs during a usbtv_video_free
    call, but the usbtv_video_fail label's code attempts to
    both access and free this data structure (bnc#1074426).

  - CVE-2017-16644: The hdpvr_probe function in
    drivers/media/usb/hdpvr/hdpvr-core.c allowed local users
    to cause a denial of service (improper error handling
    and system crash) or possibly have unspecified other
    impact via a crafted USB device (bnc#1067118).

  - CVE-2017-15951: The KEYS subsystem in did not correctly
    synchronize the actions of updating versus finding a key
    in the 'negative' state to avoid a race condition, which
    allowed local users to cause a denial of service or
    possibly have unspecified other impact via crafted
    system calls (bnc#1062840 bnc#1065615).

  - CVE-2018-1000026: A insufficient input validation
    vulnerability in the bnx2x network card driver could
    result in DoS: Network card firmware assertion takes
    card off-line. This attack appear to be exploitable via
    an attacker that must pass a very large, specially
    crafted packet to the bnx2x card. This could be done
    from an untrusted guest VM. (bnc#1079384).

  - CVE-2017-18174: In the amd_gpio_remove function in
    drivers/pinctrl/pinctrl-amd.c calls the
    pinctrl_unregister function, which could lead to a
    double free (bnc#1080533).

  - CVE-2017-16912: The 'get_pipe()' function
    (drivers/usb/usbip/stub_rx.c) allowed attackers to cause
    a denial of service (out-of-bounds read) via a specially
    crafted USB over IP packet (bnc#1078673).

  - CVE-2017-16913: The 'stub_recv_cmd_submit()' function
    (drivers/usb/usbip/stub_rx.c) when handling CMD_SUBMIT
    packets allowed attackers to cause a denial of service
    (arbitrary memory allocation) via a specially crafted
    USB over IP packet (bnc#1078672).

  - CVE-2018-1068: Insufficient user provided offset
    checking in the ebtables compat code allowed local
    attackers to overwrite kernel memory and potentially
    execute code. (bsc#1085107)

The following non-security bugs were fixed :

  - acpi / bus: Leave modalias empty for devices which are
    not present (bnc#1012382).

  - acpi, nfit: fix health event notification (FATE#321135,
    FATE#321217, FATE#321256, FATE#321391, FATE#321393).

  - acpi, nfit: fix register dimm error handling
    (FATE#321135, FATE#321217, FATE#321256, FATE#321391,
    FATE#321393).

  - acpi: sbshc: remove raw pointer from printk() message
    (bnc#1012382).

  - Add delay-init quirk for Corsair K70 RGB keyboards
    (bnc#1012382).

  - ahci: Add Intel Cannon Lake PCH-H PCI ID (bnc#1012382).

  - ahci: Add PCI ids for Intel Bay Trail, Cherry Trail and
    Apollo Lake AHCI (bnc#1012382).

  - ahci: Annotate PCI ids for mobile Intel chipsets as such
    (bnc#1012382).

  - alpha: fix crash if pthread_create races with signal
    delivery (bnc#1012382).

  - alpha: fix reboot on Avanti platform (bnc#1012382).

  - alsa: hda/ca0132 - fix possible NULL pointer use
    (bnc#1012382).

  - alsa: hda - Fix headset mic detection problem for two
    Dell machines (bnc#1012382).

  - alsa: hda/realtek - Add headset mode support for Dell
    laptop (bsc#1031717).

  - alsa: hda/realtek: PCI quirk for Fujitsu U7x7
    (bnc#1012382).

  - alsa: hda - Reduce the suspend time consumption for
    ALC256 (bsc#1031717).

  - alsa: hda - Use IS_REACHABLE() for dependency on input
    (bsc#1031717).

  - alsa: seq: Fix racy pool initializations (bnc#1012382).

  - alsa: seq: Fix regression by incorrect ioctl_mutex
    usages (bnc#1012382).

  - alsa: usb-audio: add implicit fb quirk for Behringer
    UFX1204 (bnc#1012382).

  - alsa: usb-audio: Fix UAC2 get_ctl request with a RANGE
    attribute (bnc#1012382).

  - amd-xgbe: Fix unused suspend handlers build warning
    (bnc#1012382).

  - arm64: add PTE_ADDR_MASK (bsc#1068032).

  - arm64: barrier: Add CSDB macros to control data-value
    prediction (bsc#1068032).

  - arm64: define BUG() instruction without CONFIG_BUG
    (bnc#1012382).

  - arm64: Disable unhandled signal log messages by default
    (bnc#1012382).

  - arm64: dts: add #cooling-cells to CPU nodes
    (bnc#1012382).

  - arm64: entry: Apply BP hardening for high-priority
    synchronous exceptions (bsc#1068032).

  - arm64: entry: Apply BP hardening for suspicious
    interrupts from EL0 (bsc#1068032).

  - arm64: entry: Ensure branch through syscall table is
    bounded under speculation (bsc#1068032).

  - arm64: entry: Reword comment about
    post_ttbr_update_workaround (bsc#1068032).

  - arm64: Force KPTI to be disabled on Cavium ThunderX
    (bsc#1068032).

  - arm64: futex: Mask __user pointers prior to dereference
    (bsc#1068032).

  - arm64: idmap: Use 'awx' flags for .idmap.text
    .pushsection directives (bsc#1068032).

  - arm64: Implement array_index_mask_nospec()
    (bsc#1068032).

  - arm64: Kconfig: select COMPAT_BINFMT_ELF only when
    BINFMT_ELF is set (bnc#1012382).

  - arm64: kpti: Add ->enable callback to remap swapper
    using nG mappings (bsc#1068032).

  - arm64: kpti: Make use of nG dependent on
    arm64_kernel_unmapped_at_el0() (bsc#1068032).

  - arm64: Make USER_DS an inclusive limit (bsc#1068032).

  - arm64: mm: Permit transitioning from Global to
    Non-Global without BBM (bsc#1068032).

  - arm64: move TASK_* definitions to <asm/processor.h>
    (bsc#1068032).

  - arm64: Run enable method for errata work arounds on late
    CPUs (bsc#1085045).

  - arm64: uaccess: Do not bother eliding access_ok checks
    in __(get, put)_user (bsc#1068032).

  - arm64: uaccess: Mask __user pointers for __arch_(clear,
    copy_*)_user (bsc#1068032).

  - arm64: uaccess: Prevent speculative use of the current
    addr_limit (bsc#1068032).

  - arm64: Use pointer masking to limit uaccess speculation
    (bsc#1068032).

  - arm: 8731/1: Fix csum_partial_copy_from_user() stack
    mismatch (bnc#1012382).

  - arm: AM33xx: PRM: Remove am33xx_pwrdm_read_prev_pwrst
    function (bnc#1012382).

  - arm: dts: am4372: Correct the interrupts_properties of
    McASP (bnc#1012382).

  - arm: dts: Fix omap4 hang with GPS connected to USB by
    using wakeupgen (bnc#1012382).

  - arm: dts: ls1021a: fix incorrect clock references
    (bnc#1012382).

  - arm: dts: s5pv210: add interrupt-parent for ohci
    (bnc#1012382).

  - arm: dts: STi: Add gpio polarity for 'hdmi,hpd-gpio'
    property (bnc#1012382).

  - arm: kvm: Fix SMCCC handling of unimplemented SMC/HVC
    calls (bnc#1012382).

  - arm: OMAP2+: Fix SRAM virt to phys translation for
    save_secure_ram_context (bnc#1012382).

  - arm: omap2: hide omap3_save_secure_ram on non-OMAP3
    builds (git-fixes).

  - arm: pxa/tosa-bt: add MODULE_LICENSE tag (bnc#1012382).

  - arm: spear13xx: Fix dmas cells (bnc#1012382).

  - arm: spear13xx: Fix spics gpio controller's warning
    (bnc#1012382).

  - arm: spear600: Add missing interrupt-parent of rtc
    (bnc#1012382).

  - arm: tegra: select USB_ULPI from EHCI rather than
    platform (bnc#1012382).

  - asoc: au1x: Fix timeout tests in au1xac97c_ac97_read()
    (bsc#1031717).

  - asoc: Intel: Kconfig: fix build when ACPI is not enabled
    (bnc#1012382).

  - asoc: Intel: sst: Fix the return value of
    'sst_send_byte_stream_mrfld()' (bsc#1031717).

  - asoc: mediatek: add i2c dependency (bnc#1012382).

  - asoc: nuc900: Fix a loop timeout test (bsc#1031717).

  - asoc: pcm512x: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bnc#1012382).

  - asoc: rockchip: disable clock on error (bnc#1012382).

  - asoc: rsnd: avoid duplicate free_irq() (bnc#1012382).

  - asoc: rsnd: do not call free_irq() on Parent SSI
    (bnc#1012382).

  - asoc: simple-card: Fix misleading error message
    (bnc#1012382).

  - asoc: ux500: add MODULE_LICENSE tag (bnc#1012382).

  - ata: ahci_xgene: free structure returned by
    acpi_get_object_info() (bsc#1082979).

  - ata: pata_artop: remove redundant initialization of pio
    (bsc#1082979).

  - ata: sata_dwc_460ex: remove incorrect locking
    (bsc#1082979).

  - b2c2: flexcop: avoid unused function warnings
    (bnc#1012382).

  - binder: add missing binder_unlock() (bnc#1012382).

  - binder: check for binder_thread allocation failure in
    binder_poll() (bnc#1012382).

  - binfmt_elf: compat: avoid unused function warning
    (bnc#1012382).

  - blacklist acb1feab320e powerpc/64: Do not trace irqs-off
    at interrupt return to soft-disabled context

  - blacklist.conf: blacklist too intrusive patches
    (bsc#1082979)

  - blacklist.conf: commit fd5f7cde1b85d4c8e09 ('printk:
    Never set console_may_schedule in console_trylock()')

  - blk-mq: add warning to __blk_mq_run_hw_queue() for ints
    disabled (bsc#1084772).

  - blk-mq: stop 'delayed_run_work' in
    blk_mq_stop_hw_queue() (bsc#1084967).

  - blk-mq: turn WARN_ON in __blk_mq_run_hw_queue into
    printk (bsc#1084772).

  - blktrace: fix unlocked registration of tracepoints
    (bnc#1012382).

  - block: fix an error code in add_partition()
    (bsc#1082979).

  - block: Fix __bio_integrity_endio() documentation
    (bsc#1082979).

  - bluetooth: btsdio: Do not bind to non-removable BCM43341
    (bnc#1012382).

  - bluetooth: btusb: Restore QCA Rome suspend/resume fix
    with a 'rewritten' version (bnc#1012382).

  - bnx2x: Improve reliability in case of nested PCI errors
    (bnc#1012382).

  - bnxt_en: Fix the 'Invalid VF' id check in
    bnxt_vf_ndo_prep routine (bnc#1012382).

  - bpf: arsh is not supported in 32 bit alu thus reject it
    (bnc#1012382).

  - bpf: avoid false sharing of map refcount with
    max_entries (bnc#1012382).

  - bpf: fix 32-bit divide by zero (bnc#1012382).

  - bpf: fix bpf_tail_call() x64 JIT (bnc#1012382).

  - bpf: fix divides by zero (bnc#1012382).

  - bpf: introduce BPF_JIT_ALWAYS_ON config (bnc#1012382).

  - bpf: reject stores into ctx via st and xadd
    (bnc#1012382).

  - bridge: implement missing ndo_uninit() (bsc#1042286).

  - bridge: move bridge multicast cleanup to ndo_uninit
    (bsc#1042286).

  - btrfs: copy fsid to super_block s_uuid (bsc#1080774).

  - btrfs: fix crash due to not cleaning up tree log block's
    dirty bits (bnc#1012382).

  - btrfs: fix deadlock in run_delalloc_nocow (bnc#1012382).

  - btrfs: fix deadlock when writing out space cache
    (bnc#1012382).

  - btrfs: Fix possible off-by-one in
    btrfs_search_path_in_tree (bnc#1012382).

  - btrfs: Fix quota reservation leak on preallocated files
    (bsc#1079989).

  - btrfs: fix unexpected -EEXIST when creating new inode
    (bnc#1012382).

  - btrfs: Handle btrfs_set_extent_delalloc failure in fixup
    worker (bnc#1012382).

  - can: flex_can: Correct the checking for frame length in
    flexcan_start_xmit() (bnc#1012382).

  - cdrom: turn off autoclose by default (bsc#1080813).

  - ceph: fix incorrect snaprealm when adding caps
    (bsc#1081735).

  - ceph: fix un-balanced fsc->writeback_count update
    (bsc#1081735).

  - cfg80211: check dev_set_name() return value
    (bnc#1012382).

  - cfg80211: fix cfg80211_beacon_dup (bnc#1012382).

  - cifs: dump IPC tcon in debug proc file (bsc#1071306).

  - cifs: Fix autonegotiate security settings mismatch
    (bnc#1012382).

  - cifs: Fix missing put_xid in cifs_file_strict_mmap
    (bnc#1012382).

  - cifs: make IPC a regular tcon (bsc#1071306).

  - cifs: use tcon_ipc instead of use_ipc parameter of
    SMB2_ioctl (bsc#1071306).

  - cifs: zero sensitive data when freeing (bnc#1012382).

  - clk: fix a panic error caused by accessing NULL pointer
    (bnc#1012382).

  - console/dummy: leave .con_font_get set to NULL
    (bnc#1012382).

  - cpufreq: Add Loongson machine dependencies
    (bnc#1012382).

  - crypto: aesni - handle zero length dst buffer
    (bnc#1012382).

  - crypto: af_alg - whitelist mask and type (bnc#1012382).

  - crypto: caam - fix endless loop when DECO acquire fails
    (bnc#1012382).

  - crypto: cryptd - pass through absence of ->setkey()
    (bnc#1012382).

  - crypto: hash - introduce crypto_hash_alg_has_setkey()
    (bnc#1012382).

  - crypto: poly1305 - remove ->setkey() method
    (bnc#1012382).

  - crypto: s5p-sss - Fix kernel Oops in AES-ECB mode
    (bnc#1012382).

  - crypto: tcrypt - fix S/G table for test_aead_speed()
    (bnc#1012382).

  - crypto: x86/twofish-3way - Fix %rbp usage (bnc#1012382).

  - cw1200: fix bogus maybe-uninitialized warning
    (bnc#1012382).

  - dccp: limit sk_filter trim to payload (bsc#1042286).

  - dell-wmi, dell-laptop: depends DMI (bnc#1012382).

  - direct-io: Fix sleep in atomic due to sync AIO
    (bsc#1084888).

  - dlm: fix double list_del() (bsc#1082795).

  - dlm: fix NULL pointer dereference in send_to_sock()
    (bsc#1082795).

  - dmaengine: at_hdmac: fix potential NULL pointer
    dereference in atc_prep_dma_interleaved (bnc#1012382).

  - dmaengine: dmatest: fix container_of member in
    dmatest_callback (bnc#1012382).

  - dmaengine: ioat: Fix error handling path (bnc#1012382).

  - dmaengine: jz4740: disable/unprepare clk if probe fails
    (bnc#1012382).

  - dmaengine: zx: fix build warning (bnc#1012382).

  - dm: correctly handle chained bios in dec_pending()
    (bnc#1012382).

  - dn_getsockoptdecnet: move nf_(get/set)sockopt outside
    sock lock (bnc#1012382).

  - do not put symlink bodies in pagecache into highmem
    (bnc#1012382).

  - dpt_i2o: fix build warning (bnc#1012382).

  - driver-core: use 'dev' argument in dev_dbg_ratelimited
    stub (bnc#1012382).

  - drivers: hv: balloon: Correctly update onlined page
    count (fate#315887, bsc#1082632).

  - drivers: hv: balloon: Initialize last_post_time on
    startup (fate#315887, bsc#1082632).

  - drivers: hv: balloon: Show the max dynamic memory
    assigned (fate#315887, bsc#1082632).

  - drivers: hv: kvp: Use MAX_ADAPTER_ID_SIZE for
    translating adapter id (fate#315887, bsc#1082632).

  - drivers: hv: Turn off write permission on the hypercall
    page (fate#315887, bsc#1082632).

  - drivers: hv: vmbus: Fix rescind handling (fate#315887,
    bsc#1082632).

  - drivers: hv: vmbus: Fix rescind handling issues
    (fate#315887, bsc#1082632).

  - drivers/net: fix eisa_driver probe section mismatch
    (bnc#1012382).

  - drm/amdgpu: Avoid leaking PM domain on driver unbind
    (v2) (bnc#1012382).

  - drm/amdgpu: Fix SDMA load/unload sequence on HWS
    disabled mode (bnc#1012382).

  - drm/amdkfd: Fix SDMA oversubsription handling
    (bnc#1012382).

  - drm/amdkfd: Fix SDMA ring buffer size calculation
    (bnc#1012382).

  - drm/armada: fix leak of crtc structure (bnc#1012382).

  - drm/edid: Add 6 bpc quirk for CPT panel in Asus UX303LA
    (bnc#1012382).

  - drm/gma500: remove helper function (bnc#1012382).

  - drm/gma500: Sanity-check pipe index (bnc#1012382).

  - drm/nouveau: hide gcc-4.9 -Wmaybe-uninitialized
    (bnc#1012382).

  - drm/nouveau/pci: do a msi rearm on init (bnc#1012382).

  - drm/radeon: adjust tested variable (bnc#1012382).

  - drm: rcar-du: Fix race condition when disabling planes
    at CRTC stop (bnc#1012382).

  - drm: rcar-du: Use the VBK interrupt for vblank events
    (bnc#1012382).

  - drm: Require __GFP_NOFAIL for the legacy
    drm_modeset_lock_all (bnc#1012382).

  - drm/ttm: check the return value of kzalloc
    (bnc#1012382).

  - drm/vmwgfx: use *_32_bits() macros (bnc#1012382).

  - e1000: fix disabling already-disabled warning
    (bnc#1012382).

  - edac, octeon: Fix an uninitialized variable warning
    (bnc#1012382).

  - em28xx: only use mt9v011 if camera support is enabled
    (bnc#1012382).

  - enable DST_CACHE in non-vanilla configs except
    s390x/zfcpdump

  - ext4: correct documentation for grpid mount option
    (bnc#1012382).

  - ext4: do not unnecessarily allocate buffer in
    recently_deleted() (bsc#1080344).

  - ext4: Fix data exposure after failed AIO DIO
    (bsc#1069135 bsc#1082864).

  - ext4: save error to disk in __ext4_grp_locked_error()
    (bnc#1012382).

  - f2fs: fix a bug caused by NULL extent tree
    (bsc#1082478). Does not affect SLE release but should be
    merged into leap updates

  - fbdev: auo_k190x: avoid unused function warnings
    (bnc#1012382).

  - fbdev: s6e8ax0: avoid unused function warnings
    (bnc#1012382).

  - fbdev: sis: enforce selection of at least one backend
    (bnc#1012382).

  - fbdev: sm712fb: avoid unused function warnings
    (bnc#1012382).

  - fs: Avoid invalidation in interrupt context in
    dio_complete() (bsc#1073407 bsc#1069135).

  - fs: Fix page cache inconsistency when mixing buffered
    and AIO DIO (bsc#1073407 bsc#1069135).

  - fs: invalidate page cache after end_io() in dio
    completion (bsc#1073407 bsc#1069135).

  - ftrace: Remove incorrect setting of glob search field
    (bnc#1012382).

  - geneve: fix populating tclass in geneve_get_v6_dst
    (bsc#1042286).

  - genirq/msi: Add stubs for
    get_cached_msi_msg/pci_write_msi_msg (bnc#1012382).

  - genirq/msi: Fix populating multiple interrupts
    (bsc#1085047).

  - genirq: Restore trigger settings in irq_modify_status()
    (bsc#1085056).

  - genksyms: Fix segfault with invalid declarations
    (bnc#1012382).

  - gianfar: fix a flooded alignment reports because of
    padding issue (bnc#1012382).

  - go7007: add MEDIA_CAMERA_SUPPORT dependency
    (bnc#1012382).

  - gpio: ath79: add missing MODULE_DESCRIPTION/LICENSE
    (bnc#1012382).

  - gpio: intel-mid: Fix build warning when !CONFIG_PM
    (bnc#1012382).

  - gpio: iop: add missing MODULE_DESCRIPTION/AUTHOR/LICENSE
    (bnc#1012382).

  - gpio: xgene: mark PM functions as __maybe_unused
    (bnc#1012382).

  - grace: replace BUG_ON by WARN_ONCE in exit_net hook
    (bnc#1012382).

  - gre: build header correctly for collect metadata tunnels
    (bsc#1042286).

  - gre: do not assign header_ops in collect metadata mode
    (bsc#1042286).

  - gre: do not keep the GRE header around in collect medata
    mode (bsc#1042286).

  - gre: reject GUE and FOU in collect metadata mode
    (bsc#1042286).

  - hdpvr: hide unused variable (bnc#1012382).

  - hid: quirks: Fix keyboard + touchpad on Toshiba Click
    Mini not working (bnc#1012382).

  - hippi: Fix a Fix a possible sleep-in-atomic bug in
    rr_close (bnc#1012382).

  - hrtimer: Ensure POSIX compliance (relative
    CLOCK_REALTIME hrtimers) (bnc#1012382).

  - hv_netvsc: Add ethtool handler to set and get TCP hash
    levels (fate#315887, bsc#1082632).

  - hv_netvsc: Add ethtool handler to set and get UDP hash
    levels (fate#315887, bsc#1082632).

  - hv_netvsc: Add initialization of tx_table in
    netvsc_device_add() (fate#315887, bsc#1082632).

  - hv_netvsc: Change the hash level variable to bit flags
    (fate#315887, bsc#1082632).

  - hv_netvsc: Clean up an unused parameter in
    rndis_filter_set_rss_param() (fate#315887, bsc#1082632).

  - hv_netvsc: Clean up unused parameter from
    netvsc_get_hash() (fate#315887, bsc#1082632).

  - hv_netvsc: Clean up unused parameter from
    netvsc_get_rss_hash_opts() (fate#315887, bsc#1082632).

  - hv_netvsc: copy_to_send buf can be void (fate#315887,
    bsc#1082632).

  - hv_netvsc: do not need local xmit_more (fate#315887,
    bsc#1082632).

  - hv_netvsc: drop unused macros (fate#315887,
    bsc#1082632).

  - hv_netvsc: empty current transmit aggregation if flow
    blocked (fate#315887, bsc#1082632).

  - hv_netvsc: Fix rndis_filter_close error during
    netvsc_remove (fate#315887, bsc#1082632).

  - hv_netvsc: fix send buffer failure on MTU change
    (fate#315887, bsc#1082632).

  - hv_netvsc: Fix the channel limit in netvsc_set_rxfh()
    (fate#315887, bsc#1082632).

  - hv_netvsc: Fix the real number of queues of non-vRSS
    cases (fate#315887, bsc#1082632).

  - hv_netvsc: Fix the receive buffer size limit
    (fate#315887, bsc#1082632).

  - hv_netvsc: Fix the TX/RX buffer default sizes
    (fate#315887, bsc#1082632).

  - hv_netvsc: hide warnings about uninitialized/missing
    rndis device (fate#315887, bsc#1082632).

  - hv_netvsc: make const array ver_list static, reduces
    object code size (fate#315887, bsc#1082632).

  - hv_netvsc: optimize initialization of RNDIS header
    (fate#315887, bsc#1082632).

  - hv_netvsc: pass netvsc_device to receive callback
    (fate#315887, bsc#1082632).

  - hv_netvsc: remove open_cnt reference count (fate#315887,
    bsc#1082632).

  - hv_netvsc: Rename ind_table to rx_table (fate#315887,
    bsc#1082632).

  - hv_netvsc: Rename tx_send_table to tx_table
    (fate#315887, bsc#1082632).

  - hv_netvsc: replace divide with mask when computing
    padding (fate#315887, bsc#1082632).

  - hv_netvsc: report stop_queue and wake_queue
    (fate#315887, bsc#1082632).

  - hv_netvsc: simplify function args in receive status path
    (fate#315887, bsc#1082632).

  - hv_netvsc: Simplify the limit check in
    netvsc_set_channels() (fate#315887, bsc#1082632).

  - hv_netvsc: track memory allocation failures in ethtool
    stats (fate#315887, bsc#1082632).

  - hv: preserve kabi by keeping hv_do_hypercall
    (bnc#1082632).

  - hwmon: (pmbus) Use 64bit math for DIRECT format values
    (bnc#1012382).

  - hwrng: exynos - use __maybe_unused to hide pm functions
    (bnc#1012382).

  - hyper-v: trace vmbus_ongpadl_created() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_ongpadl_torndown() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_on_message() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_on_msg_dpc() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_onoffer() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_onoffer_rescind() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_onopen_result() (fate#315887,
    bsc#1082632).

  - hyper-v: trace vmbus_onversion_response() (fate#315887,
    bsc#1082632).

  - hyper-v: Use fast hypercall for HVCALL_SIGNAL_EVENT
    (fate#315887, bsc#1082632).

  - i2c: remove __init from i2c_register_board_info()
    (bnc#1012382).

  - ib/hfi1: Fix for potential refcount leak in
    hfi1_open_file() (FATE#321231 FATE#321473).

  - ib/iser: Handle lack of memory management extentions
    correctly (bsc#1082979).

  - ib/mlx4: Fix incorrectly releasing steerable UD QPs when
    have only ETH ports (bnc#1012382).

  - ib/mlx4: Fix mlx4_ib_alloc_mr error flow (bnc#1012382).

  - ibmvnic: Account for VLAN header length in TX buffers
    (bsc#1085239).

  - ibmvnic: Account for VLAN tag in L2 Header descriptor
    (bsc#1085239).

  - ibmvnic: Allocate max queues stats buffers
    (bsc#1081498).

  - ibmvnic: Allocate statistics buffers during probe
    (bsc#1082993).

  - ibmvnic: Check for NULL skb's in NAPI poll routine
    (bsc#1081134, git-fixes).

  - ibmvnic: Clean RX pool buffers during device close
    (bsc#1081134).

  - ibmvnic: Clean up device close (bsc#1084610).

  - ibmvnic: Correct goto target for tx irq initialization
    failure (bsc#1082223).

  - ibmvnic: Do not attempt to login if RX or TX queues are
    not allocated (bsc#1082993).

  - ibmvnic: Do not disable device during failover or
    partition migration (bsc#1084610).

  - ibmvnic: Ensure that buffers are NULL after free
    (bsc#1080014).

  - ibmvnic: Fix early release of login buffer (bsc#1081134,
    git-fixes).

  - ibmvnic: fix empty firmware version and errors cleanup
    (bsc#1079038).

  - ibmvnic: Fix login buffer memory leaks (bsc#1081134).

  - ibmvnic: Fix NAPI structures memory leak (bsc#1081134).

  - ibmvnic: Fix recent errata commit (bsc#1085239).

  - ibmvnic: Fix rx queue cleanup for non-fatal resets
    (bsc#1080014).

  - ibmvnic: Fix TX descriptor tracking again (bsc#1082993).

  - ibmvnic: Fix TX descriptor tracking (bsc#1081491).

  - ibmvnic: Free and re-allocate scrqs when tx/rx scrqs
    change (bsc#1081498).

  - ibmvnic: Free RX socket buffer in case of adapter error
    (bsc#1081134).

  - ibmvnic: Generalize TX pool structure (bsc#1085224).

  - ibmvnic: Handle TSO backing device errata (bsc#1085239).

  - ibmvnic: Harden TX/RX pool cleaning (bsc#1082993).

  - ibmvnic: Improve TX buffer accounting (bsc#1085224).

  - ibmvnic: Keep track of supplementary TX descriptors
    (bsc#1081491).

  - ibmvnic: Make napi usage dynamic (bsc#1081498).

  - ibmvnic: Move active sub-crq count settings
    (bsc#1081498).

  - ibmvnic: Pad small packets to minimum MTU size
    (bsc#1085239).

  - ibmvnic: queue reset when CRQ gets closed during reset
    (bsc#1080263).

  - ibmvnic: Remove skb->protocol checks in ibmvnic_xmit
    (bsc#1080384).

  - ibmvnic: Rename active queue count variables
    (bsc#1081498).

  - ibmvnic: Reorganize device close (bsc#1084610).

  - ibmvnic: Report queue stops and restarts as debug output
    (bsc#1082993).

  - ibmvnic: Reset long term map ID counter (bsc#1080364).

  - ibmvnic: Split counters for scrq/pools/napi
    (bsc#1082223).

  - ibmvnic: Update and clean up reset TX pool routine
    (bsc#1085224).

  - ibmvnic: Update release RX pool routine (bsc#1085224).

  - ibmvnic: Update TX and TX completion routines
    (bsc#1085224).

  - ibmvnic: Update TX pool initialization routine
    (bsc#1085224).

  - ibmvnic: Wait until reset is complete to set carrier on
    (bsc#1081134).

  - ib/srpt: Remove an unused structure member
    (bsc#1082979).

  - idle: i7300: add PCI dependency (bnc#1012382).

  - igb: Free IRQs when device is hotplugged (bnc#1012382).

  - iio: adc: axp288: remove redundant duplicate const on
    axp288_adc_channels (bnc#1012382).

  - iio: adis_lib: Initialize trigger before requesting
    interrupt (bnc#1012382).

  - iio: buffer: check if a buffer has been set up when poll
    is called (bnc#1012382).

  - input: tca8418_keypad - hide gcc-4.9
    -Wmaybe-uninitialized warning (bnc#1012382).

  - input: tca8418_keypad - remove double read of key event
    register (git-fixes).

  - iommu/amd: Add align parameter to alloc_irq_index()
    (bsc#975772).

  - iommu/amd: Enforce alignment for MSI IRQs (bsc#975772).

  - iommu/amd: Fix alloc_irq_index() increment (bsc#975772).

  - iommu/amd: Limit the IOVA page range to the specified
    addresses (fate#321026).

  - iommu/arm-smmu-v3: Cope with duplicated Stream IDs
    (bsc#1084926).

  - iommu/iova: Fix underflow bug in
    __alloc_and_insert_iova_range (bsc#1084928).

  - iommu/vt-d: Use domain instead of cache fetching
    (bsc#975772).

  - ip6: add ip6_make_flowinfo helper (bsc#1042286).

  - ip6mr: fix stale iterator (bnc#1012382).

  - ipc/msg: introduce msgctl(MSG_STAT_ANY) (bsc#1072689).

  - ipc/sem: introduce semctl(SEM_STAT_ANY) (bsc#1072689).

  - ipc/shm: introduce shmctl(SHM_STAT_ANY) (bsc#1072689).

  - ip_tunnel: fix preempt warning in ip tunnel
    creation/updating (bnc#1012382).

  - ip_tunnel: replace dst_cache with generic implementation
    (bnc#1012382).

  - ipv4: allow local fragmentation in
    ip_finish_output_gso() (bsc#1042286).

  - ipv4: fix checksum annotation in udp4_csum_init
    (bsc#1042286).

  - ipv4: ipconfig: avoid unused ic_proto_used symbol
    (bnc#1012382).

  - ipv4: update comment to document GSO fragmentation cases
    (bsc#1042286).

  - ipv6: datagram: Refactor dst lookup and update codes to
    a new function (bsc#1042286).

  - ipv6: datagram: Refactor flowi6 init codes to a new
    function (bsc#1042286).

  - ipv6: datagram: Update dst cache of a connected datagram
    sk during pmtu update (bsc#1042286).

  - ipv6: fix checksum annotation in udp6_csum_init
    (bsc#1042286).

  - ipv6: icmp6: Allow icmp messages to be looped back
    (bnc#1012382).

  - ipv6/ila: fix nlsize calculation for lwtunnel
    (bsc#1042286).

  - ipv6: remove unused in6_addr struct (bsc#1042286).

  - ipv6: tcp: fix endianness annotation in
    tcp_v6_send_response (bsc#1042286).

  - ipv6: udp: Do a route lookup and update during
    release_cb (bsc#1042286).

  - ipvlan: Add the skb->mark as flow4's member to lookup
    route (bnc#1012382).

  - ipvlan: fix multicast processing (bsc#1042286).

  - ipvlan: fix various issues in ipvlan_process_multicast()
    (bsc#1042286).

  - irqchip/gic-v3: Use wmb() instead of smb_wmb() in
    gic_raise_softirq() (bnc#1012382).

  - isdn: eicon: reduce stack size of sig_ind function
    (bnc#1012382).

  - isdn: icn: remove a #warning (bnc#1012382).

  - isdn: sc: work around type mismatch warning
    (bnc#1012382).

  - jffs2: Fix use-after-free bug in jffs2_iget()'s error
    handling path (git-fixes).

  - kABI: protect struct cpuinfo_x86 (kabi).

  - kABI: protect struct ethtool_link_settings
    (bsc#1085050).

  - kABI: protect struct ip_tunnel and reintroduce
    ip_tunnel_dst_reset_all (kabi).

  - kABI: reintroduce crypto_poly1305_setkey (kabi).

  - kabi: restore kabi after 'net: replace dst_cache
    ip6_tunnel implementation with the generic one'
    (bsc#1082897).

  - kabi: restore nft_set_elem_destroy() signature
    (bsc#1042286).

  - kabi: restore rhashtable_insert_slow() signature
    (bsc#1042286).

  - kabi/severities: add sclp to KABI ignore list

  - kabi/severities: add __x86_indirect_thunk_rsp

  - kabi/severities: as per bsc#1068569 we can ignore XFS
    kabi The gods have spoken, let there be light.

  - kabi/severities: Ignore kvm for KABI severities

  - kabi: uninline sk_receive_skb() (bsc#1042286).

  - kaiser: fix compile error without vsyscall
    (bnc#1012382).

  - kaiser: fix intel_bts perf crashes (bnc#1012382).

  - kasan: rework Kconfig settings (bnc#1012382).

  - kernel/async.c: revert 'async: simplify
    lowest_in_progress()' (bnc#1012382).

  - kernel: fix rwlock implementation (bnc#1079886,
    LTC#164371).

  - kernfs: fix regression in kernfs_fop_write caused by
    wrong type (bnc#1012382).

  - keys: encrypted: fix buffer overread in
    valid_master_desc() (bnc#1012382).

  - kmemleak: add scheduling point to kmemleak_scan()
    (bnc#1012382).

  - kvm: add X86_LOCAL_APIC dependency (bnc#1012382).

  - kvm: ARM64: fix phy counter access failure in guest
    (bsc#1085015).

  - kvm: arm/arm64: Check pagesize when allocating a
    hugepage at Stage 2 (bsc#1079029).

  - kvm: nVMX: Fix kernel panics induced by illegal
    INVEPT/INVVPID types (bnc#1012382).

  - kvm: nVMX: Fix races when sending nested PI while dest
    enters/leaves L2 (bnc#1012382).

  - kvm: nVMX: invvpid handling improvements (bnc#1012382).

  - kvm: nVMX: kmap() can't fail (bnc#1012382).

  - kvm: nVMX: vmx_complete_nested_posted_interrupt() can't
    fail (bnc#1012382).

  - kvm: PPC: Book3S PR: Fix svcpu copying with preemption
    enabled (bsc#1066223).

  - kvm: s390: Add operation exception interception handler
    (FATE#324070, LTC#158959).

  - kvm: s390: Add sthyi emulation (FATE#324070,
    LTC#158959).

  - kvm: s390: Enable all facility bits that are known good
    for passthrough (FATE#324071, LTC#158956).

  - kvm: s390: Extend diag 204 fields (FATE#324070,
    LTC#158959).

  - kvm: s390: Fix STHYI buffer alignment for diag224
    (FATE#324070, LTC#158959).

  - kvm: s390: instruction-execution-protection support
    (LTC#162428).

  - kvm: s390: Introduce BCD Vector Instructions to the
    guest (FATE#324072, LTC#158953).

  - kvm: s390: Introduce Vector Enhancements facility 1 to
    the guest (FATE#324072, LTC#158953).

  - kvm: s390: Limit sthyi execution (FATE#324070,
    LTC#158959).

  - kvm: s390: Populate mask of non-hypervisor managed
    facility bits (FATE#324071, LTC#158956).

  - kvm: VMX: clean up declaration of VPID/EPT invalidation
    types (bnc#1012382).

  - kvm: VMX: Fix rflags cache during vCPU reset
    (bnc#1012382).

  - kvm: VMX: Make indirect call speculation safe
    (bnc#1012382).

  - kvm: x86: Do not re-execute instruction when not passing
    CR2 value (bnc#1012382).

  - kvm: x86: emulator: Return to user-mode on L1 CPL=0
    emulation failure (bnc#1012382).

  - kvm: x86: fix escape of guest dr6 to the host
    (bnc#1012382).

  - kvm: X86: Fix operand/address-size during instruction
    decoding (bnc#1012382).

  - kvm: x86: ioapic: Clear Remote IRR when entry is
    switched to edge-triggered (bnc#1012382).

  - kvm: x86: ioapic: Fix level-triggered EOI and IOAPIC
    reconfigure race (bnc#1012382).

  - kvm: x86: ioapic: Preserve read-only values in the
    redirection table (bnc#1012382).

  - kvm: x86: Make indirect calls in emulator speculation
    safe (bnc#1012382).

  - kvm/x86: Reduce retpoline performance impact in
    slot_handle_level_range(), by always inlining iterator
    helper methods (bnc#1012382).

  - l2tp: fix use-after-free during module unload
    (bsc#1042286).

  - led: core: Fix brightness setting when setting
    delay_off=0 (bnc#1012382).

  - leds: do not overflow sysfs buffer in led_trigger_show
    (bsc#1080464).

  - libceph: check kstrndup() return value (bsc#1081735).

  - lib/mpi: Fix umul_ppmm() for MIPS64r6 (bnc#1012382).

  - lib/uuid.c: introduce a few more generic helpers
    (fate#315887, bsc#1082632).

  - lib/uuid.c: use correct offset in uuid parser
    (fate#315887, bsc#1082632).

  - livepatch: introduce shadow variable API (bsc#1082299
    fate#313296). Shadow variables support.

  - livepatch: __kgr_shadow_get_or_alloc() is local to
    shadow.c (bsc#1082299 fate#313296). Shadow variables
    support.

  - lockd: fix 'list_add double add' caused by legacy signal
    interface (bnc#1012382).

  - loop: fix concurrent lo_open/lo_release (bnc#1012382).

  - mac80211: fix the update of path metric for RANN frame
    (bnc#1012382).

  - mac80211: mesh: drop frames appearing to be from us
    (bnc#1012382).

  - Make DST_CACHE a silent config option (bnc#1012382).

  - mdio-sun4i: Fix a memory leak (bnc#1012382).

  - md/raid1: Use a new variable to count flighting sync
    requests(bsc#1083048)

  - media: cxusb, dib0700: ignore XC2028_I2C_FLUSH
    (bnc#1012382).

  - media: dvb-usb-v2: lmedm04: Improve logic checking of
    warm start (bnc#1012382).

  - media: dvb-usb-v2: lmedm04: move ts2020 attach to
    dm04_lme2510_tuner (bnc#1012382).

  - media: r820t: fix r820t_write_reg for KASAN
    (bnc#1012382).

  - media: s5k6aa: describe some function parameters
    (bnc#1012382).

  - media: soc_camera: soc_scale_crop: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bnc#1012382).

  - media: ts2020: avoid integer overflows on 32 bit
    machines (bnc#1012382).

  - media: usbtv: add a new usbid (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: add missing
    VIDIOC_PREPARE_BUF (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: avoid sizeof(type)
    (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: copy clip list in
    put_v4l2_window32 (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: copy m.userptr in
    put_v4l2_plane32 (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: do not copy back the
    result for certain errors (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: drop pr_info for unknown
    buffer type (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: fix ctrl_is_pointer
    (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: fix the indentation
    (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: make ctrl_is_pointer work
    for subdevs (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: move 'helper' functions to
    __get/put_v4l2_format32 (bnc#1012382).

  - media: v4l2-compat-ioctl32: Copy
    v4l2_window->global_alpha (bnc#1012382).

  - media: v4l2-compat-ioctl32.c: refactor compat ioctl32
    logic (bnc#1012382).

  - media: v4l2-ioctl.c: do not copy back the result for
    -ENOTTY (bnc#1012382).

  - MIPS: Implement __multi3 for GCC7 MIPS64r6 builds
    (bnc#1012382).

  - mmc: bcm2835: Do not overwrite max frequency
    unconditionally (bsc#983145, git-fixes).

  - mm/early_ioremap: Fix boot hang with
    earlyprintk=efi,keep (bnc#1012382).

  - mm: hide a #warning for COMPILE_TEST (bnc#1012382).

  - mm/kmemleak.c: make cond_resched() rate-limiting more
    efficient (git-fixes).

  - mm: pin address_space before dereferencing it while
    isolating an LRU page (bnc#1081500).

  - mm,vmscan: Make unregister_shrinker() no-op if
    register_shrinker() failed (bnc#1012382).

  - mn10300/misalignment: Use SIGSEGV SEGV_MAPERR to report
    a failed user copy (bnc#1012382).

  - modsign: hide openssl output in silent builds
    (bnc#1012382).

  - module/retpoline: Warn about missing retpoline in module
    (bnc#1012382).

  - mpt3sas: Do not mark fw_event workqueue as
    WQ_MEM_RECLAIM (bsc#1078583).

  - mptfusion: hide unused seq_mpt_print_ioc_summary
    function (bnc#1012382).

  - mtd: cfi: convert inline functions to macros
    (bnc#1012382).

  - mtd: cfi: enforce valid geometry configuration
    (bnc#1012382).

  - mtd: ichxrom: maybe-uninitialized with gcc-4.9
    (bnc#1012382).

  - mtd: maps: add __init attribute (bnc#1012382).

  - mtd: nand: brcmnand: Disable prefetch by default
    (bnc#1012382).

  - mtd: nand: denali_pci: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bnc#1012382).

  - mtd: nand: Fix nand_do_read_oob() return value
    (bnc#1012382).

  - mtd: nand: gpmi: Fix failure when a erased page has a
    bitflip at BBM (bnc#1012382).

  - mtd: nand: sunxi: Fix ECC strength choice (bnc#1012382).

  - mtd: sh_flctl: pass FIFO as physical address
    (bnc#1012382).

  - mvpp2: fix multicast address filter (bnc#1012382).

  - ncpfs: fix unused variable warning (bnc#1012382).

  - ncr5380: shut up gcc indentation warning (bnc#1012382).

  - net: add dst_cache support (bnc#1012382).

  - net: arc_emac: fix arc_emac_rx() error paths
    (bnc#1012382).

  - net: avoid skb_warn_bad_offload on IS_ERR (bnc#1012382).

  - net: cdc_ncm: initialize drvflags before usage
    (bnc#1012382).

  - net: dst_cache_per_cpu_dst_set() can be static
    (bnc#1012382).

  - net: ena: add detection and recovery mechanism for
    handling missed/misrouted MSI-X (bsc#1083548).

  - net: ena: add new admin define for future support of
    IPv6 RSS (bsc#1083548).

  - net: ena: add power management ops to the ENA driver
    (bsc#1083548).

  - net: ena: add statistics for missed tx packets
    (bsc#1083548).

  - net: ena: fix error handling in ena_down() sequence
    (bsc#1083548).

  - net: ena: fix race condition between device reset and
    link up setup (bsc#1083548).

  - net: ena: fix rare kernel crash when bar memory remap
    fails (bsc#1083548).

  - net: ena: fix wrong max Tx/Rx queues on ethtool
    (bsc#1083548).

  - net: ena: improve ENA driver boot time (bsc#1083548).

  - net: ena: increase ena driver version to 1.3.0
    (bsc#1083548).

  - net: ena: increase ena driver version to 1.5.0
    (bsc#1083548).

  - net: ena: reduce the severity of some printouts
    (bsc#1083548).

  - net: ena: remove legacy suspend suspend/resume support
    (bsc#1083548).

  - net: ena: Remove redundant unlikely() (bsc#1083548).

  - net: ena: unmask MSI-X only after device initialization
    is completed (bsc#1083548).

  - net: ethernet: cavium: Correct Cavium Thunderx NIC
    driver names accordingly to module name (bsc#1085011).

  - net: ethernet: xilinx: Mark XILINX_LL_TEMAC broken on
    64-bit (bnc#1012382).

  - net: ethtool: Add back transceiver type (bsc#1085050).

  - net: ethtool: remove error check for legacy setting
    transceiver type (bsc#1085050).

  - netfilter: drop outermost socket lock in getsockopt()
    (bnc#1012382).

  - netfilter: ebtables: CONFIG_COMPAT: do not trust
    userland offsets (bsc#1085107).

  - netfilter: ebtables: fix erroneous reject of last rule
    (bsc#1085107).

  - netfilter: ipt_CLUSTERIP: fix out-of-bounds accesses in
    clusterip_tg_check() (bnc#1012382).

  - netfilter: ipvs: avoid unused variable warnings
    (bnc#1012382).

  - netfilter: nf_queue: Make the queue_handler pernet
    (bnc#1012382).

  - netfilter: nf_tables: fix a wrong check to skip the
    inactive rules (bsc#1042286).

  - netfilter: nf_tables: fix inconsistent element
    expiration calculation (bsc#1042286).

  - netfilter: nf_tables: fix *leak* when expr clone fail
    (bsc#1042286).

  - netfilter: nf_tables: fix race when create new element
    in dynset (bsc#1042286).

  - netfilter: on sockopt() acquire sock lock only in the
    required scope (bnc#1012382).

  - netfilter: tee: select NF_DUP_IPV6 unconditionally
    (bsc#1042286).

  - netfilter: x_tables: avoid out-of-bounds reads in
    xt_request_find_(match|target) (bnc#1012382).

  - netfilter: x_tables: fix int overflow in
    xt_alloc_table_info() (bnc#1012382).

  - netfilter: xt_RATEEST: acquire xt_rateest_mutex for hash
    insert (bnc#1012382).

  - netfilter: xt_socket: fix transparent match for IPv6
    request sockets (bsc#1042286).

  - net: gianfar_ptp: move set_fipers() to spinlock
    protecting area (bnc#1012382).

  - net: hns: add ACPI mode support for ethtool -p
    (bsc#1084041).

  - net: hp100: remove unnecessary #ifdefs (bnc#1012382).

  - net: igmp: add a missing rcu locking section
    (bnc#1012382).

  - net/ipv4: Introduce IPSKB_FRAG_SEGS bit to
    inet_skb_parm.flags (bsc#1042286).

  - netlink: fix nla_put_(u8,u16,u32) for KASAN
    (bnc#1012382).

  - net/mlx5e: Fix loopback self test when GRO is off
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5e: Fix wrong delay calculation for overflow
    check scheduling (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5e: Verify inline header size do not exceed SKB
    linear size (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5: Use 128B cacheline size for 128B or larger
    cachelines (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net: phy: Keep reporting transceiver type (bsc#1085050).

  - net: replace dst_cache ip6_tunnel implementation with
    the generic one (bnc#1012382).

  - net_sched: red: Avoid devision by zero (bnc#1012382).

  - net_sched: red: Avoid illegal values (bnc#1012382).

  - net/smc: fix NULL pointer dereference on
    sock_create_kern() error path (bsc#1082979).

  - netvsc: allow controlling send/recv buffer size
    (fate#315887, bsc#1082632).

  - netvsc: allow driver to be removed even if VF is present
    (fate#315887, bsc#1082632).

  - netvsc: check error return when restoring channels and
    mtu (fate#315887, bsc#1082632).

  - netvsc: cleanup datapath switch (fate#315887,
    bsc#1082632).

  - netvsc: do not signal host twice if empty (fate#315887,
    bsc#1082632).

  - netvsc: fix deadlock betwen link status and removal
    (fate#315887, bsc#1082632).

  - netvsc: increase default receive buffer size
    (fate#315887, bsc#1082632).

  - netvsc: keep track of some non-fatal overload conditions
    (fate#315887, bsc#1082632).

  - netvsc: no need to allocate send/receive on numa node
    (fate#315887, bsc#1082632).

  - netvsc: propagate MAC address change to VF slave
    (fate#315887, bsc#1082632).

  - netvsc: remove unnecessary cast of void pointer
    (fate#315887, bsc#1082632).

  - netvsc: remove unnecessary check for NULL hdr
    (fate#315887, bsc#1082632).

  - netvsc: whitespace cleanup (fate#315887, bsc#1082632).

  - net: vxlan: lwt: Fix vxlan local traffic (bsc#1042286).

  - net: vxlan: lwt: Use source ip address during route
    lookup (bsc#1042286).

  - NFS: commit direct writes even if they fail partially
    (bnc#1012382).

  - nfsd: check for use of the closed special stateid
    (bnc#1012382).

  - nfsd: CLOSE SHOULD return the invalid special stateid
    for NFSv4.x (x>0) (bnc#1012382).

  - nfsd: Ensure we check stateid validity in the seqid
    operation checks (bnc#1012382).

  - nfs: Do not convert nfs_idmap_cache_timeout to jiffies
    (git-fixes).

  - nfs: fix a deadlock in nfs client initialization
    (bsc#1074198).

  - nfs/pnfs: fix nfs_direct_req ref leak when i/o falls
    back to the mds (bnc#1012382).

  - NFS: reject request for id_legacy key without auxdata
    (bnc#1012382).

  - NFS: Trunking detection should handle ERESTARTSYS/EINTR
    (bsc#1074198).

  - nvme_fc: cleanup io completion (bsc#1079609).

  - nvme_fc: correct abort race condition on resets
    (bsc#1079609).

  - nvme_fc: fix abort race on teardown with lld reject
    (bsc#1083750).

  - nvme_fc: fix ctrl create failures racing with workq
    items (bsc#1076982).

  - nvme_fc: io timeout should defer abort to ctrl reset
    (bsc#1085054).

  - nvme-fc: kick admin requeue list on disconnect
    (bsc#1077241).

  - nvme_fc: minor fixes on sqsize (bsc#1076760).

  - nvme_fc: on remoteport reuse, set new nport_id and role
    (bsc#1076760).

  - nvme_fc: rework sqsize handling (bsc#1076760).

  - nvme: Fix managing degraded controllers (bnc#1012382).

  - nvme: Fix setting logical block format when revalidating
    (bsc#1079313).

  - nvme: only start KATO if the controller is live
    (bsc#1083387).

  - nvme-pci: clean up CMB initialization (bsc#1082979).

  - nvme-pci: clean up SMBSZ bit definitions (bsc#1082979).

  - nvme-pci: consistencly use ctrl->device for logging
    (bsc#1082979).

  - nvme-pci: fix typos in comments (bsc#1082979).

  - nvme-pci: Remap CMB SQ entries on every controller reset
    (bsc#1082979).

  - nvme-pci: Use PCI bus address for data/queues in CMB
    (bsc#1082979).

  - nvme: Quirks for PM1725 controllers (bsc#1082979).

  - nvme_rdma: clear NVME_RDMA_Q_LIVE bit if reconnect fails
    (bsc#1083770).

  - nvme-rdma: fix concurrent reset and reconnect
    (bsc#1082979).

  - nvme: remove nvme_revalidate_ns (bsc#1079313).

  - ocfs2: return error when we attempt to access a dirty bh
    in jbd2 (bsc#1070404).

  - openvswitch: fix the incorrect flow action alloc size
    (bnc#1012382).

  - ovl: fix failure to fsync lower dir (bnc#1012382).

  - ovs/geneve: fix rtnl notifications on iface deletion
    (bsc#1042286).

  - ovs/gre: fix rtnl notifications on iface deletion
    (bsc#1042286).

  - ovs/gre,geneve: fix error path when creating an iface
    (bsc#1042286).

  - ovs/vxlan: fix rtnl notifications on iface deletion
    (bsc#1042286).

  - PCI/ASPM: Do not retrain link if ASPM not possible
    (bnc#1071892).

  - PCI: hv: Do not sleep in compose_msi_msg() (fate#315887,
    bsc#1082632).

  - PCI: keystone: Fix interrupt-controller-node lookup
    (bnc#1012382).

  - PCI/MSI: Fix msi_desc->affinity memory leak when freeing
    MSI IRQs (bsc#1082979).

  - perf bench numa: Fixup discontiguous/sparse numa nodes
    (bnc#1012382).

  - perf top: Fix window dimensions change handling
    (bnc#1012382).

  - perf/x86: Shut up false-positive -Wmaybe-uninitialized
    warning (bnc#1012382).

  - pinctrl: sunxi: Fix A80 interrupt pin bank
    (bnc#1012382).

  - pktcdvd: Fix pkt_setup_dev() error path (bnc#1012382).

  - platform/x86: intel_mid_thermal: Fix suspend handlers
    unused warning (bnc#1012382).

  - PM / devfreq: Propagate error from devfreq_add_device()
    (bnc#1012382).

  - PM / wakeirq: Fix unbalanced IRQ enable for wakeirq
    (bsc#1031717).

  - posix-timer: Properly check sigevent->sigev_notify
    (bnc#1012382).

  - power: bq27xxx_battery: mark some symbols __maybe_unused
    (bnc#1012382).

  - powerpc/64: Fix flush_(d|i)cache_range() called from
    modules (FATE#315275 LTC#103998 bnc#1012382 bnc#863764).

  - powerpc/64s: Fix RFI flush dependency on
    HARDLOCKUP_DETECTOR (bnc#1012382).

  - powerpc/64s: Improve RFI L1-D cache flush fallback
    (bsc#1068032, bsc#1075087).

  - powerpc: Do not preempt_disable() in show_cpuinfo()
    (bsc#1066223).

  - powerpc/numa: Ensure nodes initialized for hotplug
    (FATE#322022, bsc#1081514).

  - powerpc/numa: Invalidate numa_cpu_lookup_table on cpu
    remove (bsc#1081512).

  - powerpc/numa: Use ibm,max-associativity-domains to
    discover possible nodes (FATE#322022, bsc#1081514).

  - powerpc/perf: Fix oops when grouping different pmu
    events (bnc#1012382).

  - powerpc/powernv: Fix MCE handler to avoid trashing
    CR0/CR1 registers (bsc#1066223).

  - powerpc/powernv: Move IDLE_STATE_ENTER_SEQ macro to
    cpuidle.h (bsc#1066223).

  - powerpc/powernv: Support firmware disable of RFI flush
    (bsc#1068032, bsc#1075087).

  - powerpc/pseries: Fix cpu hotplug crash with memoryless
    nodes (FATE#322022, bsc#1081514).

  - powerpc/pseries: Support firmware disable of RFI flush
    (bsc#1068032, bsc#1075087).

  - powerpc: Simplify module TOC handling (bnc#1012382).

  - power: reset: zx-reboot: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bnc#1012382).

  - profile: hide unused functions when !CONFIG_PROC_FS
    (bnc#1012382).

  - Provide a function to create a NUL-terminated string
    from unterminated data (bnc#1012382).

  - pwc: hide unused label (bnc#1012382).

  - qla2xxx: Add changes for devloss timeout in driver
    (bsc#1084427).

  - qla2xxx: Add FC-NVMe abort processing (bsc#1084427).

  - qla2xxx: asynchronous pci probing (bsc#1034503).

  - qla2xxx: Cleanup code to improve FC-NVMe error handling
    (bsc#1084427).

  - qla2xxx: Convert QLA_TGT_ABTS to
    TARGET_SCF_LOOKUP_LUN_FROM_TAG
    (bsc#1043726,FATE#324770).

  - qla2xxx: do not check login_state if no loop id is
    assigned (bsc#1081681).

  - qla2xxx: ensure async flags are reset correctly
    (bsc#1081681).

  - qla2xxx: Fix Async GPN_FT for FCP and FC-NVMe scan
    (bsc#1084427).

  - qla2xxx: Fix FC-NVMe IO abort during driver reset
    (bsc#1084427).

  - qla2xxx: Fix incorrect tcm_qla2xxx_free_cmd use during
    TMR ABORT (v2) (bsc#1043726,FATE#324770).

  - qla2xxx: Fix n2n_ae flag to prevent dev_loss on PDB
    change (bsc#1084427).

  - qla2xxx: Fix NVMe entry_type for iocb packet on BE
    system (bsc#1043726,FATE#324770).

  - qla2xxx: Fix retry for PRLI RJT with reason of BUSY
    (bsc#1084427).

  - qla2xxx: Fixup locking for session deletion
    (bsc#1081681).

  - qla2xxx: Remove nvme_done_list (bsc#1084427).

  - qla2xxx: Remove unneeded message and minor cleanup for
    FC-NVMe (bsc#1084427).

  - qla2xxx: remove use of FC-specific error codes
    (bsc#1043726,FATE#324770).

  - qla2xxx: Restore ZIO threshold setting (bsc#1084427).

  - qla2xxx: Return busy if rport going away (bsc#1084427).

  - qla2xxx: Set IIDMA and fcport state before
    qla_nvme_register_remote() (bsc#1084427).

  - qla2xxx: Update driver version to 10.00.00.06-k
    (bsc#1084427).

  - qlax2xxx: Drop SUSE-specific qla2xxx patches
    (bsc#1043726)

  - qlcnic: fix deadlock bug (bnc#1012382).

  - r8169: fix RTL8168EP take too long to complete driver
    initialization (bnc#1012382).

  - RDMA/cma: Make sure that PSN is not over max allowed
    (bnc#1012382).

  - RDMA/uverbs: Protect from command mask overflow
    (bsc#1082979).

  - reiserfs: avoid a -Wmaybe-uninitialized warning
    (bnc#1012382).

  - Revert 'Bluetooth: btusb: fix QCA Rome suspend/resume'
    (bnc#1012382).

  - Revert 'bpf: avoid false sharing of map refcount with
    max_entries' (kabi).

  - Revert 'netfilter: nf_queue: Make the queue_handler
    pernet' (kabi).

  - Revert 'net: replace dst_cache ip6_tunnel implementation
    with the generic one' (kabi bnc#1082897).

  - Revert 'power: bq27xxx_battery: Remove unneeded
    dependency in Kconfig' (bnc#1012382).

  - Revert 'powerpc: Simplify module TOC handling' (kabi).

  - Revert SUSE-specific qla2xxx patch 'Add module parameter
    for interrupt mode' (bsc#1043726)

  - Revert 'x86/entry/64: Separate cpu_current_top_of_stack
    from TSS.sp0' 

  - Revert 'x86/entry/64: Use a per-CPU trampoline stack for
    IDT entries' 

  - rfi-flush: Move the logic to avoid a redo into the
    debugfs code (bsc#1068032, bsc#1075087).

  - rfi-flush: Switch to new linear fallback flush
    (bsc#1068032, bsc#1075087).

  - rhashtable: add rhashtable_lookup_get_insert_key()
    (bsc#1042286).

  - rtc-opal: Fix handling of firmware error codes, prevent
    busy loops (bnc#1012382).

  - rtlwifi: fix gcc-6 indentation warning (bnc#1012382).

  - rtlwifi: rtl8821ae: Fix connection lost problem
    correctly (bnc#1012382).

  - s390: add no-execute support (FATE#324087, LTC#158827).

  - s390/dasd: fix handling of internal requests
    (bsc#1080321).

  - s390/dasd: fix wrongly assigned configuration data
    (bnc#1012382).

  - s390/dasd: prevent prefix I/O error (bnc#1012382).

  - s390: fix handling of -1 in set(,fs)[gu]id16 syscalls
    (bnc#1012382).

  - s390: hypfs: Move diag implementation and data
    definitions (FATE#324070, LTC#158959).

  - s390: kvm: Cpu model support for msa6, msa7 and msa8
    (FATE#324069, LTC#159031).

  - s390: Make cpc_name accessible (FATE#324070,
    LTC#158959).

  - s390: Make diag224 public (FATE#324070, LTC#158959).

  - s390/mem_detect: use unsigned longs (FATE#324071,
    LTC#158956).

  - s390/mm: align swapper_pg_dir to 16k (FATE#324087,
    LTC#158827).

  - s390/mm: always use PAGE_KERNEL when mapping pages
    (FATE#324087, LTC#158827).

  - s390/noexec: execute kexec datamover without DAT
    (FATE#324087, LTC#158827).

  - s390/oprofile: fix address range for asynchronous stack
    (bsc#1082979).

  - s390/pageattr: allow kernel page table splitting
    (FATE#324087, LTC#158827).

  - s390/pageattr: avoid unnecessary page table splitting
    (FATE#324087, LTC#158827).

  - s390/pageattr: handle numpages parameter correctly
    (FATE#324087, LTC#158827).

  - s390/pci_dma: improve lazy flush for unmap (bnc#1079886,
    LTC#163393).

  - s390/pci_dma: improve map_sg (bnc#1079886, LTC#163393).

  - s390/pci_dma: make lazy flush independent from the
    tlb_refresh bit (bnc#1079886, LTC#163393).

  - s390/pci_dma: remove dma address range check
    (bnc#1079886, LTC#163393).

  - s390/pci_dma: simplify dma address calculation
    (bnc#1079886, LTC#163393).

  - s390/pci_dma: split dma_update_trans (bnc#1079886,
    LTC#163393).

  - s390/pci: fix dma address calculation in map_sg
    (bnc#1079886, LTC#163393).

  - s390/pci: handle insufficient resources during dma tlb
    flush (bnc#1079886, LTC#163393).

  - s390/pgtable: introduce and use generic csp inline asm
    (FATE#324087, LTC#158827).

  - s390/pgtable: make pmd and pud helper functions
    available (FATE#324087, LTC#158827).

  - s390/qeth: fix underestimated count of buffer elements
    (bnc#1082089, LTC#164529).

  - s390: report new vector facilities (FATE#324088,
    LTC#158828).

  - s390/sclp: Add hmfai field (FATE#324071, LTC#158956).

  - s390/vmem: align segment and region tables to 16k
    (FATE#324087, LTC#158827).

  - s390/vmem: introduce and use SEGMENT_KERNEL and
    REGION3_KERNEL (FATE#324087, LTC#158827).

  - s390/vmem: simplify vmem code for read-only mappings
    (FATE#324087, LTC#158827).

  - sched/rt: Up the root domain ref count when passing it
    around via IPIs (bnc#1012382).

  - sched/rt: Use container_of() to get root domain in
    rto_push_irq_work_func() (bnc#1012382).

  - scripts/kernel-doc: Do not fail with status != 0 if
    error encountered with -none (bnc#1012382).

  - scsi: aacraid: Fix hang in kdump (bsc#1022607,
    FATE#321673).

  - scsi: aacraid: Prevent crash in case of free interrupt
    during scsi EH path (bnc#1012382).

  - scsi: advansys: fix build warning for PCI=n
    (bnc#1012382).

  - scsi: advansys: fix uninitialized data access
    (bnc#1012382).

  - scsi: do not look for NULL devices handlers by name
    (bsc#1082373).

  - scsi: fas216: fix sense buffer initialization
    (bsc#1082979).

  - scsi: fdomain: drop fdomain_pci_tbl when built-in
    (bnc#1012382).

  - scsi: hisi_sas: directly attached disk LED feature for
    v2 hw (bsc#1083409).

  - scsi: ibmvfc: fix misdefined reserved field in
    ibmvfc_fcp_rsp_info (bnc#1012382).

  - SCSI: initio: remove duplicate module device table
    (bnc#1012382 bsc#1082979).

  - SCSI: initio: remove duplicate module device table
    (bsc#1082979).

  - scsi: libsas: fix error when getting phy events
    (bsc#1082979).

  - scsi: libsas: fix memory leak in
    sas_smp_get_phy_events() (bsc#1082979).

  - scsi: lpfc: Add WQ Full Logic for NVME Target
    (bsc#1080656).

  - scsi: lpfc: Allow set of maximum outstanding SCSI cmd
    limit for a target (bsc#1080656).

  - scsi: lpfc: Beef up stat counters for debug
    (bsc#1076693).

  - scsi: lpfc: correct debug counters for abort
    (bsc#1080656).

  - scsi: lpfc: do not dereference localport before it has
    been null checked (bsc#1076693).

  - scsi: lpfc: Do not return internal MBXERR_ERROR code
    from probe function (bsc#1082979).

  - scsi: lpfc: fix a couple of minor indentation issues
    (bsc#1076693).

  - scsi: lpfc: Fix -EOVERFLOW behavior for NVMET and
    defer_rcv (bsc#1076693).

  - scsi: lpfc: Fix header inclusion in lpfc_nvmet
    (bsc#1080656).

  - scsi: lpfc: Fix infinite wait when driver unregisters a
    remote NVME port (bsc#1076693).

  - scsi: lpfc: Fix IO failure during hba reset testing with
    nvme io (bsc#1080656).

  - scsi: lpfc: Fix issue_lip if link is disabled
    (bsc#1080656).

  - scsi: lpfc: Fix issues connecting with nvme initiator
    (bsc#1076693).

  - scsi: lpfc: Fix nonrecovery of NVME controller after
    cable swap (bsc#1080656).

  - scsi: lpfc: Fix PRLI handling when topology type changes
    (bsc#1080656).

  - scsi: lpfc: Fix receive PRLI handling (bsc#1076693).

  - scsi: lpfc: Fix RQ empty firmware trap (bsc#1080656).

  - scsi: lpfc: Fix SCSI io host reset causing kernel crash
    (bsc#1080656).

  - scsi: lpfc: Fix SCSI LUN discovery when SCSI and NVME
    enabled (bsc#1076693).

  - scsi: lpfc: Fix soft lockup in lpfc worker thread during
    LIP testing (bsc#1080656).

  - scsi: lpfc: Increase CQ and WQ sizes for SCSI
    (bsc#1080656).

  - scsi: lpfc: Increase SCSI CQ and WQ sizes (bsc#1076693).

  - scsi: lpfc: Indicate CONF support in NVMe PRLI
    (bsc#1080656).

  - scsi: lpfc: move placement of target destroy on driver
    detach (bsc#1080656).

  - scsi: lpfc: Treat SCSI Write operation Underruns as an
    error (bsc#1080656).

  - scsi: lpfc: Update 11.4.0.7 modified files for 2018
    Copyright (bsc#1080656).

  - scsi: lpfc: update driver version to 11.4.0.6
    (bsc#1076693).

  - scsi: lpfc: update driver version to 11.4.0.7
    (bsc#1080656).

  - scsi: lpfc: Validate adapter support for SRIU option
    (bsc#1080656).

  - scsi: mvumi: use __maybe_unused to hide pm functions
    (bnc#1012382).

  - scsi: qla2xxx: Ability to process multiple SGEs in
    Command SGL for CT passthrough commands
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Accelerate SCSI BUSY status generation in
    target mode (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Add ability to autodetect SFP type
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add ability to send PRLO
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add ability to use GPNFT/GNNFT for RSCN
    handling (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add ATIO-Q processing for INTx mode
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add boundary checks for exchanges to be
    offloaded (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add command completion for error path
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add debug knob for user control workload
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Add debug logging routine for qpair
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Added change to enable ZIO for FC-NVMe
    devices (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add FC-NVMe command handling
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add FC-NVMe F/W initialization and
    transport registration (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add FC-NVMe port discovery and PRLI
    handling (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add function call to qpair for door bell
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Add fw_started flags to qpair
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Add lock protection around host lookup
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add LR distance support from nvram bit
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: add missing includes for qla_isr
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add option for use reserve exch for ELS
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add ql2xiniexchg parameter
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Add retry limit for fabric scan logic
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add support for minimum link speed
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add switch command to simplify fabric
    discovery (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add timeout ability to
    wait_for_sess_deletion() (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Add XCB counters to debugfs
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Allow ABTS, PURX, RIDA on ATIOQ for
    ISP83XX/27XX (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Allow MBC_GET_PORT_DATABASE to query and
    save the port states (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Allow relogin and session creation after
    reset (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Allow SNS fabric login to be retried
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Allow target mode to accept PRLI in dual
    mode (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: avoid unused-function warning
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Change ha->wq max_active value to default
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Changes to support N2N logins
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Chip reset uses wrong lock during IO
    flush (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Cleanup FC-NVMe code
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Cleanup NPIV host in target mode during
    config teardown (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Clear fc4f_nvme flag
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Clear loop id after delete
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Combine Active command arrays
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Convert 32-bit LUN usage to 64-bit
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Defer processing of GS IOCB calls
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Delay loop id allocation at login
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Do not call abort handler function during
    chip reset (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Do not call dma_free_coherent with IRQ
    disabled (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: do not include <generated/utsrelease.h>
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Enable Async TMF processing
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Enable ATIO interrupt handshake for
    ISP27XX (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Enable Target Multi Queue
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Fix abort command deadlock due to
    spinlock (FATE#320146, bsc#966328).

  - scsi: qla2xxx: fix a bunch of typos and spelling
    mistakes (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix a locking imbalance in
    qlt_24xx_handle_els() (bsc#1082979).

  - scsi: qla2xxx: Fix compile warning
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Fix FC-NVMe LUN discovery (bsc#1083223).

  - scsi: qla2xxx: Fix Firmware dump size for Extended login
    and Exchange Offload (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix GPNFT/GNNFT error handling
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix gpnid error processing
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix incorrect handle for abort IOCB
    (bsc#1082979).

  - scsi: qla2xxx: Fix login state machine freeze
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix login state machine stuck at GPDB
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix logo flag for qlt_free_session_done()
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix mailbox failure while deleting Queue
    pairs (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Fix memory leak in dual/target mode
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix NPIV host cleanup in target mode
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix NPIV host enable after chip reset
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix NULL pointer access for fcport
    structure (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix NULL pointer crash due to active
    timer for ABTS (bsc#1082979).

  - scsi: qla2xxx: Fix NULL pointer crash due to probe
    failure (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix oops in qla2x00_probe_one error path
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix PRLI state check
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix queue ID for async abort with
    Multiqueue (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix recursion while sending terminate
    exchange (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix Relogin being triggered too fast
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix re-login for Nport Handle in use
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix remoteport disconnect for FC-NVMe
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix scan state field for fcport
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix session cleanup for N2N
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix slow mem alloc behind lock
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix smatch warning in
    qla25xx_delete_(rsp|req)_que (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: fix spelling mistake of variable
    sfp_additonal_info (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix system crash for Notify ack timeout
    handling (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix system crash in qlt_plogi_ack_unref
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix system crash while triggering FW dump
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix system panic due to pointer access
    problem (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix target multiqueue configuration
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix task mgmt handling for NPIV
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix warning during port_name debug print
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix warning for code intentation in
    __qla24xx_handle_gpdb_event() (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix warning in
    qla2x00_async_iocb_timeout() (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Fix WWPN/WWNN in debug message
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Handle PCIe error for driver
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Include Exchange offload/Extended Login
    into FW dump (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Increase ql2xmaxqdepth to 64
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Increase verbosity of debug messages
    logged (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Migrate switch registration commands away
    from mailbox interface (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: move fields from qla_hw_data to qla_qpair
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Move function prototype to correct header
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Move logging default mask to execute once
    only (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Move session delete to driver work queue
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Move target stat counters from vha to
    qpair (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Move work element processing out of DPC
    thread (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Off by one in qlt_ctio_to_cmd()
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Preparation for Target MQ
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Prevent multiple active discovery
    commands per session (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Prevent relogin trigger from sending too
    many commands (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Prevent sp->free null/uninitialized
    pointer dereference (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Print correct mailbox registers in failed
    summary (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Properly extract ADISC error codes
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Protect access to qpair members with
    qpair->qp_lock (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Query FC4 type during RSCN processing
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Recheck session state after RSCN
    (bsc#1043726,FATE#324770)

  - scsi: qla2xxx: Reduce the use of terminate exchange
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Reduce trace noise for Async Events
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Reinstate module parameter ql2xenablemsix
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Relogin to target port on a cable swap
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Remove aborting ELS IOCB call issued as
    part of timeout (FATE#320146, bsc#966328).

  - scsi: qla2xxx: Remove an unused structure member
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Remove datasegs_per_cmd and
    datasegs_per_cont field (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Remove extra register read
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Remove extra register read
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Remove FC_NO_LOOP_ID for FCP and FC-NVMe
    Discovery (bsc#1084397).

  - scsi: qla2xxx: Remove potential macro parameter
    side-effect in ql_dump_regs() (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: remove redundant assignment of d
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: remove redundant null check on tgt
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Remove redundant wait when target is
    stopped (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Remove session creation redundant code
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Remove unused argument from
    qlt_schedule_sess_for_deletion()
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Remove unused irq_cmd_count field
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Remove unused tgt_enable_64bit_addr flag
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: remove writeq/readq function definitions
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Replace fcport alloc with
    qla2x00_alloc_fcport (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Replace GPDB with async ADISC command
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Reset the logo flag, after target
    re-login (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Retry switch command on time out
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Send FC4 type NVMe to the management
    server (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Serialize GPNID for multiple RSCN
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Serialize session deletion by using
    work_lock (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Serialize session free in
    qlt_free_session_done (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Simpify unregistration of FC-NVMe
    local/remote ports (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Skip IRQ affinity for Target QPairs
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Skip zero queue count entry during FW
    dump capture (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Suppress a kernel complaint in
    qla_init_base_qpair() (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Tweak resource count dump
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Update Driver version to 10.00.00.00-k
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Update driver version to 10.00.00.01-k
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Update driver version to 10.00.00.02-k
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Update driver version to 10.00.00.03-k
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Update driver version to 10.00.00.04-k
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Update driver version to 10.00.00.05-k
    (bsc#1081681).

  - scsi: qla2xxx: Update driver version to 9.01.00.00-k
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Update fw_started flags at qpair creation
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Use BIT_6 to acquire FAWWPN from switch
    (bsc#1043726,FATE#324770)

  - scsi: qla2xxx: Use chip reset to bring down laser on
    unload (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: use dma_mapping_error to check map errors
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Use FC-NVMe FC4 type for FDMI
    registration (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Use IOCB path to submit Control VP MBX
    command (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Use known NPort ID for Management Server
    login (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Use ql2xnvmeenable to enable Q-Pair for
    FC-NVMe (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: use shadow register for ISP27XX
    (bsc#1043725,FATE#324770).

  - scsi: qla2xxx: Use shadow register for ISP27XX
    (bsc#1043726,FATE#324770).

  - scsi: qla2xxx: Use sp->free instead of hard coded call
    (bsc#1043726,FATE#324770).

  - scsi: ses: do not get power status of SES device slot on
    probe (bsc#1082979).

  - scsi: sim710: fix build warning (bnc#1012382).

  - scsi: sr: workaround VMware ESXi cdrom emulation bug
    (bsc#1080813).

  - scsi: storvsc: Fix scsi_cmd error assignments in
    storvsc_handle_error (bnc#1012382).

  - scsi: storvsc: remove unnecessary channel inbound lock
    (fate#315887, bsc#1082632).

  - scsi: sun_esp: fix device reference leaks (bsc#1082979).

  - scsi: tcm_qla2xxx: Do not allow aborted cmd to advance
    (bsc#1043725,FATE#324770).

  - scsi: ufs: ufshcd: fix potential NULL pointer
    dereference in ufshcd_config_vreg (bnc#1012382).

  - sctp: make use of pre-calculated len (bnc#1012382).

  - selinux: ensure the context is NUL terminated in
    security_context_to_sid_core() (bnc#1012382).

  - selinux: general protection fault in sock_has_perm
    (bnc#1012382).

  - selinux: skip bounded transition processing if the
    policy isn't loaded (bnc#1012382).

  - serial: 8250_mid: fix broken DMA dependency
    (bnc#1012382).

  - serial: 8250_uniphier: fix error return code in
    uniphier_uart_probe() (bsc#1031717).

  - serial: imx: Only wakeup via RTSDEN bit if the system
    has RTS/CTS (bnc#1012382).

  - series.conf: disable qla2xxx patches (bsc#1043725)

  - sget(): handle failures of register_shrinker()
    (bnc#1012382).

  - signal/openrisc: Fix do_unaligned_access to send the
    proper signal (bnc#1012382).

  - signal/sh: Ensure si_signo is initialized in
    do_divide_error (bnc#1012382).

  - SolutionEngine771x: fix Ether platform data
    (bnc#1012382).

  - spi: atmel: fixed spin_lock usage inside
    atmel_spi_remove (bnc#1012382).

  - spi: imx: do not access registers while clocks disabled
    (bnc#1012382).

  - spi: sun4i: disable clocks in the remove function
    (bnc#1012382).

  - ssb: mark ssb_bus_register as __maybe_unused
    (bnc#1012382).

  - staging: android: ashmem: Fix a race condition in pin
    ioctls (bnc#1012382).

  - staging: iio: adc: ad7192: fix external frequency
    setting (bnc#1012382).

  - staging: rtl8188eu: Fix incorrect response to
    SIOCGIWESSID (bnc#1012382).

  - staging: ste_rmi4: avoid unused function warnings
    (bnc#1012382).

  - staging: unisys: visorinput depends on INPUT
    (bnc#1012382).

  - staging: wilc1000: fix kbuild test robot error
    (bnc#1012382).

  - SUNRPC: Allow connect to return EHOSTUNREACH
    (bnc#1012382).

  - target: Add support for TMR percpu reference counting
    (bsc#1043726,FATE#324770).

  - target: Add TARGET_SCF_LOOKUP_LUN_FROM_TAG support for
    ABORT_TASK (bsc#1043726,FATE#324770).

  - tc1100-wmi: fix build warning when CONFIG_PM not enabled
    (bnc#1012382).

  - tc358743: fix register i2c_rd/wr function fix
    (git-fixes).

  - tc358743: fix register i2c_rd/wr functions
    (bnc#1012382).

  - tcp: do not set rtt_min to 1 (bsc#1042286).

  - tcp: release sk_frag.page in tcp_disconnect
    (bnc#1012382).

  - test_bpf: fix the dummy skb after dissector changes
    (bsc#1042286).

  - tg3: Add workaround to restrict 5762 MRRS to 2048
    (bnc#1012382).

  - tg3: Enable PHY reset in MTU change path for 5720
    (bnc#1012382).

  - thermal: fix INTEL_SOC_DTS_IOSF_CORE dependencies
    (bnc#1012382).

  - thermal: spear: use __maybe_unused for PM functions
    (bnc#1012382).

  - tlan: avoid unused label with PCI=n (bnc#1012382).

  - tools build: Add tools tree support for 'make -s'
    (bnc#1012382).

  - tpm-dev-common: Reject too short writes (bsc#1020645,
    git-fixes).

  - tpm: fix potential buffer overruns caused by bit
    glitches on the bus (bsc#1020645, git-fixes).

  - tpm_i2c_infineon: fix potential buffer overruns caused
    by bit glitches on the bus (bsc#1020645, git-fixes).

  - tpm_i2c_nuvoton: fix potential buffer overruns caused by
    bit glitches on the bus (bsc#1020645, git-fixes).

  - tpm: st33zp24: fix potential buffer overruns caused by
    bit glitches on the bus (bsc#1020645, git-fixes).

  - tpm_tis: fix potential buffer overruns caused by bit
    glitches on the bus (bsc#1020645, git-fixes).

  - tty: cyclades: cyz_interrupt is only used for PCI
    (bnc#1012382).

  - tty: hvc_xen: hide xen_console_remove when unused
    (bnc#1012382).

  - tty: mxser: Remove ASYNC_CLOSING (bnc#1072363).

  - ubi: block: Fix locking for idr_alloc/idr_remove
    (bnc#1012382).

  - udp: restore UDPlite many-cast delivery (bsc#1042286).

  - usb: build drivers/usb/common/ when USB_SUPPORT is set
    (bnc#1012382).

  - USB: cdc-acm: Do not log urb submission errors on
    disconnect (bnc#1012382).

  - USB: cdc_subset: only build when one driver is enabled
    (bnc#1012382).

  - usb: dwc3: gadget: Set maxpacket size for ep0 IN
    (bnc#1012382).

  - usb: f_fs: Prevent gadget unbind if it is already
    unbound (bnc#1012382).

  - usb: gadget: do not dereference g until after it has
    been null checked (bnc#1012382).

  - usb: gadget: f_fs: Process all descriptors during bind
    (bnc#1012382).

  - usb: gadget: uvc: Missing files for configfs interface
    (bnc#1012382).

  - usbip: fix 3eee23c3ec14 tcp_socket address still in the
    status file (bnc#1012382).

  - usbip: keep usbip_device sockfd state in sync with
    tcp_socket (bnc#1012382).

  - usbip: list: do not list devices attached to vhci_hcd
    (bnc#1012382).

  - usbip: prevent bind loops on devices attached to
    vhci_hcd (bnc#1012382).

  - usbip: vhci_hcd: clear just the USB_PORT_STAT_POWER bit
    (bnc#1012382).

  - usb: ldusb: add PIDs for new CASSY devices supported by
    this driver (bnc#1012382).

  - usb: musb/ux500: remove duplicate check for
    dma_is_compatible (bnc#1012382).

  - usb: ohci: Proper handling of ed_rm_list to handle race
    condition between usb_kill_urb() and finish_unlinks()
    (bnc#1012382).

  - usb: option: Add support for FS040U modem (bnc#1012382).

  - usb: phy: msm add regulator dependency (bnc#1012382).

  - usb: renesas_usbhs: missed the 'running' flag in
    usb_dmac with rx path (bnc#1012382).

  - USB: serial: io_edgeport: fix possible sleep-in-atomic
    (bnc#1012382).

  - USB: serial: pl2303: new device id for Chilitag
    (bnc#1012382).

  - USB: serial: simple: add Motorola Tetra driver
    (bnc#1012382).

  - usb: uas: unconditionally bring back host after reset
    (bnc#1012382).

  - v4l: remove MEDIA_TUNER dependency for VIDEO_TUNER
    (bnc#1012382).

  - vb2: V4L2_BUF_FLAG_DONE is set after DQBUF
    (bnc#1012382).

  - vfs: do not do RCU lookup of empty pathnames
    (bnc#1012382).

  - vhost_net: stop device during reset owner (bnc#1012382).

  - video: fbdev: atmel_lcdfb: fix display-timings lookup
    (bnc#1012382).

  - video: fbdev/mmp: add MODULE_LICENSE (bnc#1012382).

  - video: fbdev: sis: remove unused variable (bnc#1012382).

  - video: fbdev: via: remove possibly unused variables
    (bnc#1012382).

  - video: Use bool instead int pointer for get_opt_bool()
    argument (bnc#1012382).

  - virtio_balloon: prevent uninitialized variable use
    (bnc#1012382).

  - vmbus: add per-channel sysfs info (fate#315887,
    bsc#1082632).

  - vmbus: add prefetch to ring buffer iterator
    (fate#315887, bsc#1082632).

  - vmbus: do not acquire the mutex in
    vmbus_hvsock_device_unregister() (fate#315887,
    bsc#1082632).

  - vmbus: drop unused ring_buffer_info elements
    (fate#315887, bsc#1082632).

  - vmbus: eliminate duplicate cached index (fate#315887,
    bsc#1082632).

  - vmbus: hvsock: add proper sync for
    vmbus_hvsock_device_unregister() (fate#315887,
    bsc#1082632).

  - vmbus: initialize reserved fields in messages
    (fate#315887, bsc#1082632).

  - vmbus: make channel_message table constant (fate#315887,
    bsc#1082632).

  - vmbus: more host signalling avoidance (fate#315887,
    bsc#1082632).

  - vmbus: refactor hv_signal_on_read (fate#315887,
    bsc#1082632).

  - vmbus: remove unused vmbus_sendpacket_ctl (fate#315887,
    bsc#1082632).

  - vmbus: remove unused vmbus_sendpacket_multipagebuffer
    (fate#315887, bsc#1082632).

  - vmbus: remove unused vmubs_sendpacket_pagebuffer_ctl
    (fate#315887, bsc#1082632).

  - vmbus: Reuse uuid_le_to_bin() helper (fate#315887,
    bsc#1082632).

  - vmbus: simplify hv_ringbuffer_read (fate#315887,
    bsc#1082632).

  - vmbus: unregister device_obj->channels_kset
    (fate#315887, bsc#1082632).

  - vmxnet3: prevent building with 64K pages (bnc#1012382).

  - vxlan: consolidate csum flag handling (bsc#1042286).

  - vxlan: consolidate output route calculation
    (bsc#1042286).

  - vxlan: consolidate vxlan_xmit_skb and vxlan6_xmit_skb
    (bsc#1042286).

  - vxlan: do not allow overwrite of config src addr
    (bsc#1042286).

  - watchdog: imx2_wdt: restore previous timeout after
    suspend+resume (bnc#1012382).

  - wireless: cw1200: use __maybe_unused to hide pm
    functions_ (bnc#1012382).

  - x86: add MULTIUSER dependency for KVM (bnc#1012382).

  - x86/asm: Fix inline asm call constraints for GCC 4.4
    (bnc#1012382).

  - x86/boot: Avoid warning for zero-filling .bss
    (bnc#1012382).

  - x86: bpf_jit: small optimization in emit_bpf_tail_call()
    (bnc#1012382).

  - x86/bugs: Drop one 'mitigation' from dmesg
    (bnc#1012382).

  - x86/build: Silence the build with 'make -s'
    (bnc#1012382).

  - x86/cpu/bugs: Make retpoline module warning conditional
    (bnc#1012382).

  - x86/cpu: Change type of x86_cache_size variable to
    unsigned int (bnc#1012382).

  - x86/entry/64: Separate cpu_current_top_of_stack from
    TSS.sp0 (bsc#1077560).

  - x86/entry/64: Use a per-CPU trampoline stack for IDT
    entries (bsc#1077560).

  - x86: fix build warnign with 32-bit PAE (bnc#1012382).

  - x86/fpu/math-emu: Fix possible uninitialized variable
    use (bnc#1012382).

  - x86/hyperv: Implement hv_get_tsc_page() (fate#315887,
    bsc#1082632).

  - x86/hyper-v: include hyperv/ only when CONFIG_HYPERV is
    set (fate#315887, bsc#1082632).

  - x86/hyper-v: Introduce fast hypercall implementation
    (fate#315887, bsc#1082632).

  - x86/hyper-v: Make hv_do_hypercall() inline (fate#315887,
    bsc#1082632).

  - x86/hyperv: Move TSC reading method to asm/mshyperv.h
    (fate#315887, bsc#1082632).

  - x86/kaiser: fix build error with KASAN &&
    !FUNCTION_GRAPH_TRACER (bnc#1012382).

  - x86/kvm/vmx: do not use vm-exit instruction length for
    fast MMIO when running nested (bsc#1081431).

  - x86/mce: Pin the timer when modifying
    (bsc#1080851,1076282).

  - x86/microcode/AMD: Change load_microcode_amd()'s param
    to bool to fix preemptibility bug (bnc#1012382).

  - x86/microcode/AMD: Do not load when running on a
    hypervisor (bnc#1012382).

  - x86/microcode/AMD: Do not load when running on a
    hypervisor (bsc#1081436 bsc#1081437).

  - x86/microcode: Do the family check first (bnc#1012382).

  - x86/microcode: Do the family check first (bsc#1081436
    bsc#1081437).

  - x86/mm/kmmio: Fix mmiotrace for page unaligned addresses
    (bnc#1012382).

  - x86/mm/pkeys: Fix fill_sig_info_pkey (fate#321300).

  - x86/nospec: Fix header guards names (bnc#1012382).

  - x86/oprofile: Fix bogus GCC-8 warning in nmi_setup()
    (bnc#1012382).

  - x86/paravirt: Remove 'noreplace-paravirt' cmdline option
    (bnc#1012382).

  - x86/platform: Add PCI dependency for PUNIT_ATOM_DEBUG
    (bnc#1012382).

  - x86/platform/olpc: Fix resume handler build warning
    (bnc#1012382).

  - x86/pti: Make unpoison of pgd for trusted boot work for
    real (bnc#1012382).

  - x86/ras/inject: Make it depend on X86_LOCAL_APIC=y
    (bnc#1012382).

  - x86/retpoline: Avoid retpolines for built-in __init
    functions (bnc#1012382).

  - x86/retpoline/hyperv: Convert assembler indirect jumps
    (fate#315887, bsc#1082632).

  - x86/retpoline: Remove the esp/rsp thunk (bnc#1012382).

  - x86/spectre: Check CONFIG_RETPOLINE in command line
    parser (bnc#1012382).

  - x86/spectre: Fix an error message (git-fixes).

  - x86/spectre: Fix spelling mistake: 'vunerable'->
    'vulnerable' (bnc#1012382).

  - x86/spectre: Remove the out-of-tree RSB stuffing

  - x86/spectre: Simplify spectre_v2 command line parsing
    (bnc#1012382).

  - x86/speculation: Fix typo IBRS_ATT, which should be
    IBRS_ALL (bnc#1012382).

  - x86/xen: Zero MSR_IA32_SPEC_CTRL before suspend
    (bnc#1065600).

  - xen/gntdev: Fix off-by-one error when unmapping with
    holes (bnc#1012382).

  - xen/gntdev: Fix partial gntdev_mmap() cleanup
    (bnc#1012382).

  - xen-netfront: enable device after manual module load
    (bnc#1012382).

  - xen-netfront: remove warning when unloading module
    (bnc#1012382).

  - xen: XEN_ACPI_PROCESSOR is Dom0-only (bnc#1012382).

  - xfrm: check id proto in validate_tmpl() (bnc#1012382).

  - xfrm: Fix stack-out-of-bounds read on socket policy
    lookup (bnc#1012382).

  - xfrm: Fix stack-out-of-bounds with misconfigured
    transport mode policies (bnc#1012382).

  - xfrm_user: propagate sec ctx allocation errors
    (bsc#1042286).

  - xfs: do not chain ioends during writepage submission
    (bsc#1077285 bsc#1043441).

  - xfs: factor mapping out of xfs_do_writepage (bsc#1077285
    bsc#1043441).

  - xfs: Introduce writeback context for writepages
    (bsc#1077285 bsc#1043441).

  - xfs: ioends require logically contiguous file offsets
    (bsc#1077285 bsc#1043441).

  - xfs: quota: check result of register_shrinker()
    (bnc#1012382).

  - xfs: quota: fix missed destroy of qi_tree_lock
    (bnc#1012382).

  - xfs: remove nonblocking mode from xfs_vm_writepage
    (bsc#1077285 bsc#1043441).

  - xfs: remove xfs_cancel_ioend (bsc#1077285 bsc#1043441).

  - xfs: stop searching for free slots in an inode chunk
    when there are none (bsc#1072739).

  - xfs: toggle readonly state around xfs_log_mount_finish
    (bsc#1073401).

  - xfs: ubsan fixes (bnc#1012382).

  - xfs: write unmount record for ro mounts (bsc#1073401).

  - xfs: xfs_cluster_write is redundant (bsc#1077285
    bsc#1043441).

  - xtensa: fix futex_atomic_cmpxchg_inatomic (bnc#1012382).

  - zram: fix operator precedence to get offset
    (bsc#1082979)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006867"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=103998_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=863764"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983145"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/23");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.120-45.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.120-45.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.120-45.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.120-45.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-debuginfo-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-4.4.120-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-debuginfo-4.4.120-45.1") ) flag++;

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
