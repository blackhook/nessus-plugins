#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-388.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135003);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/02");

  script_cve_id("CVE-2019-19768", "CVE-2020-8647", "CVE-2020-8649", "CVE-2020-9383");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-388)");
  script_summary(english:"Check for the openSUSE-2020-388 patch");

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

  - CVE-2020-8647: There was a use-after-free vulnerability
    in the vc_do_resize function in drivers/tty/vt/vt.c
    (bnc#1162929 1164078).

  - CVE-2020-8649: There was a use-after-free vulnerability
    in the vgacon_invert_region function in
    drivers/video/console/vgacon.c (bnc#1162929 1162931).

  - CVE-2020-9383: An issue was discovered in the set_fdc in
    drivers/block/floppy.c that lead to a wait_til_ready
    out-of-bounds read because the FDC index is not checked
    for errors before assigning it, aka CID-2e90ca68b0d2
    (bnc#1165111).

  - CVE-2019-19768: There was a use-after-free (read) in the
    __blk_add_trace function in kernel/trace/blktrace.c
    (which is used to fill out a blk_io_trace structure and
    place it in a per-cpu sub-buffer) (bnc#1159285).

The following non-security bugs were fixed :

  - ALSA: hda/realtek - Add Headset Button supported for
    ThinkPad X1 (bsc#1111666).

  - ALSA: hda/realtek - Add Headset Mic supported
    (bsc#1111666).

  - ALSA: hda/realtek - Add more codec supported Headset
    Button (bsc#1111666).

  - ALSA: hda/realtek - Apply quirk for MSI GP63, too
    (bsc#1111666).

  - ALSA: hda/realtek - Apply quirk for yet another MSI
    laptop (bsc#1111666).

  - ALSA: hda/realtek - Enable the headset of ASUS B9450FA
    with ALC294 (bsc#1111666).

  - ALSA: hda/realtek - Fix a regression for mute led on
    Lenovo Carbon X1 (bsc#1111666).

  - ALSA: hda/realtek - Fix silent output on Gigabyte X570
    Aorus Master (bsc#1111666).

  - ALSA: usb-audio: Add boot quirk for MOTU M Series
    (bsc#1111666).

  - ALSA: usb-audio: Add clock validity quirk for Denon
    MC7000/MCX8000 (bsc#1111666).

  - ALSA: usb-audio: Apply 48kHz fixed rate playback for
    Jabra Evolve 65 headset (bsc#1111666).

  - ALSA: usb-audio: Fix UAC2/3 effect unit parsing
    (bsc#1111666).

  - ALSA: usb-audio: Use lower hex numbers for IDs
    (bsc#1111666).

  - ALSA: usb-audio: add implicit fb quirk for MOTU M Series
    (bsc#1111666).

  - ALSA: usb-audio: add quirks for Line6 Helix devices
    fw>=2.82 (bsc#1111666).

  - ALSA: usb-audio: fix Corsair Virtuoso mixer label
    collision (bsc#1111666).

  - ALSA: usb-audio: unlock on error in probe (bsc#1111666).

  - ALSA: usx2y: Adjust indentation in
    snd_usX2Y_hwdep_dsp_status (bsc#1051510).

  - ASoC: dapm: Correct DAPM handling of active widgets
    during shutdown (bsc#1051510).

  - ASoC: pcm512x: Fix unbalanced regulator enable call in
    probe error path (bsc#1051510).

  - ASoC: pcm: Fix possible buffer overflow in dpcm state
    sysfs output (bsc#1051510).

  - ASoC: pcm: update FE/BE trigger order based on the
    command (bsc#1051510).

  - ASoC: topology: Fix memleak in
    soc_tplg_link_elems_load() (bsc#1051510).

  - Add CONFIG_RAID6_PQ_BENCHMARK=y in following config
    files for the above change,

  - EDAC, ghes: Make platform-based whitelisting x86-only
    (bsc#1158187).

  - EDAC/mc: Fix use-after-free and memleaks during device
    removal (bsc#1114279).

  - Enable the following two patches in series.conf, and
    refresh the KABI patch due to previous md commit
    (bsc#1119680),

  - HID: core: fix off-by-one memset in
    hid_report_raw_event() (bsc#1051510).

  - Input: edt-ft5x06 - work around first register access
    error (bsc#1051510).

  - Input: synaptics - enable SMBus on ThinkPad L470
    (bsc#1051510).

  - Input: synaptics - remove the LEN0049 dmi id from
    topbuttonpad list (bsc#1051510).

  - Input: synaptics - switch T470s to RMI4 by default
    (bsc#1051510).

  - KVM: VMX: check descriptor table exits on instruction
    emulation (bsc#1166104).

  - NFC: pn544: Fix a typo in a debug message (bsc#1051510).

  - NFC: port100: Convert cpu_to_le16(le16_to_cpu(E1) + E2)
    to use le16_add_cpu() (bsc#1051510).

  - PCI/AER: Clear device status bits during ERR_COR
    handling (bsc#1161561).

  - PCI/AER: Clear device status bits during ERR_FATAL and
    ERR_NONFATAL (bsc#1161561).

  - PCI/AER: Clear only ERR_FATAL status bits during fatal
    recovery (bsc#1161561).

  - PCI/AER: Clear only ERR_NONFATAL bits during non-fatal
    recovery (bsc#1161561).

  - PCI/AER: Do not clear AER bits if error handling is
    Firmware-First (bsc#1161561).

  - PCI/AER: Do not read upstream ports below fatal errors
    (bsc#1161561).

  - PCI/AER: Factor out ERR_NONFATAL status bit clearing
    (bsc#1161561).

  - PCI/AER: Take reference on error devices (bsc#1161561).

  - PCI/ERR: Run error recovery callbacks for all affected
    devices (bsc#1161561).

  - PCI/ERR: Use slot reset if available (bsc#1161561).

  - Update 'drm/i915: Wean off drm_pci_alloc/drm_pci_free'
    (bsc#1114279) This patch fixes
    ../drivers/gpu/drm/i915/i915_gem.c: In function
    'i915_gem_object_get_pages_phys':
    ../drivers/gpu/drm/i915/i915_gem.c:232:2: warning:
    return makes pointer from integer without a cast
    [enabled by default] introduced by commit
    cde29f21f04985905600b14e6936f4f023329a99.

  - Update config files. CONFIG_IPX was set on ARM. Disable
    as on other archs.

  - [1/2,media] uvcvideo: Refactor teardown of uvc on USB
    disconnect (https://patchwork.kernel.org/patch/9683663/)
    (bsc#1164507)

  - amdgpu/gmc_v9: save/restore sdpif regs during S3
    (bsc#1113956)

  - atm: zatm: Fix empty body Clang warnings (bsc#1051510).

  - b43legacy: Fix -Wcast-function-type (bsc#1051510).

  - blk: Fix kabi due to blk_trace_mutex addition
    (bsc#1159285).

  - blktrace: fix dereference after null check
    (bsc#1159285).

  - blktrace: fix trace mutex deadlock (bsc#1159285).

  - bonding/alb: properly access headers in bond_alb_xmit()
    (networking-stable-20_02_09).

  - config: enable BLK_DEV_SR_VENDOR on armv7hl
    (bsc#1164632)

  - cpufreq: powernv: Fix unsafe notifiers (bsc#1065729).

  - cpufreq: powernv: Fix use-after-free (bsc#1065729).

  - crypto: pcrypt - Fix user-after-free on module unload
    (git-fixes).

  - dmaengine: coh901318: Fix a double lock bug in
    dma_tc_handle() (bsc#1051510).

  - driver core: Print device when resources present in
    really_probe() (bsc#1051510).

  - driver core: platform: Prevent resouce overflow from
    causing infinite loops (bsc#1051510).

  - driver core: platform: fix u32 greater or equal to zero
    comparison (bsc#1051510).

  - drivers/md/raid5-ppl.c: use the new spelling of
    RWH_WRITE_LIFE_NOT_SET (bsc#1166003).

  - drivers/md/raid5.c: use the new spelling of
    RWH_WRITE_LIFE_NOT_SET (bsc#1166003).

  - drm/amd/dm/mst: Ignore payload update failures
    (bsc#1112178)

  - drm/gma500: Fixup fbdev stolen size usage evaluation
    (bsc#1051510).

  - drm/i915/gvt: Fix orphan vgpu dmabuf_objs' lifetime
    (git-fixes).

  - drm/i915/gvt: Fix unnecessary schedule timer when no
    vGPU exits (git-fixes).

  - drm/i915/selftests: Fix return in assert_mmap_offset()
    (bsc#1114279)

  - drm/i915/userptr: Try to acquire the page lock around
    (bsc#1114279)

  - drm/i915: Program MBUS with rmw during initialization
    (git-fixes).

  - drm/mediatek: handle events when enabling/disabling crtc
    (bsc#1051510).

  - drm/nouveau/disp/nv50-: prevent oops when no channel
    method map provided (bsc#1051510).

  - drm/nouveau/gr/gk20a,gm200-: add terminators to method
    lists read from fw (bsc#1051510).

  - drm/nouveau/kms/gv100-: Re-set LUT after clearing for
    modesets (git-fixes).

  - drm/sun4i: Fix DE2 VI layer format support (git-fixes).

  - drm/sun4i: de2/de3: Remove unsupported VI layer formats
    (git-fixes).

  - drm: remove the newline for CRC source name
    (bsc#1051510).

  - fcntl: fix typo in RWH_WRITE_LIFE_NOT_SET r/w hint name
    (bsc#1166003).

  - firmware: imx: misc: Align imx sc msg structs to 4
    (git-fixes).

  - firmware: imx: scu-pd: Align imx sc msg structs to 4
    (git-fixes).

  - firmware: imx: scu: Ensure sequential TX (git-fixes).

  - fs/xfs: fix f_ffree value for statfs when project quota
    is set (bsc#1165985).

  - hwmon: (adt7462) Fix an error return in
    ADT7462_REG_VOLT() (bsc#1051510).

  - ibmvnic: Do not process device remove during device
    reset (bsc#1065729).

  - ibmvnic: Warn unknown speed message only when carrier is
    present (bsc#1065729).

  - iommu/amd: Check feature support bit before accessing
    MSI capability registers (bsc#1166101).

  - iommu/amd: Only support x2APIC with IVHD type 11h/40h
    (bsc#1166102).

  - iommu/amd: Remap the IOMMU device table with the memory
    encryption mask for kdump (bsc#1141895).

  - iommu/dma: Fix MSI reservation allocation (bsc#1166730).

  - iommu/vt-d: Fix a bug in intel_iommu_iova_to_phys() for
    huge page (bsc#1166732).

  - iommu/vt-d: Fix compile warning from intel-svm.h
    (bsc#1166103).

  - iommu/vt-d: Fix the wrong printing in RHSA parsing
    (bsc#1166733).

  - iommu/vt-d: Ignore devices with out-of-spec domain
    number (bsc#1166734).

  - iommu/vt-d: dmar: replace WARN_TAINT with pr_warn +
    add_taint (bsc#1166731).

  - iommu/vt-d: quirk_ioat_snb_local_iommu: replace
    WARN_TAINT with pr_warn + add_taint (bsc#1166735).

  - iwlegacy: Fix -Wcast-function-type (bsc#1051510).

  - iwlwifi: mvm: Do not require PHY_SKU NVM section for
    3168 devices (bsc#1166632).

  - iwlwifi: mvm: Fix thermal zone registration
    (bsc#1051510).

  - kdump, proc/vmcore: Enable kdumping encrypted memory
    with SME enabled (bsc#1141895).

  - kexec: Allocate decrypted control pages for kdump if SME
    is enabled (bsc#1141895).

  - lib/raid6: add missing include for raid6test
    (bsc#1166003).

  - lib/raid6: add option to skip algo benchmarking
    (bsc#1166003).

  - lib/raid6: avoid __attribute_const__ redefinition
    (bsc#1166003).

  - libnvdimm/pfn: fix fsdax-mode namespace info-block
    zero-fields (bsc#1165929).

  - libnvdimm/pfn_dev: Do not clear device memmap area
    during generic namespace probe (bsc#1165929
    bsc#1165950).

  - libnvdimm: remove redundant __func__ in dev_dbg
    (bsc#1165929).

  - md raid0/linear: Mark array as 'broken' and fail BIOs if
    a member is gone (bsc#1166003).

  - md-batch-flush-requests-kabi.patch

  - md-batch-flush-requests.patch

  - md-bitmap: create and destroy wb_info_pool with the
    change of backlog (bsc#1166003).

  - md-bitmap: create and destroy wb_info_pool with the
    change of bitmap (bsc#1166003).

  - md-bitmap: small cleanups (bsc#1166003).

  - md-cluster/bitmap: do not call
    md_bitmap_sync_with_cluster during reshaping stage
    (bsc#1166003).

  - md-cluster/raid10: call update_size in
    md_reap_sync_thread (bsc#1166003).

  - md-cluster/raid10: do not call remove_and_add_spares
    during reshaping stage (bsc#1166003).

  - md-cluster/raid10: resize all the bitmaps before start
    reshape (bsc#1166003).

  - md-cluster/raid10: support add disk under grow mode
    (bsc#1166003).

  - md-cluster: introduce resync_info_get interface for
    sanity check (bsc#1166003).

  - md-cluster: remove suspend_info (bsc#1166003).

  - md-cluster: send BITMAP_NEEDS_SYNC message if reshaping
    is interrupted (bsc#1166003).

  - md-linear: use struct_size() in kzalloc() (bsc#1166003).

  - md/bitmap: avoid race window between md_bitmap_resize
    and bitmap_file_clear_bit (bsc#1166003).

  - md/bitmap: use mddev_suspend/resume instead of
    ->quiesce() (bsc#1166003).

  - md/raid0: Fix an error message in raid0_make_request()
    (bsc#1166003).

  - md/raid10: Fix raid10 replace hang when new added disk
    faulty (bsc#1166003).

  - md/raid10: end bio when the device faulty (bsc#1166003).

  - md/raid10: prevent access of uninitialized resync_pages
    offset (bsc#1166003).

  - md/raid10: read balance chooses idlest disk for SSD
    (bsc#1166003).

  - md/raid1: Fix a warning message in remove_wb()
    (bsc#1166003).

  - md/raid1: avoid soft lockup under high load
    (bsc#1166003).

  - md/raid1: end bio when the device faulty (bsc#1166003).

  - md/raid1: fail run raid1 array when active disk less
    than one (bsc#1166003).

  - md/raid1: fix potential data inconsistency issue with
    write behind device (bsc#1166003).

  - md/raid1: get rid of extra blank line and space
    (bsc#1166003).

  - md/raid5: use bio_end_sector to calculate last_sector
    (bsc#1166003).

  - md/raid6: fix algorithm choice under larger PAGE_SIZE
    (bsc#1166003).

  - md: Make bio_alloc_mddev use bio_alloc_bioset
    (bsc#1166003).

  - md: add __acquires/__releases annotations to
    (un)lock_two_stripes (bsc#1166003).

  - md: add __acquires/__releases annotations to
    handle_active_stripes (bsc#1166003).

  - md: add a missing endianness conversion in
    check_sb_changes (bsc#1166003).

  - md: add bitmap_abort label in md_run (bsc#1166003).

  - md: add feature flag MD_FEATURE_RAID0_LAYOUT
    (bsc#1166003).

  - md: allow last device to be forcibly removed from
    RAID1/RAID10 (bsc#1166003).

  - md: avoid invalid memory access for array sb->dev_roles
    (bsc#1166003).

  - md: change kabi fix patch name, from
    patches.kabi/md-batch-flush-requests-kabi.patch to
    patches.kabi/md-backport-kabi.patch

  - md: convert to kvmalloc (bsc#1166003).

  - md: do not call spare_active in md_reap_sync_thread if
    all member devices can't work (bsc#1166003).

  - md: do not set In_sync if array is frozen (bsc#1166003).

  - md: fix a typo s/creat/create (bsc#1166003).

  - md: fix for divide error in status_resync (bsc#1166003).

  - md: fix spelling typo and add necessary space
    (bsc#1166003).

  - md: introduce mddev_create/destroy_wb_pool for the
    change of member device (bsc#1166003).

  - md: make sure desc_nr less than MD_SB_DISKS
    (bsc#1166003).

  - md: md.c: Return -ENODEV when mddev is NULL in
    rdev_attr_show (bsc#1166003).

  - md: no longer compare spare disk superblock events in
    super_load (bsc#1166003).

  - md: raid10: Use struct_size() in kmalloc()
    (bsc#1166003).

  - md: raid1: check rdev before reference in
    raid1_sync_request func (bsc#1166003).

  - md: remove set but not used variable 'bi_rdev'
    (bsc#1166003).

  - md: rename wb stuffs (bsc#1166003).

  - md: return -ENODEV if rdev has no mddev assigned
    (bsc#1166003).

  - md: use correct type in super_1_load (bsc#1166003).

  - md: use correct type in super_1_sync (bsc#1166003).

  - md: use correct types in md_bitmap_print_sb
    (bsc#1166003).

  - media: uvcvideo: Refactor teardown of uvc on USB
    disconnect (bsc#1164507).

  - net/smc: add fallback check to connect() (git-fixes).

  - net/smc: fix cleanup for linkgroup setup failures
    (git-fixes).

  - net/smc: no peer ID in CLC decline for SMCD (git-fixes).

  - net/smc: transfer fasync_list in case of fallback
    (git-fixes).

  - net: macb: Limit maximum GEM TX length in TSO
    (networking-stable-20_02_09).

  - net: macb: Remove unnecessary alignment check for TSO
    (networking-stable-20_02_09).

  - net: mvneta: move rx_dropped and rx_errors in per-cpu
    stats (networking-stable-20_02_09).

  - net: systemport: Avoid RBUF stuck in Wake-on-LAN mode
    (networking-stable-20_02_09).

  - net_sched: fix a resource leak in tcindex_set_parms()
    (networking-stable-20_02_09).

  - nvme: Fix parsing of ANA log page (bsc#1166658).

  - nvme: Translate more status codes to blk_status_t
    (bsc#1156510).

  - nvme: resync include/linux/nvme.h with nvmecli
    (bsc#1156510).

  - orinoco: avoid assertion in case of NULL pointer
    (bsc#1051510).

  - padata: always acquire cpu_hotplug_lock before
    pinst->lock (git-fixes).

  - pinctrl: baytrail: Do not clear IRQ flags on direct-irq
    enabled pins (bsc#1051510).

  - pinctrl: imx: scu: Align imx sc msg structs to 4
    (git-fixes).

  - pinctrl: sh-pfc: sh7264: Fix CAN function GPIOs
    (bsc#1051510).

  - pinctrl: sh-pfc: sh7269: Fix CAN function GPIOs
    (bsc#1051510).

  - powerpc/pseries: fix of_read_drc_info_cell() to point at
    next record (bsc#1165980 ltc#183834).

  - powerpc: fix hardware PMU exception bug on PowerVM
    compatibility mode systems (bsc#1056686).

  - qmi_wwan: re-add DW5821e pre-production variant
    (bsc#1051510).

  - raid10: refactor common wait code from regular
    read/write request (bsc#1166003).

  - raid1: factor out a common routine to handle the
    completion of sync write (bsc#1166003).

  - raid1: simplify raid1_error function (bsc#1166003).

  - raid1: use an int as the return value of raise_barrier()
    (bsc#1166003).

  - raid5 improve too many read errors msg by adding limits
    (bsc#1166003).

  - raid5: block failing device if raid will be failed
    (bsc#1166003).

  - raid5: do not increment read_errors on EILSEQ return
    (bsc#1166003).

  - raid5: do not set STRIPE_HANDLE to stripe which is in
    batch list (bsc#1166003).

  - raid5: need to set STRIPE_HANDLE for batch head
    (bsc#1166003).

  - raid5: remove STRIPE_OPS_REQ_PENDING (bsc#1166003).

  - raid5: remove worker_cnt_per_group argument from
    alloc_thread_groups (bsc#1166003).

  - raid5: set write hint for PPL (bsc#1166003).

  - raid5: use bio_end_sector in r5_next_bio (bsc#1166003).

  - raid6/test: fix a compilation error (bsc#1166003).

  - raid6/test: fix a compilation warning (bsc#1166003).

  - remoteproc: Initialize rproc_class before use
    (bsc#1051510).

  - rtlwifi: rtl_pci: Fix -Wcast-function-type
    (bsc#1051510).

  - s390/pci: Fix unexpected write combine on resource
    (git-fixes).

  - s390/uv: Fix handling of length extensions (git-fixes).

  - staging: rtl8188eu: Fix potential overuse of kernel
    memory (bsc#1051510).

  - staging: rtl8188eu: Fix potential security hole
    (bsc#1051510).

  - staging: rtl8723bs: Fix potential overuse of kernel
    memory (bsc#1051510).

  - staging: rtl8723bs: Fix potential security hole
    (bsc#1051510).

  - tick: broadcast-hrtimer: Fix a race in bc_set_next
    (bsc#1044231).

  - tools: Update include/uapi/linux/fcntl.h copy from the
    kernel (bsc#1166003).

  - usb: host: xhci: update event ring dequeue pointer on
    purpose (git-fixes).

  - vgacon: Fix a UAF in vgacon_invert_region (bsc#1114279)

  - virtio-blk: fix hw_queue stopped on arbitrary error
    (git-fixes).

  - x86/cpu/amd: Enable the fixed Instructions Retired
    counter IRPERF (bsc#1114279).

  - x86/ioremap: Add an ioremap_encrypted() helper
    (bsc#1141895).

  - x86/kdump: Export the SME mask to vmcoreinfo
    (bsc#1141895).

  - x86/mce/amd: Fix kobject lifetime (bsc#1114279).

  - x86/mce/amd: Publish the bank pointer only after setup
    has succeeded (bsc#1114279).

  - x86/mm: Split vmalloc_sync_all() (bsc#1165741).

  - xfs: also remove cached ACLs when removing the
    underlying attr (bsc#1165873).

  - xfs: bulkstat should copy lastip whenever userspace
    supplies one (bsc#1165984).

  - xhci: Force Maximum Packet size for Full-speed bulk
    devices to valid range (bsc#1051510).

  - xhci: fix runtime pm enabling for quirky Intel hosts
    (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111974"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://patchwork.kernel.org/patch/9683663/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9383");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.44.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
