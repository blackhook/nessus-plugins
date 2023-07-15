#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-336.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134559);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/18");

  script_cve_id("CVE-2019-14615", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-16746", "CVE-2019-16994", "CVE-2019-18808", "CVE-2019-19036", "CVE-2019-19045", "CVE-2019-19051", "CVE-2019-19054", "CVE-2019-19066", "CVE-2019-19318", "CVE-2019-19319", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19447", "CVE-2019-19523", "CVE-2019-19526", "CVE-2019-19527", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19535", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19927", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-20054", "CVE-2019-20095", "CVE-2019-20096", "CVE-2020-2732", "CVE-2020-7053", "CVE-2020-8428", "CVE-2020-8648", "CVE-2020-8992");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-336)");
  script_summary(english:"Check for the openSUSE-2020-336 patch");

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

  - CVE-2019-14615: Insufficient control flow in certain
    data structures for some Intel(R) Processors with
    Intel(R) Processor Graphics may have allowed an
    unauthenticated user to potentially enable information
    disclosure via local access (bnc#1160195 bnc#1165881).

  - CVE-2019-14896: A heap-based buffer overflow
    vulnerability was found in the Marvell WiFi chip driver.
    A remote attacker could cause a denial of service
    (system crash) or, possibly execute arbitrary code, when
    the lbs_ibss_join_existing function is called after a
    STA connects to an AP (bnc#1157157).

  - CVE-2019-14897: A stack-based buffer overflow was found
    in the Marvell WiFi chip driver. An attacker is able to
    cause a denial of service (system crash) or, possibly
    execute arbitrary code, when a STA works in IBSS mode
    (allows connecting stations together without the use of
    an AP) and connects to another STA (bnc#1157155).

  - CVE-2019-16746: An issue was discovered in
    net/wireless/nl80211.c. It did not check the length of
    variable elements in a beacon head, leading to a buffer
    overflow (bnc#1152107).

  - CVE-2019-16994: In the Linux kernel before 5.0, a memory
    leak exists in sit_init_net() in net/ipv6/sit.c when
    register_netdev() fails to register sitn->fb_tunnel_dev,
    which may cause denial of service, aka CID-07f12b26e21a
    (bnc#1161523).

  - CVE-2019-18808: A memory leak in the ccp_run_sha_cmd()
    function in drivers/crypto/ccp/ccp-ops.c allowed
    attackers to cause a denial of service (memory
    consumption), aka CID-128c66429247 (bnc#1156259).

  - CVE-2019-19036: btrfs_root_node in fs/btrfs/ctree.c
    allowed a NULL pointer dereference because
    rcu_dereference(root->node) can be zero (bnc#1157692).

  - CVE-2019-19045: A memory leak in the
    mlx5_fpga_conn_create_cq() function in
    drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c
    allowed attackers to cause a denial of service (memory
    consumption) by triggering mlx5_vector2eqn() failures,
    aka CID-c8c2a057fdc7 (bnc#1161522).

  - CVE-2019-19051: A memory leak in the
    i2400m_op_rfkill_sw_toggle() function in
    drivers/net/wimax/i2400m/op-rfkill.c allowed attackers
    to cause a denial of service (memory consumption), aka
    CID-6f3ef5c25cc7 (bnc#1159024).

  - CVE-2019-19054: A memory leak in the cx23888_ir_probe()
    function in drivers/media/pci/cx23885/cx23888-ir.c
    allowed attackers to cause a denial of service (memory
    consumption) by triggering kfifo_alloc() failures, aka
    CID-a7b2df76b42b (bnc#1161518).

  - CVE-2019-19066: A memory leak in the bfad_im_get_stats()
    function in drivers/scsi/bfa/bfad_attr.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering bfa_port_get_stats()
    failures, aka CID-0e62395da2bd (bnc#1157303).

  - CVE-2019-19318: Mounting a crafted btrfs image twice can
    cause an rwsem_down_write_slowpath use-after-free
    because (in rwsem_can_spin_on_owner in
    kernel/locking/rwsem (bnc#1158026).

  - CVE-2019-19319: A setxattr operation, after a mount of a
    crafted ext4 image, can cause a slab-out-of-bounds write
    access because of an ext4_xattr_set_entry use-after-free
    in fs/ext4/xattr.c when a large old_size value is used
    in a memset call (bnc#1158021).

  - CVE-2019-19332: An out-of-bounds memory write issue was
    found in the way the Linux kernel's KVM hypervisor
    handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to
    get CPUID features emulated by the KVM hypervisor. A
    user or process able to access the '/dev/kvm' device
    could use this flaw to crash the system, resulting in a
    denial of service (bnc#1158827).

  - CVE-2019-19338: There was an incomplete fix for
    Transaction Asynchronous Abort (TAA) (bnc#1158954).

  - CVE-2019-19447: Mounting a crafted ext4 filesystem
    image, performing some operations, and unmounting can
    lead to a use-after-free in ext4_put_super in
    fs/ext4/super.c, related to dump_orphan_list in
    fs/ext4/super.c (bnc#1158819).

  - CVE-2019-19526: There was a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/nfc/pn533/usb.c driver, aka CID-6af3aa57a098
    (bnc#1158893).

  - CVE-2019-19527: There was a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/hid/usbhid/hiddev.c driver, aka CID-9c09b214f30e
    (bnc#1158900).

  - CVE-2019-19532: There were multiple out-of-bounds write
    bugs that can be caused by a malicious USB device in the
    Linux kernel HID drivers, aka CID-d9d4b1e46d95. This
    affects drivers/hid/hid-axff.c, drivers/hid/hid-dr.c,
    drivers/hid/hid-emsff.c, drivers/hid/hid-gaff.c,
    drivers/hid/hid-holtekff.c, drivers/hid/hid-lg2ff.c,
    drivers/hid/hid-lg3ff.c, drivers/hid/hid-lg4ff.c,
    drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c,
    drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c,
    drivers/hid/hid-tmff.c, and drivers/hid/hid-zpff.c
    (bnc#1158824).

  - CVE-2019-19533: There was an info-leak bug that can be
    caused by a malicious USB device in the
    drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka
    CID-a10feaf8c464 (bnc#1158834).

  - CVE-2019-19535: There was an info-leak bug that can be
    caused by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_fd.c driver, aka
    CID-30a8beeb3042 (bnc#1158903).

  - CVE-2019-19537: There was a race condition bug that can
    be caused by a malicious USB device in the USB character
    device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c (bnc#1158904).

  - CVE-2019-19767: The Linux kernel mishandled
    ext4_expand_extra_isize, as demonstrated by
    use-after-free errors in __ext4_expand_extra_isize and
    ext4_xattr_set_entry, related to fs/ext4/inode.c and
    fs/ext4/super.c, aka CID-4ea99936a163 (bnc#1159297).

  - CVE-2019-19927: Mounting a crafted f2fs filesystem image
    and performing some operations can lead to
    slab-out-of-bounds read access in ttm_put_pages in
    drivers/gpu/drm/ttm/ttm_page_alloc.c. This is related to
    the vmwgfx or ttm module (bnc#1160147).

  - CVE-2019-19965: There was a NULL pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of
    mishandling of port disconnection during discovery,
    related to a PHY down race condition, aka
    CID-f70267f379b5 (bnc#1159911).

  - CVE-2019-19966: There was a use-after-free in
    cpia2_exit() in drivers/media/usb/cpia2/cpia2_v4l.c that
    will cause denial of service, aka CID-dea37a972655
    (bnc#1159841).

  - CVE-2019-20054: There was a NULL pointer dereference in
    drop_sysctl_table() in fs/proc/proc_sysctl.c, related to
    put_links, aka CID-23da9588037e (bnc#1159910).

  - CVE-2019-20095: mwifiex_tm_cmd in
    drivers/net/wireless/marvell/mwifiex/cfg80211.c had some
    error-handling cases that did not free allocated hostcmd
    memory, aka CID-003b686ace82. This will cause a memory
    leak and denial of service (bnc#1159909).

  - CVE-2019-20096: There was a memory leak in
    __feat_register_sp() in net/dccp/feat.c, which may cause
    denial of service, aka CID-1d3ff0950e2b (bnc#1159908).

  - CVE-2020-2732: Fixed an issue affecting Intel CPUs where
    an L2 guest may trick the L0 hypervisor into accessing
    sensitive L1 resources (bsc#1163971).

  - CVE-2020-7053: There was a use-after-free (write) in the
    i915_ppgtt_close function in
    drivers/gpu/drm/i915/i915_gem_gtt.c, aka
    CID-7dc40713618c. This is related to
    i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c (bnc#1160966).

  - CVE-2020-8428: fs/namei.c has a may_create_in_sticky
    use-after-free, which allowed local users to cause a
    denial of service (OOPS) or possibly obtain sensitive
    information from kernel memory, aka CID-d0cb50185ae9.
    One attack vector may be an open system call for a UNIX
    domain socket, if the socket is being moved to a new
    parent directory and its old parent directory is being
    removed (bnc#1162109).

  - CVE-2020-8648: There was a use-after-free vulnerability
    in the n_tty_receive_buf_common function in
    drivers/tty/n_tty.c (bnc#1162928).

  - CVE-2020-8992: ext4_protect_reserved_inode in
    fs/ext4/block_validity.c allowed attackers to cause a
    denial of service (soft lockup) via a crafted journal
    size (bnc#1164069).

  - CVE-2019-19523: There was a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/usb/misc/adutux.c driver, aka CID-44efc269db79
    (bnc#1158823).

The following non-security bugs were fixed :

  - smb3: print warning once if posix context returned on
    open (bsc#1144333).

  - 6pack,mkiss: fix possible deadlock (bsc#1051510).

  - ACPI / APEI: Do not wait to serialise with oops messages
    when panic()ing (bsc#1051510).

  - ACPI / APEI: Switch estatus pool to use vmalloc memory
    (bsc#1051510).

  - ACPI / LPSS: Ignore acpi_device_fix_up_power() return
    value (bsc#1051510).

  - ACPI / video: Add force_none quirk for Dell OptiPlex
    9020M (bsc#1051510).

  - ACPI / watchdog: Fix init failure with overlapping
    register regions (bsc#1162557).

  - ACPI / watchdog: Set default timeout in probe
    (bsc#1162557).

  - ACPI: OSL: only free map once in osl.c (bsc#1051510).

  - ACPI: PM: Avoid attaching ACPI PM domain to certain
    devices (bsc#1051510).

  - ACPI: bus: Fix NULL pointer check in
    acpi_bus_get_private_data() (bsc#1051510).

  - ACPI: fix acpi_find_child_device() invocation in
    acpi_preset_companion() (bsc#1051510).

  - ACPI: sysfs: Change ACPI_MASKABLE_GPE_MAX to 0x100
    (bsc#1051510).

  - ACPI: video: Do not export a non working backlight
    interface on MSI MS-7721 boards (bsc#1051510).

  - ACPI: watchdog: Allow disabling WDAT at boot
    (bsc#1162557).

  - ALSA: control: remove useless assignment in .info
    callback of PCM chmap element (git-fixes).

  - ALSA: dummy: Fix PCM format loop in proc output
    (bsc#1111666).

  - ALSA: echoaudio: simplify get_audio_levels
    (bsc#1051510).

  - ALSA: fireface: fix return value in error path of
    isochronous resources reservation (bsc#1051510).

  - ALSA: hda - Add docking station support for Lenovo
    Thinkpad T420s (git-fixes).

  - ALSA: hda - Apply sync-write workaround to old Intel
    platforms, too (bsc#1111666).

  - ALSA: hda - Downgrade error message for single-cmd
    fallback (git-fixes).

  - ALSA: hda - constify and cleanup static NodeID tables
    (bsc#1111666).

  - ALSA: hda - fixup for the bass speaker on Lenovo Carbon
    X1 7th gen (git-fixes).

  - ALSA: hda/analog - Minor optimization for SPDIF mux
    connections (git-fixes).

  - ALSA: hda/ca0132 - Avoid endless loop (git-fixes).

  - ALSA: hda/ca0132 - Fix work handling in delayed HP
    detection (git-fixes).

  - ALSA: hda/ca0132 - Keep power on during processing DSP
    response (git-fixes).

  - ALSA: hda/hdmi - Add new pci ids for AMD GPU display
    audio (git-fixes).

  - ALSA: hda/hdmi - Clean up Intel platform-specific fixup
    checks (bsc#1111666).

  - ALSA: hda/hdmi - Fix duplicate unref of pci_dev
    (bsc#1051510).

  - ALSA: hda/hdmi - add retry logic to parse_intel_hdmi()
    (git-fixes).

  - ALSA: hda/hdmi - fix atpx_present when CLASS is not VGA
    (bsc#1051510).

  - ALSA: hda/hdmi - fix vgaswitcheroo detection for AMD
    (git-fixes).

  - ALSA: hda/realtek - Add Bass Speaker and fixed dac for
    bass speaker (bsc#1111666).

  - ALSA: hda/realtek - Add Headset Mic supported for HP cPC
    (bsc#1111666).

  - ALSA: hda/realtek - Add headset Mic no shutup for ALC283
    (bsc#1051510).

  - ALSA: hda/realtek - Add new codec supported for
    ALCS1200A (bsc#1111666).

  - ALSA: hda/realtek - Add quirk for the bass speaker on
    Lenovo Yoga X1 7th gen (bsc#1111666).

  - ALSA: hda/realtek - Apply mic mute LED quirk for Dell
    E7xx laptops, too (bsc#1111666).

  - ALSA: hda/realtek - Dell headphone has noise on unmute
    for ALC236 (git-fixes).

  - ALSA: hda/realtek - Enable the bass speaker of ASUS
    UX431FLC (bsc#1111666).

  - ALSA: hda/realtek - Fix inverted bass GPIO pin on Acer
    8951G (git-fixes).

  - ALSA: hda/realtek - Fix silent output on MSI-GL73
    (git-fixes).

  - ALSA: hda/realtek - Fixed one of HP ALC671 platform
    Headset Mic supported (bsc#1111666).

  - ALSA: hda/realtek - Line-out jack does not work on a
    Dell AIO (bsc#1051510).

  - ALSA: hda/realtek - More constifications (bsc#1111666).

  - ALSA: hda/realtek - Set EAPD control to default for
    ALC222 (bsc#1111666).

  - ALSA: hda: Add Clevo W65_67SB the power_save blacklist
    (git-fixes).

  - ALSA: hda: Add JasperLake PCI ID and codec vid
    (bsc#1111666).

  - ALSA: hda: Clear RIRB status before reading WP
    (bsc#1111666).

  - ALSA: hda: Constify snd_kcontrol_new items
    (bsc#1111666).

  - ALSA: hda: Constify snd_pci_quirk tables (bsc#1111666).

  - ALSA: hda: More constifications (bsc#1111666).

  - ALSA: hda: Reset stream if DMA RUN bit not cleared
    (bsc#1111666).

  - ALSA: hda: Use scnprintf() for printing texts for
    sysfs/procfs (git-fixes).

  - ALSA: hda: constify copied structure (bsc#1111666).

  - ALSA: hda: correct kernel-doc parameter descriptions
    (bsc#1111666).

  - ALSA: hda: hdmi - add Tigerlake support (bsc#1111666).

  - ALSA: hda: hdmi - fix pin setup on Tigerlake
    (bsc#1111666).

  - ALSA: hda: patch_hdmi: remove warnings with empty body
    (bsc#1111666).

  - ALSA: hda: patch_realtek: fix empty macro usage in if
    block (bsc#1111666).

  - ALSA: ice1724: Fix sleep-in-atomic in Infrasonic Quartet
    support code (bsc#1051510).

  - ALSA: oxfw: fix return value in error path of
    isochronous resources reservation (bsc#1051510).

  - ALSA: pcm: Avoid possible info leaks from PCM stream
    buffers (git-fixes).

  - ALSA: pcm: oss: Avoid potential buffer overflows
    (git-fixes).

  - ALSA: seq: Avoid concurrent access to queue flags
    (git-fixes).

  - ALSA: seq: Fix concurrent access to queue current
    tick/time (git-fixes).

  - ALSA: seq: Fix racy access for queue timer in proc read
    (bsc#1051510).

  - ALSA: sh: Fix compile warning wrt const (git-fixes).

  - ALSA: sh: Fix unused variable warnings (bsc#1111666).

  - ALSA: usb-audio: Apply sample rate quirk for Audioengine
    D1 (git-fixes).

  - ALSA: usb-audio: Apply the sample rate quirk for Bose
    Companion 5 (bsc#1111666).

  - ALSA: usb-audio: Fix endianess in descriptor validation
    (bsc#1111666).

  - ALSA: usb-audio: fix set_format altsetting sanity check
    (bsc#1051510).

  - ALSA: usb-audio: fix sync-ep altsetting sanity check
    (bsc#1051510).

  - ASoC: Jack: Fix NULL pointer dereference in
    snd_soc_jack_report (bsc#1051510).

  - ASoC: au8540: use 64-bit arithmetic instead of 32-bit
    (bsc#1051510).

  - ASoC: compress: fix unsigned integer overflow check
    (bsc#1051510).

  - ASoC: cs4349: Use PM ops 'cs4349_runtime_pm'
    (bsc#1051510).

  - ASoC: msm8916-wcd-analog: Fix selected events for MIC
    BIAS External1 (bsc#1051510).

  - ASoC: samsung: i2s: Fix prescaler setting for the
    secondary DAI (bsc#1111666).

  - ASoC: sun8i-codec: Fix setting DAI data format
    (git-fixes).

  - ASoC: wm8962: fix lambda value (git-fixes).

  - Bluetooth: Fix race condition in hci_release_sock()
    (bsc#1051510).

  - Bluetooth: hci_bcm: Handle specific unknown packets
    after firmware loading (bsc#1051510).

  - btrfs: add missing extents release on file extent
    cluster relocation error (bsc#1159483).

  - btrfs: avoid fallback to transaction commit during fsync
    of files with holes (bsc#1159569).

  - btrfs: fix block group remaining RO forever after error
    during device replace (bsc#1160442).

  - btrfs: fix btrfs_write_inode vs delayed iput deadlock
    (bsc#1154243).

  - btrfs: fix infinite loop during fsync after rename
    operations (bsc#1163383).

  - btrfs: fix infinite loop during nocow writeback due to
    race (bsc#1160804).

  - btrfs: fix missing data checksums after replaying a log
    tree (bsc#1161931).

  - btrfs: fix negative subv_writers counter and data space
    leak after buffered write (bsc#1160802).

  - btrfs: fix race between adding and putting tree mod seq
    elements and nodes (bsc#1163384).

  - btrfs: fix removal logic of the tree mod log that leads
    to use-after-free issues (bsc#1160803).

  - btrfs: fix selftests failure due to uninitialized i_mode
    in test inodes (Fix for dependency of bsc#1157692).

  - btrfs: make tree checker detect checksum items with
    overlapping ranges (bsc#1161931).

  - btrfs: send, skip backreference walking for extents with
    many references (bsc#1162139).

  - CDC-NCM: handle incomplete transfer of MTU
    (networking-stable-19_11_10).

  - CIFS: Add support for setting owner info, dos
    attributes, and create time (bsc#1144333).

  - CIFS: Close cached root handle only if it had a lease
    (bsc#1144333).

  - CIFS: Close open handle after interrupted close
    (bsc#1144333).

  - CIFS: Do not miss cancelled OPEN responses
    (bsc#1144333).

  - CIFS: Fix NULL pointer dereference in mid callback
    (bsc#1144333).

  - CIFS: Fix NULL pointer dereference in
    smb2_push_mandatory_locks (bsc#1144333).

  - CIFS: Fix task struct use-after-free on reconnect
    (bsc#1144333).

  - CIFS: Properly process SMB3 lease breaks (bsc#1144333).

  - CIFS: Respect O_SYNC and O_DIRECT flags during reconnect
    (bsc#1144333).

  - CIFS: Return directly after a failed
    build_path_from_dentry() in cifs_do_create()
    (bsc#1144333).

  - CIFS: Use common error handling code in
    smb2_ioctl_query_info() (bsc#1144333).

  - CIFS: Use memdup_user() rather than duplicating its
    implementation (bsc#1144333).

  - CIFS: fix a white space issue in cifs_get_inode_info()
    (bsc#1144333).

  - CIFS: refactor cifs_get_inode_info() (bsc#1144333).

  - CIFS: remove set but not used variables 'cinode' and
    'netfid' (bsc#1144333).

  - Cover up kABI breakage due to DH key verification
    (bsc#1155331).

  - Delete patches which cause regression (bsc#1165527
    ltc#184149).

  - Documentation: Document arm64 kpti control
    (bsc#1162623).

  - Enable CONFIG_BLK_DEV_SR_VENDOR (boo#1164632).

  - Fix the locking in dcache_readdir() and friends
    (bsc#1123328).

  - HID: doc: fix wrong data structure reference for
    UHID_OUTPUT (bsc#1051510).

  - HID: hiddev: Fix race in in hiddev_disconnect()
    (git-fixes).

  - HID: hidraw, uhid: Always report EPOLLOUT (bsc#1051510).

  - HID: hidraw: Fix returning EPOLLOUT from hidraw_poll
    (bsc#1051510).

  - HID: intel-ish-hid: fixes incorrect error handling
    (bsc#1051510).

  - HID: uhid: Fix returning EPOLLOUT from uhid_char_poll
    (bsc#1051510).

  - IB/hfi1: Close window for pq and request coliding
    (bsc#1060463 ).

  - IB/hfi1: Do not cancel unused work item (bsc#1114685 ).

  - IB/mlx5: Fix steering rule of drop and count
    (bsc#1103991 ).

  - IB/mlx5: Remove dead code (bsc#1103991).

  - Input: aiptek - fix endpoint sanity check (bsc#1051510).

  - Input: cyttsp4_core - fix use after free bug
    (bsc#1051510).

  - Input: goodix - add upside-down quirk for Teclast X89
    tablet (bsc#1051510).

  - Input: gtco - fix endpoint sanity check (bsc#1051510).

  - Input: keyspan-remote - fix control-message timeouts
    (bsc#1051510).

  - Input: pegasus_notetaker - fix endpoint sanity check
    (bsc#1051510).

  - Input: pm8xxx-vib - fix handling of separate enable
    register (bsc#1051510).

  - Input: rmi_f54 - read from FIFO in 32 byte blocks
    (bsc#1051510).

  - Input: sun4i-ts - add a check for
    devm_thermal_zone_of_sensor_register (bsc#1051510).

  - Input: sur40 - fix interface sanity checks
    (bsc#1051510).

  - Input: synaptics - switch another X1 Carbon 6 to
    RMI/SMbus (bsc#1051510).

  - Input: synaptics-rmi4 - do not increment rmiaddr for
    SMBus transfers (bsc#1051510).

  - Input: synaptics-rmi4 - simplify data read in
    rmi_f54_work (bsc#1051510).

  - KVM: Clean up __kvm_gfn_to_hva_cache_init() and its
    callers (bsc#1133021).

  - KVM: PPC: Book3S HV: Uninit vCPU if vcore creation fails
    (bsc#1061840).

  - KVM: PPC: Book3S PR: Fix -Werror=return-type build
    failure (bsc#1061840).

  - KVM: PPC: Book3S PR: Free shared page if mmu
    initialization fails (bsc#1061840).

  - KVM: SVM: Override default MMIO mask if memory
    encryption is enabled (bsc#1162618).

  - KVM: arm64: Store vcpu on the stack during
    __guest_enter() (bsc#1133021).

  - KVM: fix spectrev1 gadgets (bsc#1164705).

  - KVM: s390: Do not leak kernel stack data in the
    KVM_S390_INTERRUPT ioctl (git-fixes).

  - KVM: s390: ENOTSUPP -> EOPNOTSUPP fixups (bsc#1133021).

  - KVM: s390: Test for bad access register and size at the
    start of S390_MEM_OP (git-fixes).

  - KVM: s390: do not clobber registers during guest
    reset/store status (bsc#1133021).

  - KVM: x86: Protect DR-based index computations from
    Spectre-v1/L1TF attacks (bsc#1164734).

  - KVM: x86: Protect MSR-based index computations from
    Spectre-v1/L1TF attacks in x86.c (bsc#1164733).

  - KVM: x86: Protect MSR-based index computations in
    fixed_msr_to_seg_unit() from Spectre-v1/L1TF attacks
    (bsc#1164731).

  - KVM: x86: Protect MSR-based index computations in pmu.h
    from Spectre-v1/L1TF attacks (bsc#1164732).

  - KVM: x86: Protect ioapic_read_indirect() from
    Spectre-v1/L1TF attacks (bsc#1164728).

  - KVM: x86: Protect ioapic_write_indirect() from
    Spectre-v1/L1TF attacks (bsc#1164729).

  - KVM: x86: Protect kvm_hv_msr_[get|set]_crash_data() from
    Spectre-v1/L1TF attacks (bsc#1164712).

  - KVM: x86: Protect kvm_lapic_reg_write() from
    Spectre-v1/L1TF attacks (bsc#1164730).

  - KVM: x86: Protect pmu_intel.c from Spectre-v1/L1TF
    attacks (bsc#1164735).

  - KVM: x86: Protect x86_decode_insn from Spectre-v1/L1TF
    attacks (bsc#1164705).

  - KVM: x86: Refactor picdev_write() to prevent
    Spectre-v1/L1TF attacks (bsc#1164727).

  - KVM: x86: Remove a spurious export of a static function
    (bsc#1158954).

  - NFC: fdp: fix incorrect free object
    (networking-stable-19_11_10).

  - NFC: pn533: fix bulk-message timeout (bsc#1051510).

  - NFC: pn544: Adjust indentation in
    pn544_hci_check_presence (git-fixes).

  - NFC: st21nfca: fix double free
    (networking-stable-19_11_10).

  - PCI/IOV: Fix memory leak in pci_iov_add_virtfn()
    (git-fixes).

  - PCI/MSI: Return -ENOSPC from
    pci_alloc_irq_vectors_affinity() (bsc#1051510).

  - PCI/switchtec: Fix vep_vector_number ioread width
    (bsc#1051510).

  - PCI: Add DMA alias quirk for Intel VCA NTB
    (bsc#1051510).

  - PCI: Do not disable bridge BARs when assigning bus
    resources (bsc#1051510).

  - PCI: pciehp: Avoid returning prematurely from sysfs
    requests (git-fixes).

  - PCI: rpaphp: Add drc-info support for hotplug slot
    registration (bsc#1157480 ltc#181028).

  - PCI: rpaphp: Annotate and correctly byte swap DRC
    properties (bsc#1157480 ltc#181028).

  - PCI: rpaphp: Avoid a sometimes-uninitialized warning
    (bsc#1157480 ltc#181028).

  - PCI: rpaphp: Correctly match ibm, my-drc-index to
    drc-name when using drc-info (bsc#1157480 ltc#181028).

  - PCI: rpaphp: Do not rely on firmware feature to imply
    drc-info support (bsc#1157480 ltc#181028).

  - PCI: rpaphp: Fix up pointer to first drc-info entry
    (bsc#1157480 ltc#181028).

  - PM / AVS: SmartReflex: NULL check before some freeing
    functions is not needed (bsc#1051510).

  - PM / Domains: Deal with multiple states but no governor
    in genpd (bsc#1051510).

  - RDMA/bnxt_re: Avoid freeing MR resources if dereg fails
    (bsc#1050244).

  - RDMA/bnxt_re: Enable SRIOV VF support on Broadcom's
    57500 adapter series (bsc#1154916).

  - RDMA/bnxt_re: Fix chip number validation Broadcom's Gen
    P5 series (bsc#1157895).

  - RDMA/bnxt_re: Fix missing le16_to_cpu (bsc#1157895).

  - RDMA/cma: Fix unbalanced cm_id reference count during
    address resolve (bsc#1103992).

  - RDMA/hfi1: Fix memory leak in
    _dev_comp_vect_mappings_create (bsc#1114685).

  - RDMA/hns: Bugfix for qpc/cqc timer configuration
    (bsc#1104427 bsc#1126206).

  - RDMA/hns: Correct the value of srq_desc_size
    (bsc#1104427 ).

  - RDMA/hns: Fix to support 64K page for srq (bsc#1104427
    ).

  - RDMA/hns: Prevent memory leaks of eq->buf_list
    (bsc#1104427 ).

  - RDMA/uverbs: Verify MR access flags (bsc#1103992).

  - crypto/dh: Adjust for change of DH_KPP_SECRET_MIN_SIZE
    in 35f7d5225ffcbf1b759f641aec1735e3a89b1914

  - crypto/dh: Remove the fips=1 check in dh.c dh.c is not
    fips-specific and should perform the same regardless of
    this setting.

  - Revert 'HID: add NOGET quirk for Eaton Ellipse MAX UPS'
    (git-fixes).

  - Revert 'Input: synaptics-rmi4 - do not increment rmiaddr
    for SMBus transfers' (bsc#1051510).

  - Revert 'ath10k: fix DMA related firmware crashes on
    multiple devices' (git-fixes).

  - Revert 'locking/pvqspinlock: Do not wait if vCPU is
    preempted' (bsc#1050549).

  - Revert 'mmc: sdhci: Fix incorrect switch to HS mode'
    (bsc#1051510).

  - Revert
    patches.suse/samples-bpf-add-a-test-for-bpf_override_ret
    urn.patch (bsc#1159500)

  - SMB3: Backup intent flag missing from some more ops
    (bsc#1144333).

  - SMB3: Fix crash in SMB2_open_init due to uninitialized
    field in compounding path (bsc#1144333).

  - SMB3: Fix persistent handles reconnect (bsc#1144333).

  - SUNRPC: Fix svcauth_gss_proxy_init() (bsc#1103992).

  - Staging: iio: adt7316: Fix i2c data reading, set the
    data field (bsc#1051510).

  - USB: EHCI: Do not return -EPIPE when hub is disconnected
    (git-fixes).

  - USB: adutux: fix interface sanity check (bsc#1051510).

  - USB: atm: ueagle-atm: add missing endpoint check
    (bsc#1051510).

  - USB: core: add endpoint-blacklist quirk (git-fixes).

  - USB: core: fix check for duplicate endpoints
    (git-fixes).

  - USB: documentation: flags on usb-storage versus UAS
    (bsc#1051510).

  - USB: idmouse: fix interface sanity checks (bsc#1051510).

  - USB: quirks: blacklist duplicate ep on Sound Devices
    USBPre2 (git-fixes).

  - USB: serial: ch341: handle unbound port at reset_resume
    (bsc#1051510).

  - USB: serial: ftdi_sio: add device IDs for U-Blox
    C099-F9P (bsc#1051510).

  - USB: serial: io_edgeport: add missing active-port sanity
    check (bsc#1051510).

  - USB: serial: io_edgeport: fix epic endpoint lookup
    (bsc#1051510).

  - USB: serial: io_edgeport: handle unbound ports on URB
    completion (bsc#1051510).

  - USB: serial: io_edgeport: use irqsave() in USB's
    complete callback (bsc#1051510).

  - USB: serial: ir-usb: add missing endpoint sanity check
    (bsc#1051510).

  - USB: serial: ir-usb: fix IrLAP framing (bsc#1051510).

  - USB: serial: ir-usb: fix link-speed handling
    (bsc#1051510).

  - USB: serial: keyspan: handle unbound ports
    (bsc#1051510).

  - USB: serial: opticon: fix control-message timeouts
    (bsc#1051510).

  - USB: serial: option: Add support for Quectel RM500Q
    (bsc#1051510).

  - USB: serial: option: add Telit ME910G1 0x110a
    composition (git-fixes).

  - USB: serial: option: add ZLP support for 0x1bc7/0x9010
    (git-fixes).

  - USB: serial: option: add support for Quectel RM500Q in
    QDL mode (git-fixes).

  - USB: serial: quatech2: handle unbound ports
    (bsc#1051510).

  - USB: serial: simple: Add Motorola Solutions TETRA
    MTP3xxx and MTP85xx (bsc#1051510).

  - USB: serial: suppress driver bind attributes
    (bsc#1051510).

  - USB: uas: heed CAPACITY_HEURISTICS (bsc#1051510).

  - USB: uas: honor flag to avoid CAPACITY16 (bsc#1051510).

  - Update
    patches.suse/powerpc-xive-Implement-get_irqchip_state-me
    thod-for-.patch (bsc#1085030).

  - af_packet: set defaule value for tmo (bsc#1051510).

  - apparmor: fix unsigned len comparison with less than
    zero (git-fixes).

  - ar5523: check NULL before memcpy() in ar5523_cmd()
    (bsc#1051510).

  - arm64: Revert support for execute-only user mappings
    (bsc#1160218).

  - ata: ahci: Add shutdown to freeze hardware resources of
    ahci (bsc#1164388).

  - ath10k: Correct the DMA direction for management tx
    buffers (bsc#1111666).

  - ath10k: fix fw crash by moving chip reset after napi
    disabled (bsc#1051510).

  - ath10k: pci: Fix comment on ath10k_pci_dump_memory_sram
    (bsc#1111666).

  - ath10k: pci: Only dump ATH10K_MEM_REGION_TYPE_IOREG when
    safe (bsc#1111666).

  - ath6kl: Fix off by one error in scan completion
    (bsc#1051510).

  - ath9k: fix storage endpoint lookup (git-fixes).

  - atl1e: checking the status of atl1e_write_phy_reg
    (bsc#1051510).

  - audit: Allow auditd to set pid to 0 to end auditing
    (bsc#1158094).

  - batman-adv: Fix DAT candidate selection on little endian
    systems (bsc#1051510).

  - bcache: Fix an error code in bch_dump_read()
    (bsc#1163762).

  - bcache: Revert 'bcache: shrink btree node cache after
    bch_btree_check()' (bsc#1163762, bsc#1112504).

  - bcache: add code comment bch_keylist_pop() and
    bch_keylist_pop_front() (bsc#1163762).

  - bcache: add code comments for state->pool in
    __btree_sort() (bsc#1163762).

  - bcache: add code comments in bch_btree_leaf_dirty()
    (bsc#1163762).

  - bcache: add cond_resched() in __bch_cache_cmp()
    (bsc#1163762).

  - bcache: add idle_max_writeback_rate sysfs interface
    (bsc#1163762).

  - bcache: add more accurate error messages in read_super()
    (bsc#1163762).

  - bcache: add readahead cache policy options via sysfs
    interface (bsc#1163762).

  - bcache: at least try to shrink 1 node in bch_mca_scan()
    (bsc#1163762).

  - bcache: avoid unnecessary btree nodes flushing in
    btree_flush_write() (bsc#1163762).

  - bcache: check return value of prio_read() (bsc#1163762).

  - bcache: deleted code comments for dead code in
    bch_data_insert_keys() (bsc#1163762).

  - bcache: do not export symbols (bsc#1163762).

  - bcache: explicity type cast in bset_bkey_last()
    (bsc#1163762).

  - bcache: fix a lost wake-up problem caused by
    mca_cannibalize_lock (bsc#1163762).

  - bcache: fix deadlock in bcache_allocator (bsc#1163762).

  - bcache: fix incorrect data type usage in
    btree_flush_write() (bsc#1163762).

  - bcache: fix memory corruption in
    bch_cache_accounting_clear() (bsc#1163762).

  - bcache: fix static checker warning in
    bcache_device_free() (bsc#1163762).

  - bcache: ignore pending signals when creating gc and
    allocator thread (bsc#1163762, bsc#1112504).

  - bcache: print written and keys in
    trace_bcache_btree_write (bsc#1163762).

  - bcache: reap c->btree_cache_freeable from the tail in
    bch_mca_scan() (bsc#1163762).

  - bcache: reap from tail of c->btree_cache in
    bch_mca_scan() (bsc#1163762).

  - bcache: remove macro nr_to_fifo_front() (bsc#1163762).

  - bcache: remove member accessed from struct btree
    (bsc#1163762).

  - bcache: remove the extra cflags for request.o
    (bsc#1163762).

  - bcma: remove set but not used variable 'sizel'
    (git-fixes).

  - blk-mq: avoid sysfs buffer overflow with too many CPU
    cores (bsc#1159377).

  - blk-mq: avoid sysfs buffer overflow with too many CPU
    cores (bsc#1163840).

  - blk-mq: make sure that line break can be printed
    (bsc#1159377).

  - blk-mq: make sure that line break can be printed
    (bsc#1164098).

  - bnxt: apply computed clamp value for coalece parameter
    (bsc#1104745).

  - bnxt_en: Fix MSIX request logic for RDMA driver
    (bsc#1104745 ).

  - bnxt_en: Fix NTUPLE firmware command failures
    (bsc#1104745 ).

  - bnxt_en: Fix TC queue mapping
    (networking-stable-20_02_05).

  - bnxt_en: Improve device shutdown method (bsc#1104745 ).

  - bnxt_en: Issue PCIe FLR in kdump kernel to cleanup
    pending DMAs (bsc#1134090 jsc#SLE-5954).

  - bnxt_en: Return error if FW returns more data than dump
    length (bsc#1104745).

  - bonding: fix active-backup transition after link failure
    (git-fixes).

  - bonding: fix potential NULL deref in
    bond_update_slave_arr (bsc#1051510).

  - bonding: fix slave stuck in BOND_LINK_FAIL state
    (networking-stable-19_11_10).

  - bonding: fix state transition issue in link monitoring
    (networking-stable-19_11_10).

  - bonding: fix unexpected IFF_BONDING bit unset
    (bsc#1051510).

  - bpf, offload: Replace bitwise AND by logical AND in
    bpf_prog_offload_info_fill (bsc#1109837).

  - bpf, offload: Unlock on error in
    bpf_offload_dev_create() (bsc#1109837).

  - bpf/sockmap: Read psock ingress_msg before
    sk_receive_queue (bsc#1083647).

  - bpf/stackmap: Fix deadlock with rq_lock in
    bpf_get_stack() (bsc#1083647).

  - bpf: Fix incorrect verifier simulation of ARSH under
    ALU32 (bsc#1083647).

  - bpf: Make use of probe_user_write in probe write helper
    (bsc#1083647).

  - bpf: Reject indirect var_off stack access in raw mode
    (bsc#1160618).

  - bpf: Reject indirect var_off stack access in unpriv mode
    (bco#1160618).

  - bpf: Sanity check max value for var_off stack access
    (bco#1160618).

  - bpf: Support variable offset stack access from helpers
    (bco#1160618).

  - bpf: add self-check logic to liveness analysis
    (bsc#1160618).

  - bpf: add verifier stats and log_level bit 2
    (bsc#1160618).

  - bpf: improve stacksafe state comparison (bco#1160618).

  - bpf: improve verification speed by droping states
    (bsc#1160618).

  - bpf: improve verification speed by not remarking
    live_read (bsc#1160618).

  - bpf: improve verifier branch analysis (bsc#1160618).

  - bpf: increase complexity limit and maximum program size
    (bsc#1160618).

  - bpf: increase verifier log limit (bsc#1160618).

  - bpf: skmsg, fix potential psock NULL pointer dereference
    (bsc#1109837).

  - bpf: speed up stacksafe check (bco#1160618).

  - bpf: verifier: teach the verifier to reason about the
    BPF_JSET instruction (bco#1160618).

  - brcmfmac: Fix memory leak in brcmf_p2p_create_p2pdev()
    (bsc#1111666).

  - brcmfmac: Fix memory leak in brcmf_usbdev_qinit
    (git-fixes).

  - brcmfmac: Fix use after free in brcmf_sdio_readframes()
    (git-fixes).

  - brcmfmac: fix interface sanity check (git-fixes).

  - brcmfmac: sdio: Fix OOB interrupt initialization on
    brcm43362 (bsc#1111666).

  - brcmfmac: set F2 watermark to 256 for 4373
    (bsc#1111666).

  - brcmfmac: set SDIO F1 MesBusyCtrl for CYW4373
    (bsc#1111666).

  - btrfs: Ensure we trim ranges across block group boundary
    (bsc#1151910).

  - btrfs: Move btrfs_check_chunk_valid() to tree-check.[ch]
    and export it (dependency for bsc#1157692).

  - btrfs: abort transaction after failed inode updates in
    create_subvol (bsc#1161936).

  - btrfs: dev-replace: remove warning for unknown return
    codes when finished (dependency for bsc#1162067).

  - btrfs: do not call synchronize_srcu() in inode_tree_del
    (bsc#1161934).

  - btrfs: do not double lock the subvol_sem for rename
    exchange (bsc#1162943).

  - btrfs: fix integer overflow in calc_reclaim_items_nr
    (bsc#1160433).

  - btrfs: handle ENOENT in btrfs_uuid_tree_iterate
    (bsc#1161937).

  - btrfs: harden agaist duplicate fsid on scanned devices
    (bsc#1134973).

  - btrfs: inode: Verify inode mode to avoid NULL pointer
    dereference (dependency for bsc#1157692).

  - btrfs: record all roots for rename exchange on a subvol
    (bsc#1161933).

  - btrfs: relocation: fix reloc_root lifespan and access
    (bsc#1159588).

  - btrfs: scrub: Require mandatory block group RO for
    dev-replace (bsc#1162067).

  - btrfs: simplify inode locking for RWF_NOWAIT
    (git-fixes).

  - btrfs: skip log replay on orphaned roots (bsc#1161935).

  - btrfs: tree-checker: Check chunk item at tree block read
    time (dependency for bsc#1157692).

  - btrfs: tree-checker: Check level for leaves and nodes
    (dependency for bsc#1157692).

  - btrfs: tree-checker: Enhance chunk checker to validate
    chunk profile (dependency for bsc#1157692).

  - btrfs: tree-checker: Fix wrong check on max devid (fixes
    for dependency of bsc#1157692).

  - btrfs: tree-checker: Make btrfs_check_chunk_valid()
    return EUCLEAN instead of EIO (dependency for
    bsc#1157692).

  - btrfs: tree-checker: Make chunk item checker messages
    more readable (dependency for bsc#1157692).

  - btrfs: tree-checker: Verify dev item (dependency for
    bsc#1157692).

  - btrfs: tree-checker: Verify inode item (dependency for
    bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    block_group_err (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_block_group_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_csum_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_dev_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_dir_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_extent_data_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_inode_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    check_leaf_item (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in dev_item_err
    (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in dir_item_err
    (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in
    file_extent_err (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in check_leaf
    (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in chunk_err
    (dependency for bsc#1157692).

  - btrfs: tree-checker: get fs_info from eb in generic_err
    (dependency for bsc#1157692).

  - btrfs: volumes: Use more straightforward way to
    calculate map length (bsc#1151910).

  - can, slip: Protect tty->disc_data in write_wakeup and
    close with RCU (bsc#1051510).

  - can: c_can: D_CAN: c_can_chip_config(): perform a
    sofware reset on open (bsc#1051510).

  - can: can_dropped_invalid_skb(): ensure an initialized
    headroom in outgoing CAN sk_buffs (bsc#1051510).

  - can: gs_usb: gs_usb_probe(): use descriptors of current
    altsetting (bsc#1051510).

  - can: mscan: mscan_rx_poll(): fix rx path lockup when
    returning from polling to irq mode (bsc#1051510).

  - can: peak_usb: report bus recovery as well
    (bsc#1051510).

  - can: rx-offload: can_rx_offload_irq_offload_fifo():
    continue on error (bsc#1051510).

  - can: rx-offload: can_rx_offload_irq_offload_timestamp():
    continue on error (bsc#1051510).

  - can: rx-offload: can_rx_offload_offload_one(): increment
    rx_fifo_errors on queue overflow or OOM (bsc#1051510).

  - can: rx-offload: can_rx_offload_offload_one(): use
    ERR_PTR() to propagate error value in case of errors
    (bsc#1051510).

  - can: slcan: Fix use-after-free Read in slcan_open
    (bsc#1051510).

  - cdrom: respect device capabilities during opening action
    (boo#1164632).

  - cfg80211/mac80211: make ieee80211_send_layer2_update a
    public function (bsc#1051510).

  - cfg80211: check for set_wiphy_params (bsc#1051510).

  - cfg80211: fix deadlocks in autodisconnect work
    (bsc#1111666).

  - cfg80211: fix memory leak in cfg80211_cqm_rssi_update
    (bsc#1111666).

  - cfg80211: fix page refcount issue in A-MSDU decap
    (bsc#1051510).

  - cgroup: pids: use atomic64_t for pids->limit
    (bsc#1161514).

  - chardev: Avoid potential use-after-free in
    'chrdev_open()' (bsc#1163849).

  - cifs: Add tracepoints for errors on flush or fsync
    (bsc#1144333).

  - cifs: Adjust indentation in smb2_open_file
    (bsc#1144333).

  - cifs: Avoid doing network I/O while holding cache lock
    (bsc#1144333).

  - cifs: Clean up DFS referral cache (bsc#1144333).

  - cifs: Do not display RDMA transport on reconnect
    (bsc#1144333).

  - cifs: Fix lookup of root ses in DFS referral cache
    (bsc#1144333).

  - cifs: Fix memory allocation in
    __smb2_handle_cancelled_cmd() (bsc#1144333).

  - cifs: Fix memory allocation in
    __smb2_handle_cancelled_cmd() (bsc#1144333).

  - cifs: Fix mode output in debugging statements
    (bsc#1144333).

  - cifs: Fix mount options set in automount (bsc#1144333).

  - cifs: Fix mount options set in automount (bsc#1144333).

  - cifs: Fix potential deadlock when updating vol in
    cifs_reconnect() (bsc#1144333).

  - cifs: Fix potential softlockups while refreshing DFS
    cache (bsc#1144333).

  - cifs: Fix retrieval of DFS referrals in cifs_mount()
    (bsc#1144333).

  - cifs: Fix return value in __update_cache_entry
    (bsc#1144333).

  - cifs: Fix use-after-free bug in cifs_reconnect()
    (bsc#1144333).

  - cifs: Get rid of kstrdup_const()'d paths (bsc#1144333).

  - cifs: Introduce helpers for finding TCP connection
    (bsc#1144333).

  - cifs: Merge is_path_valid() into get_normalized_path()
    (bsc#1144333).

  - cifs: Optimize readdir on reparse points (bsc#1144333).

  - cifs: Use #define in cifs_dbg (bsc#1144333).

  - cifs: add SMB2_open() arg to return POSIX data
    (bsc#1144333).

  - cifs: add SMB3 change notification support
    (bsc#1144333).

  - cifs: add a debug macro that prints \\server\share for
    errors (bsc#1144333).

  - cifs: add missing mount option to /proc/mounts
    (bsc#1144333).

  - cifs: add new debugging macro cifs_server_dbg
    (bsc#1144333).

  - cifs: add passthrough for smb2 setinfo (bsc#1144333).

  - cifs: add smb2 POSIX info level (bsc#1144333).

  - cifs: add support for fallocate mode 0 for non-sparse
    files (bsc#1144333).

  - cifs: add support for flock (bsc#1144333).

  - cifs: allow chmod to set mode bits using special sid
    (bsc#1144333).

  - cifs: call wake_up(&server->response_q) inside of
    cifs_reconnect() (bsc#1144333).

  - cifs: close the shared root handle on tree disconnect
    (bsc#1144333).

  - cifs: create a helper function to parse the
    query-directory response buffer (bsc#1144333).

  - cifs: do d_move in rename (bsc#1144333).

  - cifs: do not ignore the SYNC flags in getattr
    (bsc#1144333).

  - cifs: do not leak -EAGAIN for stat() during reconnect
    (bsc#1144333).

  - cifs: do not use 'pre:' for MODULE_SOFTDEP
    (bsc#1144333).

  - cifs: enable change notification for SMB2.1 dialect
    (bsc#1144333).

  - cifs: fail i/o on soft mounts if sessionsetup errors out
    (bsc#1144333).

  - cifs: fix NULL dereference in match_prepath
    (bsc#1144333).

  - cifs: fix a comment for the timeouts when sending echos
    (bsc#1144333).

  - cifs: fix dereference on ses before it is null checked
    (bsc#1144333).

  - cifs: fix mode bits from dir listing when mounted with
    modefromsid (bsc#1144333).

  - cifs: fix mount option display for sec=krb5i
    (bsc#1161907).

  - cifs: fix potential mismatch of UNC paths (bsc#1144333).

  - cifs: fix rename() by ensuring source handle opened with
    DELETE bit (bsc#1144333).

  - cifs: fix soft mounts hanging in the reconnect code
    (bsc#1144333).

  - cifs: fix soft mounts hanging in the reconnect code
    (bsc#1144333).

  - cifs: fix uninitialized variable poential problem with
    network I/O cache lock patch (bsc#1144333).

  - cifs: get mode bits from special sid on stat
    (bsc#1144333).

  - cifs: handle prefix paths in reconnect (bsc#1144333).

  - cifs: log warning message (once) if out of disk space
    (bsc#1144333).

  - cifs: make sure we do not overflow the max EA buffer
    size (bsc#1144333).

  - cifs: make use of cap_unix(ses) in cifs_reconnect_tcon()
    (bsc#1144333).

  - cifs: modefromsid: make room for 4 ACE (bsc#1144333).

  - cifs: modefromsid: write mode ACE first (bsc#1144333).

  - cifs: plumb smb2 POSIX dir enumeration (bsc#1144333).

  - cifs: potential unintitliazed error code in
    cifs_getattr() (bsc#1144333).

  - cifs: prepare SMB2_query_directory to be used with
    compounding (bsc#1144333).

  - cifs: print warning once if mounting with vers=1.0
    (bsc#1144333).

  - cifs: remove redundant assignment to pointer pneg_ctxt
    (bsc#1144333).

  - cifs: remove redundant assignment to variable rc
    (bsc#1144333).

  - cifs: remove set but not used variable 'server'
    (bsc#1144333).

  - cifs: remove set but not used variables (bsc#1144333).

  - cifs: remove unused variable 'sid_user' (bsc#1144333).

  - cifs: remove unused variable (bsc#1144333).

  - cifs: rename a variable in SendReceive() (bsc#1144333).

  - cifs: rename posix create rsp (bsc#1144333).

  - cifs: replace various strncpy with strscpy and similar
    (bsc#1144333).

  - cifs: set correct max-buffer-size for smb2_ioctl_init()
    (bsc#1144333).

  - cifs: smbd: Add messages on RDMA session destroy and
    reconnection (bsc#1144333).

  - cifs: smbd: Invalidate and deregister memory
    registration on re-send for direct I/O (bsc#1144333).

  - cifs: smbd: Only queue work for error recovery on memory
    registration (bsc#1144333).

  - cifs: smbd: Return -EAGAIN when transport is
    reconnecting (bsc#1144333).

  - cifs: smbd: Return -ECONNABORTED when trasnport is not
    in connected state (bsc#1144333).

  - cifs: smbd: Return -EINVAL when the number of iovs
    exceeds SMBDIRECT_MAX_SGE (bsc#1144333).

  - cifs: use PTR_ERR_OR_ZERO() to simplify code
    (bsc#1144333).

  - cifs: use compounding for open and first query-dir for
    readdir() (bsc#1144333).

  - cifs: use mod_delayed_work() for &server->reconnect if
    already queued (bsc#1144333).

  - clk: Do not try to enable critical clocks if prepare
    failed (bsc#1051510).

  - clk: imx: clk-composite-8m: add lock to gate/mux
    (git-fixes).

  - clk: mmp2: Fix the order of timer mux parents
    (bsc#1051510).

  - clk: qcom: rcg2: Do not crash if our parent can't be
    found; return an error (bsc#1051510).

  - clk: rockchip: fix I2S1 clock gate register for rk3328
    (bsc#1051510).

  - clk: rockchip: fix ID of 8ch clock of I2S1 for rk3328
    (bsc#1051510).

  - clk: rockchip: fix rk3188 sclk_mac_lbtest parameter
    ordering (bsc#1051510).

  - clk: rockchip: fix rk3188 sclk_smc gate data
    (bsc#1051510).

  - clk: sunxi-ng: add mux and pll notifiers for A64 CPU
    clock (bsc#1051510).

  - clk: sunxi: sun9i-mmc: Implement reset callback for
    reset controls (bsc#1051510).

  - clk: tegra: Mark fuse clock as critical (bsc#1051510).

  - clocksource/drivers/bcm2835_timer: Fix memory leak of
    timer (bsc#1051510).

  - clocksource: Prevent double add_timer_on() for
    watchdog_timer (bsc#1051510).

  - closures: fix a race on wakeup from closure_sync
    (bsc#1163762).

  - cls_rsvp: fix rsvp_policy (networking-stable-20_02_05).

  - configfs_register_group() shouldn't be (and isn't)
    called in rmdirable parts (bsc#1051510).

  - copy/pasted 'Recommends:' instead of 'Provides:',
    'Obsoletes:' and 'Conflicts :

  - core: Do not skip generic XDP program execution for
    cloned SKBs (bsc#1109837).

  - crypto: DRBG - add FIPS 140-2 CTRNG for noise source
    (bsc#1155334).

  - crypto: af_alg - Use bh_lock_sock in sk_destruct
    (bsc#1051510).

  - crypto: api - Check spawn->alg under lock in
    crypto_drop_spawn (bsc#1051510).

  - crypto: api - Fix race condition in crypto_spawn_alg
    (bsc#1051510).

  - crypto: atmel-sha - fix error handling when setting hmac
    key (bsc#1051510).

  - crypto: caam/qi2 - fix typo in algorithm's driver name
    (bsc#1111666).

  - crypto: ccp - fix uninitialized list head (bsc#1051510).

  - crypto: chelsio - fix writing tfm flags to wrong place
    (bsc#1051510).

  - crypto: dh - add public key verification test
    (bsc#1155331).

  - crypto: dh - fix calculating encoded key size
    (bsc#1155331).

  - crypto: dh - fix memory leak (bsc#1155331).

  - crypto: dh - update test for public key verification
    (bsc#1155331).

  - crypto: ecdh - add public key verification test
    (bsc#1155331).

  - crypto: ecdh - fix typo of P-192 b value (bsc#1155331).

  - crypto: mxc-scc - fix build warnings on ARM64
    (bsc#1051510).

  - crypto: pcrypt - Do not clear MAY_SLEEP flag in original
    request (bsc#1051510).

  - crypto: picoxcell - adjust the position of tasklet_init
    and fix missed tasklet_kill (bsc#1051510).

  - crypto: reexport crypto_shoot_alg() (bsc#1051510, kABI
    fix).

  - cxgb4: request the TX CIDX updates to status page
    (bsc#1127371).

  - devlink: report 0 after hitting end in region read
    (bsc#1109837).

  - dma-buf: Fix memory leak in sync_file_merge()
    (git-fixes).

  - dma-mapping: fix return type of dma_set_max_seg_size()
    (bsc#1051510).

  - dmaengine: Fix access to uninitialized dma_slave_caps
    (bsc#1051510).

  - dmaengine: coh901318: Fix a double-lock bug
    (bsc#1051510).

  - dmaengine: coh901318: Remove unused variable
    (bsc#1051510).

  - drivers/base/memory.c: cache blocks in radix tree to
    accelerate lookup (bsc#1159955 ltc#182993).

  - drivers/base/memory.c: do not access uninitialized
    memmaps in soft_offline_page_store() (bsc#1051510).

  - drivers/base/platform.c: kmemleak ignore a known leak
    (bsc#1051510).

  - drivers/regulator: fix a missing check of return value
    (bsc#1051510).

  - drm/amd/display: Retrain dongles when SINK_COUNT becomes
    non-zero (bsc#1111666).

  - drm/amd/powerplay: remove set but not used variable
    'us_mvdd' (bsc#1111666).

  - drm/amdgpu/(uvd,vcn): fetch ring's read_ptr after alloc
    (bsc#1111666).

  - drm/amdgpu: add function parameter description in
    'amdgpu_device_set_cg_state' (bsc#1111666).

  - drm/amdgpu: add function parameter description in
    'amdgpu_gart_bind' (bsc#1051510).

  - drm/amdgpu: fix bad DMA from INTERRUPT_CNTL2
    (bsc#1114279)

  - drm/amdgpu: fix ring test failure issue during s3 in vce
    3.0 (V2) (bsc#1111666).

  - drm/amdgpu: remove 4 set but not used variable in
    amdgpu_atombios_get_connector_info_from_object_table
    (bsc#1051510).

  - drm/amdgpu: remove always false comparison in
    'amdgpu_atombios_i2c_process_i2c_ch' (bsc#1051510).

  - drm/amdgpu: remove set but not used variable
    'amdgpu_connector' (bsc#1051510).

  - drm/amdgpu: remove set but not used variable 'dig'
    (bsc#1051510).

  - drm/amdgpu: remove set but not used variable
    'dig_connector' (bsc#1051510).

  - drm/amdgpu: remove set but not used variable 'invalid'
    (bsc#1111666).

  - drm/amdgpu: remove set but not used variable
    'mc_shared_chmap' (bsc#1051510).

  - drm/amdgpu: remove set but not used variable
    'mc_shared_chmap' from 'gfx_v6_0.c' and 'gfx_v7_0.c'
    (bsc#1051510).

  - drm/amdkfd: fix a use after free race with mmu_notifer
    unregister (bsc#1114279)

  - drm/dp_mst: correct the shifting in DP_REMOTE_I2C_READ
    (bsc#1051510).

  - drm/etnaviv: fix dumping of iommuv2 (bsc#1114279)

  - drm/fb-helper: Round up bits_per_pixel if possible
    (bsc#1051510).

  - drm/i810: Prevent underflow in ioctl (bsc#1114279)

  - drm/i915/gvt: Pin vgpu dma address before using
    (bsc#1112178)

  - drm/i915/gvt: Separate display reset from ALL_ENGINES
    reset (bsc#1114279)

  - drm/i915/gvt: set guest display buffer as readonly
    (bsc#1112178)

  - drm/i915/gvt: use vgpu lock for active state setting
    (bsc#1112178)

  - drm/i915/perf: add missing delay for OA muxes
    configuration (bsc#1111666).

  - drm/i915/userptr: Try to acquire the page lock around
    (bsc#1114279)

  - drm/i915/userptr: fix size calculation (bsc#1114279)

  - drm/i915: Add missing include file <linux/math64.h>
    (bsc#1051510).

  - drm/i915: Call dma_set_max_seg_size() in
    i915_driver_hw_probe() (bsc#1111666).

  - drm/i915: Fix pid leak with banned clients (bsc#1114279)

  - drm/i915: Handle vm_mmap error during I915_GEM_MMAP
    ioctl with WC set (bsc#1111666).

  - drm/i915: Make sure cdclk is high enough for DP audio on
    VLV/CHV (bsc#1111666).

  - drm/i915: Reacquire priolist cache after dropping the
    engine lock (bsc#1129770) Fixes a const function
    argument in the patch.

  - drm/i915: Sanity check mmap length against object size
    (bsc#1111666).

  - drm/i915: Wean off drm_pci_alloc/drm_pci_free
    (bsc#1114279)

  - drm/mediatek: Add gamma property according to hardware
    capability (bsc#1114279)

  - drm/mediatek: disable all the planes in atomic_disable
    (bsc#1114279)

  - drm/mipi_dbi: Fix off-by-one bugs in mipi_dbi_blank()
    (bsc#1114279)

  - drm/msm: include linux/sched/task.h (bsc#1112178)

  - drm/mst: Fix MST sideband up-reply failure handling
    (bsc#1051510).

  - drm/nouveau/bar/gf100: ensure BAR is mapped
    (bsc#1111666).

  - drm/nouveau/bar/nv50: check bar1 vmm return value
    (bsc#1111666).

  - drm/nouveau/mmu: qualify vmm during dtor (bsc#1111666).

  - drm/nouveau/secboot/gm20b: initialize pointer in
    gm20b_secboot_new() (bsc#1051510).

  - drm/nouveau: Fix copy-paste error in
    nouveau_fence_wait_uevent_handler (bsc#1051510).

  - drm/qxl: Return error if fbdev is not 32 bpp
    (bsc#1159028)

  - drm/qxl: Return error if fbdev is not 32 bpp
    (bsc#1159028)

  - drm/radeon: fix r1xx/r2xx register checker for POT
    textures (bsc#1114279)

  - drm/rect: Avoid division by zero (bsc#1111666).

  - drm/rect: update kerneldoc for drm_rect_clip_scaled()
    (bsc#1111666).

  - drm/rockchip: Round up _before_ giving to the clock
    framework (bsc#1114279)

  - drm/rockchip: lvds: Fix indentation of a #define
    (bsc#1051510).

  - drm/sun4i: hdmi: Remove duplicate cleanup calls
    (bsc#1113956)

  - drm/sun4i: tcon: Set RGB DCLK min. divider based on
    hardware model (bsc#1111666).

  - drm/sun4i: tcon: Set min division of TCON0_DCLK to 1
    (bsc#1111666).

  - drm/ttm: ttm_tt_init_fields() can be static
    (bsc#1111666).

  - drm/vmwgfx: prevent memory leak in vmw_cmdbuf_res_add
    (bsc#1051510).

  - drm: atmel-hlcdc: enable clock before configuring timing
    engine (bsc#1114279)

  - drm: bridge: dw-hdmi: constify copied structure
    (bsc#1051510).

  - drm: limit to INT_MAX in create_blob ioctl
    (bsc#1051510).

  - drm: meson: venc: cvbs: fix CVBS mode matching
    (bsc#1051510).

  - drm: msm: mdp4: Adjust indentation in
    mdp4_dsi_encoder_enable (bsc#1111666).

  - drm: msm: mdp4: Adjust indentation in
    mdp4_dsi_encoder_enable (bsc#1114279)

  - drm: panel-lvds: Potential Oops in probe error handling
    (bsc#1114279)

  - drm: rcar-du: Recognize 'renesas,vsps' in addition to
    'vsps' (bsc#1114279)

  - e1000e: Add support for Comet Lake (bsc#1158533).

  - e1000e: Add support for Tiger Lake (bsc#1158533).

  - e1000e: Increase pause and refresh time (bsc#1158533).

  - e100: Fix passing zero to 'PTR_ERR' warning in
    e100_load_ucode_wait (bsc#1051510).

  - enic: prevent waking up stopped tx queues over watchdog
    reset (bsc#1133147).

  - ethtool: Factored out similar ethtool link settings for
    virtual devices to core (bsc#1136157 ltc#177197).

  - exit: panic before exit_mm() on global init exit
    (bsc#1161549).

  - ext2: check err when partial != NULL (bsc#1163859).

  - ext4, jbd2: ensure panic when aborting with zero errno
    (bsc#1163853).

  - ext4: Fix mount failure with quota configured as module
    (bsc#1164471).

  - ext4: check for directory entries too close to block end
    (bsc#1163861).

  - ext4: fix a bug in ext4_wait_for_tail_page_commit
    (bsc#1163841).

  - ext4: fix checksum errors with indexed dirs
    (bsc#1160979).

  - ext4: fix deadlock allocating crypto bounce page from
    mempool (bsc#1163842).

  - ext4: fix mount failure with quota configured as module
    (bsc#1164471).

  - ext4: improve explanation of a mount failure caused by a
    misconfigured kernel (bsc#1163843).

  - extcon: max8997: Fix lack of path setting in USB device
    mode (bsc#1051510).

  - firestream: fix memory leaks (bsc#1051510).

  - fix autofs regression caused by follow_managed() changes
    (bsc#1159271).

  - fix dget_parent() fastpath race (bsc#1159271).

  - fix memory leak in large read decrypt offload
    (bsc#1144333).

  - fjes: fix missed check in fjes_acpi_add (bsc#1051510).

  - fs/cifs/cifssmb.c: use true,false for bool variable
    (bsc#1144333).

  - fs/cifs/sess.c: Remove set but not used variable
    'capabilities' (bsc#1144333).

  - fs/cifs/smb2ops.c: use true,false for bool variable
    (bsc#1144333).

  - fs/cifs/smb2pdu.c: Make SMB2_notify_init static
    (bsc#1144333).

  - fs/namei.c: fix missing barriers when checking
    positivity (bsc#1159271).

  - fs/namei.c: pull positivity check into follow_managed()
    (bsc#1159271).

  - fs/open.c: allow opening only regular files during
    execve() (bsc#1163845).

  - fs: cifs: Fix atime update check vs mtime (bsc#1144333).

  - fs: cifs: Initialize filesystem timestamp ranges
    (bsc#1144333).

  - fs: cifs: cifsssmb: remove redundant assignment to
    variable ret (bsc#1144333).

  - fs: cifs: mute -Wunused-const-variable message
    (bsc#1144333).

  - fscrypt: do not set policy for a dead directory
    (bsc#1163846).

  - ftrace: Add comment to why rcu_dereference_sched() is
    open coded (git-fixes).

  - ftrace: Avoid potential division by zero in function
    profiler (bsc#1160784).

  - ftrace: Protect ftrace_graph_hash with ftrace_sync
    (git-fixes).

  - genirq/proc: Return proper error code when
    irq_set_affinity() fails (bnc#1105392).

  - genirq: Prevent NULL pointer dereference in
    resend_irqs() (bsc#1051510).

  - genirq: Properly pair kobject_del() with kobject_add()
    (bsc#1051510).

  - gpio: Fix error message on out-of-range GPIO in lookup
    table (bsc#1051510).

  - gtp: avoid zero size hashtable
    (networking-stable-20_01_01).

  - gtp: do not allow adding duplicate tid and ms_addr pdp
    context (networking-stable-20_01_01).

  - gtp: fix an use-after-free in ipv4_pdp_find()
    (networking-stable-20_01_01).

  - gtp: fix wrong condition in gtp_genl_dump_pdp()
    (networking-stable-20_01_01).

  - gtp: make sure only SOCK_DGRAM UDP sockets are accepted
    (networking-stable-20_01_27).

  - gtp: use __GFP_NOWARN to avoid memalloc warning
    (networking-stable-20_02_05).

  - hidraw: Return EPOLLOUT from hidraw_poll (bsc#1051510).

  - hotplug/drc-info: Add code to search ibm,drc-info
    property (bsc#1157480 ltc#181028).

  - hv_netvsc: Fix memory leak when removing rndis device
    (networking-stable-20_01_20).

  - hv_netvsc: Fix offset usage in netvsc_send_table()
    (bsc#1164598).

  - hv_netvsc: Fix send_table offset in case of a host bug
    (bsc#1164598).

  - hv_netvsc: Fix tx_table init in rndis_set_subchannel()
    (bsc#1164598).

  - hv_netvsc: Fix unwanted rx_table reset (bsc#1164598).

  - hwmon: (adt7475) Make volt2reg return same reg as
    reg2volt input (bsc#1051510).

  - hwmon: (core) Do not use device managed functions for
    memory allocations (bsc#1051510).

  - hwmon: (k10temp) Add support for AMD family 17h, model
    70h CPUs (bsc#1163206).

  - hwmon: (nct7802) Fix voltage limits to wrong registers
    (bsc#1051510).

  - hwmon: (pmbus/ltc2978) Fix PMBus polling of MFR_COMMON
    definitions (bsc#1051510).

  - hwrng: stm32 - fix unbalanced pm_runtime_enable
    (bsc#1051510).

  - i2c: imx: do not print error message on probe defer
    (bsc#1051510).

  - ibmveth: Detect unsupported packets before sending to
    the hypervisor (bsc#1159484 ltc#182983).

  - ibmvfc: Fix NULL return compiler warning (bsc#1161951
    ltc#183551).

  - ibmvnic: Bound waits for device queries (bsc#1155689
    ltc#182047).

  - ibmvnic: Fix completion structure initialization
    (bsc#1155689 ltc#182047).

  - ibmvnic: Serialize device queries (bsc#1155689
    ltc#182047).

  - ibmvnic: Terminate waiting device threads after loss of
    service (bsc#1155689 ltc#182047).

  - ice: fix stack leakage (bsc#1118661).

  - idr: Fix idr_alloc_u32 on 32-bit systems (bsc#1051510).

  - iio: adc: max9611: Fix too short conversion time delay
    (bsc#1051510).

  - iio: buffer: align the size of scan bytes to size of the
    largest element (bsc#1051510).

  - inet: protect against too small mtu values
    (networking-stable-19_12_16).

  - iommu/amd: Fix IOMMU perf counter clobbering during init
    (bsc#1162617).

  - iommu/arm-smmu-v3: Populate VMID field for
    CMDQ_OP_TLBI_NH_VA (bsc#1164314).

  - iommu/io-pgtable-arm: Fix race handling in
    split_blk_unmap() (bsc#1164115).

  - iommu/iova: Init the struct iova to fix the possible
    memleak (bsc#1160469).

  - iommu/mediatek: Correct the flush_iotlb_all callback
    (bsc#1160470).

  - iommu/vt-d: Unlink device if failed to add to group
    (bsc#1160756).

  - iommu: Remove device link to group on failure
    (bsc#1160755).

  - ipmi: Do not allow device module unload when in use
    (bsc#1154768).

  - ipv4: Fix table id reference in fib_sync_down_addr
    (networking-stable-19_11_10).

  - ipv4: ensure rcu_read_lock() in cipso_v4_error()
    (git-fixes).

  - ipv6: restrict IPV6_ADDRFORM operation (bsc#1109837).

  - iwlegacy: ensure loop counter addr does not wrap and
    cause an infinite loop (git-fixes).

  - iwlwifi: change monitor DMA to be coherent
    (bsc#1161243).

  - iwlwifi: clear persistence bit according to device
    family (bsc#1111666).

  - iwlwifi: do not throw error when trying to remove IGTK
    (bsc#1051510).

  - iwlwifi: mvm: Send non offchannel traffic via AP sta
    (bsc#1051510).

  - iwlwifi: mvm: fix NVM check for 3168 devices
    (bsc#1051510).

  - iwlwifi: mvm: force TCM re-evaluation on TCM resume
    (bsc#1111666).

  - iwlwifi: mvm: synchronize TID queue removal
    (bsc#1051510).

  - iwlwifi: pcie: fix erroneous print (bsc#1111666).

  - iwlwifi: trans: Clear persistence bit when starting the
    FW (bsc#1111666).

  - jbd2: Fix possible overflow in jbd2_log_space_left()
    (bsc#1163860).

  - jbd2: clear JBD2_ABORT flag before journal_reset to
    update log tail info when load journal (bsc#1163862).

  - jbd2: do not clear the BH_Mapped flag when forgetting a
    metadata buffer (bsc#1163836).

  - jbd2: make sure ESHUTDOWN to be recorded in the journal
    superblock (bsc#1163863).

  - jbd2: move the clearing of b_modified flag to the
    journal_unmap_buffer() (bsc#1163880).

  - jbd2: switch to use jbd2_journal_abort() when failed to
    submit the commit record (bsc#1163852).

  - kABI fix for 'ipmi: Do not allow device module unload
    when in use' (bsc#1154768).

  - kABI fixup for alloc_dax_region
    (bsc#1158071,bsc#1160678).

  - kABI workaround for can/skb.h inclusion (bsc#1051510).

  - crypto/dh: Make sure the FIPS pubkey check is only
    executed in FIPS mode.

  - kABI: Protest new fields in BPF structs (bsc#1160618).

  - kABI: add _q suffix to exports that take struct dh
    (bsc#1155331).

  - kABI: protect struct sctp_ep_common (kabi).

  - kabi/severities: Whitelist rpaphp_get_drc_props
    (bsc#1157480 ltc#181028).

  - kconfig: fix broken dependency in randconfig-generated
    .config (bsc#1051510).

  - kernel-binary.spec.in: do not recommend firmware for
    kvmsmall and azure flavor (boo#1161360).

  - kernel/module.c: Only return -EEXIST for modules that
    have finished loading (bsc#1165488).

  - kernel/module.c: wakeup processes in module_wq on module
    unload (bsc#1165488).

  - kernel/trace: Fix do not unregister tracepoints when
    register sched_migrate_task fail (bsc#1160787).

  - kernfs: Fix range checks in kernfs_get_target_path
    (bsc#1051510).

  - kexec: bail out upon SIGKILL when allocating memory
    (git-fixes).

  - kvm: x86: Host feature SSBD does not imply guest feature
    SPEC_CTRL_SSBD (bsc#1160476).

  - l2tp: Allow duplicate session creation with UDP
    (networking-stable-20_02_05).

  - lcoking/rwsem: Add missing ACQUIRE to read_slowpath
    sleep loop (bsc#1050549).

  - leds: Allow to call led_classdev_unregister()
    unconditionally (bsc#1161674).

  - leds: class: ensure workqueue is initialized before
    setting brightness (bsc#1161674).

  - lib/scatterlist.c: adjust indentation in
    __sg_alloc_table (bsc#1051510).

  - lib/test_kasan.c: fix memory leak in
    kmalloc_oob_krealloc_more() (bsc#1051510).

  - lib: crc64: include <linux/crc64.h> for 'crc64_be'
    (bsc#1163762).

  - libnvdimm-fix-devm_nsio_enable-kabi.patch: Fixup
    compiler warning

  - libnvdimm/namespace: Differentiate between probe mapping
    and runtime mapping (bsc#1153535).

  - libnvdimm/pfn: Account for PAGE_SIZE > info-block-size
    in nd_pfn_init() (bsc#1127682 bsc#1153535 ltc#175033
    ltc#181834).

  - libnvdimm: Fix devm_nsio_enable() kabi (bsc#1153535).

  - livepatch/samples/selftest: Use klp_shadow_alloc() API
    correctly (bsc#1071995).

  - livepatch/selftest: Clean up shadow variable names and
    type (bsc#1071995).

  - locking/rwsem: Prevent decrement of reader count before
    increment (bsc#1050549).

  - mac80211: Do not send Layer 2 Update frame before
    authorization (bsc#1051510).

  - mac80211: Fix TKIP replay protection immediately after
    key setup (bsc#1051510).

  - mac80211: fix ieee80211_txq_setup_flows() failure path
    (bsc#1111666).

  - mac80211: fix station inactive_time shortly after boot
    (bsc#1051510).

  - mac80211: mesh: restrict airtime metric to peered
    established plinks (bsc#1051510).

  - macvlan: do not assume mac_header is set in
    macvlan_broadcast() (bsc#1051510).

  - macvlan: use skb_reset_mac_header() in
    macvlan_queue_xmit() (bsc#1051510).

  - mailbox: mailbox-test: fix NULL pointer if no mmio
    (bsc#1051510).

  - md/raid0: Fix buffer overflow at debug print
    (bsc#1164051).

  - media/v4l2-core: set pages dirty upon releasing DMA
    buffers (bsc#1051510).

  - media: af9005: uninitialized variable printked
    (bsc#1051510).

  - media: cec.h: CEC_OP_REC_FLAG_ values were swapped
    (bsc#1051510).

  - media: cec: CEC 2.0-only bcast messages were ignored
    (git-fixes).

  - media: cec: report Vendor ID after initialization
    (bsc#1051510).

  - media: digitv: do not continue if remote control state
    can't be read (bsc#1051510).

  - media: dvb-usb/dvb-usb-urb.c: initialize actlen to 0
    (bsc#1051510).

  - media: exynos4-is: fix wrong mdev and v4l2 dev order in
    error path (git-fixes).

  - media: gspca: zero usb_buf (bsc#1051510).

  - media: iguanair: fix endpoint sanity check
    (bsc#1051510).

  - media: ov6650: Fix control handler not freed on init
    error (git-fixes).

  - media: ov6650: Fix crop rectangle alignment not passed
    back (git-fixes).

  - media: ov6650: Fix incorrect use of JPEG colorspace
    (git-fixes).

  - media: pulse8-cec: fix lost cec_transmit_attempt_done()
    call.

  - media: pulse8-cec: return 0 when invalidating the
    logical address (bsc#1051510).

  - media: stkwebcam: Bugfix for wrong return values
    (bsc#1051510).

  - media: uvcvideo: Avoid cyclic entity chains due to
    malformed USB descriptors (bsc#1051510).

  - media: uvcvideo: Fix error path in control parsing
    failure (git-fixes).

  - media: v4l2-ctrl: fix flags for DO_WHITE_BALANCE
    (bsc#1051510).

  - media: v4l2-ioctl.c: zero reserved fields for S/TRY_FMT
    (bsc#1051510).

  - media: v4l2-rect.h: fix v4l2_rect_map_inside() top/left
    adjustments (bsc#1051510).

  - mei: bus: prefix device names on bus with the bus name
    (bsc#1051510).

  - mfd: da9062: Fix watchdog compatible string
    (bsc#1051510).

  - mfd: dln2: More sanity checking for endpoints
    (bsc#1051510).

  - mfd: rn5t618: Mark ADC control register volatile
    (bsc#1051510).

  - missing escaping of backslashes in macro expansions
    (bsc#1143959)

  - mlxsw: spectrum: Wipe xstats.backlog of down ports
    (bsc#1112374).

  - mlxsw: spectrum_qdisc: Ignore grafting of invisible FIFO
    (bsc#1112374).

  - mlxsw: spectrum_qdisc: Include MC TCs in Qdisc counters
    (bsc#1112374).

  - mlxsw: spectrum_router: Fix determining underlay for a
    GRE tunnel (bsc#1112374).

  - mm, memory_hotplug: do not clear numa_node association
    after hot_remove (bnc#1115026).

  - mm/page-writeback.c: fix range_cyclic writeback vs
    writepages deadlock (bsc#1159394).

  - mm: memory_hotplug: use put_device() if device_register
    fail (bsc#1159955 ltc#182993).

  - mmc: mediatek: fix CMD_TA to 2 for MT8173 HS200/HS400
    mode (bsc#1051510).

  - mmc: sdhci-of-esdhc: Revert 'mmc: sdhci-of-esdhc: add
    erratum A-009204 support' (bsc#1051510).

  - mmc: sdhci-of-esdhc: fix P2020 errata handling
    (bsc#1051510).

  - mmc: sdhci: Add a quirk for broken command queuing
    (git-fixes).

  - mmc: sdhci: Workaround broken command queuing on Intel
    GLK (git-fixes).

  - mmc: sdhci: fix minimum clock rate for v3 controller
    (bsc#1051510).

  - mmc: spi: Toggle SPI polarity, do not hardcode it
    (bsc#1051510).

  - mmc: tegra: fix SDR50 tuning override (bsc#1051510).

  - mod_devicetable: fix PHY module format
    (networking-stable-19_12_28).

  - moduleparam: fix parameter description mismatch
    (bsc#1051510).

  - mqprio: Fix out-of-bounds access in mqprio_dump
    (bsc#1109837).

  - mtd: fix mtd_oobavail() incoherent returned value
    (bsc#1051510).

  - mwifiex: debugfs: correct histogram spacing, formatting
    (bsc#1051510).

  - mwifiex: delete unused mwifiex_get_intf_num()
    (bsc#1111666).

  - mwifiex: drop most magic numbers from
    mwifiex_process_tdls_action_frame() (git-fixes).

  - mwifiex: fix potential NULL dereference and use after
    free (bsc#1051510).

  - mwifiex: update set_mac_address logic (bsc#1111666).

  - namei: only return -ECHILD from follow_dotdot_rcu()
    (bsc#1163851).

  - net, ip6_tunnel: fix namespaces move
    (networking-stable-20_01_27).

  - net, ip_tunnel: fix namespaces move
    (networking-stable-20_01_27).

  - net, sysctl: Fix compiler warning when only cBPF is
    present (bsc#1109837).

  - net-sysfs: Fix reference count leak
    (networking-stable-20_01_27).

  - net/ethtool: Introduce link_ksettings API for virtual
    network devices (bsc#1136157 ltc#177197).

  - net/ibmvnic: Fix typo in retry check (bsc#1155689
    ltc#182047).

  - net/mlx4_en: Fix wrong limitation for number of TX rings
    (bsc#1103989).

  - net/mlx4_en: fix mlx4 ethtool -N insertion
    (networking-stable-19_11_25).

  - net/mlx5: Accumulate levels for chains prio namespaces
    (bsc#1103990).

  - net/mlx5: Fix lowest FDB pool size (bsc#1103990).

  - net/mlx5: IPsec, Fix esp modify function attribute
    (bsc#1103990 ).

  - net/mlx5: IPsec, fix memory leak at
    mlx5_fpga_ipsec_delete_sa_ctx (bsc#1103990).

  - net/mlx5: Update the list of the PCI supported devices
    (bsc#1127611).

  - net/mlx5: Update the list of the PCI supported devices
    (bsc#1127611).

  - net/mlx5: prevent memory leak in
    mlx5_fpga_conn_create_cq (bsc#1046303).

  - net/mlx5e: Fix SFF 8472 eeprom length (git-fixes).

  - net/mlx5e: Fix set vf link state error flow
    (networking-stable-19_11_25).

  - net/mlx5e: Query global pause state before setting
    prio2buffer (bsc#1103990).

  - net/mlxfw: Fix out-of-memory error in mfa2 flash burning
    (bsc#1051858).

  - net/mlxfw: Verify FSM error code translation does not
    exceed array size (bsc#1051858).

  - net/sched: act_pedit: fix WARN() in the traffic path
    (networking-stable-19_11_25).

  - net/tls: fix async operation (bsc#1109837).

  - net/tls: free the record on encryption error
    (bsc#1109837).

  - net/tls: take into account that bpf_exec_tx_verdict()
    may free the record (bsc#1109837).

  - net/wan/fsl_ucc_hdlc: fix out of bounds write on array
    utdm_info (networking-stable-20_01_20).

  - net: Fix Tx hash bound checking (bsc#1109837).

  - net: add sendmsg_locked and sendpage_locked to af_inet6
    (bsc#1144162).

  - net: bridge: deny dev_set_mac_address() when
    unregistering (networking-stable-19_12_16).

  - net: cdc_ncm: Signedness bug in cdc_ncm_set_dgram_size()
    (git-fixes).

  - net: cxgb3_main: Add CAP_NET_ADMIN check to
    CHELSIO_GET_MEM (networking-stable-20_01_27).

  - net: dsa: mv88e6xxx: Preserve priority when setting CPU
    port (networking-stable-20_01_11).

  - net: dsa: tag_qca: fix doubled Tx statistics
    (networking-stable-20_01_20).

  - net: dst: Force 4-byte alignment of dst_metrics
    (networking-stable-19_12_28).

  - net: ena: fix napi handler misbehavior when the napi
    budget is zero (networking-stable-20_01_01).

  - net: ethernet: octeon_mgmt: Account for second possible
    VLAN header (networking-stable-19_11_10).

  - net: ethernet: ti: cpsw: fix extra rx interrupt
    (networking-stable-19_12_16).

  - net: fix data-race in neigh_event_send()
    (networking-stable-19_11_10).

  - net: hisilicon: Fix a BUG trigered by wrong bytes_compl
    (networking-stable-19_12_28).

  - net: hns3: fix ETS bandwidth validation bug (bsc#1104353
    ).

  - net: hns3: fix a copying IPv6 address error in
    hclge_fd_get_flow_tuples() (bsc#1104353).

  - net: hns: fix soft lockup when there is not enough
    memory (networking-stable-20_01_20).

  - net: hsr: fix possible NULL deref in hsr_handle_frame()
    (networking-stable-20_02_05).

  - net: ip6_gre: fix moving ip6gre between namespaces
    (networking-stable-20_01_27).

  - net: nfc: nci: fix a possible sleep-in-atomic-context
    bug in nci_uart_tty_receive()
    (networking-stable-19_12_28).

  - net: phy: Check against net_device being NULL
    (bsc#1051510).

  - net: phy: Fix not to call phy_resume() if PHY is not
    attached (bsc#1051510).

  - net: phy: Fix the register offsets in Broadcom iProc
    mdio mux driver (bsc#1051510).

  - net: phy: at803x: Change error to EINVAL for invalid MAC
    (bsc#1051510).

  - net: phy: broadcom: Use strlcpy() for
    ethtool::get_strings (bsc#1051510).

  - net: phy: dp83867: Set up RGMII TX delay (bsc#1051510).

  - net: phy: fixed_phy: Fix fixed_phy not checking GPIO
    (bsc#1051510).

  - net: phy: marvell: Use strlcpy() for
    ethtool::get_strings (bsc#1051510).

  - net: phy: marvell: clear wol event before setting it
    (bsc#1051510).

  - net: phy: meson-gxl: check phy_write return value
    (bsc#1051510).

  - net: phy: micrel: Use strlcpy() for ethtool::get_strings
    (bsc#1051510).

  - net: phy: mscc: read 'vsc8531, edge-slowdown' as an u32
    (bsc#1051510).

  - net: phy: mscc: read 'vsc8531,vddmac' as an u32
    (bsc#1051510).

  - net: phy: xgene: disable clk on error paths
    (bsc#1051510).

  - net: phy: xgmiitorgmii: Check phy_driver ready before
    accessing (bsc#1051510).

  - net: phy: xgmiitorgmii: Check read_status results
    (bsc#1051510).

  - net: phy: xgmiitorgmii: Support generic PHY status read
    (bsc#1051510).

  - net: psample: fix skb_over_panic
    (networking-stable-19_12_03).

  - net: qlogic: Fix error paths in ql_alloc_large_buffers()
    (networking-stable-19_12_28).

  - net: rtnetlink: prevent underflows in do_setvfinfo()
    (networking-stable-19_11_25).

  - net: rtnetlink: validate IFLA_MTU attribute in
    rtnl_create_link() (networking-stable-20_01_27).

  - net: sch_prio: When ungrafting, replace with FIFO
    (networking-stable-20_01_11).

  - net: sched: correct flower port blocking (git-fixes).

  - net: sched: ensure opts_len <= IP_TUNNEL_OPTS_MAX in
    act_tunnel_key (bsc#1109837).

  - net: sched: fix `tc -s class show` no bstats on class
    with nolock subqueues (networking-stable-19_12_03).

  - net: sched: fix dump qlen for sch_mq/sch_mqprio with
    NOLOCK subqueues (bsc#1109837).

  - net: stmmac: Delete txtimer in suspend()
    (networking-stable-20_02_05).

  - net: stmmac: dwmac-sunxi: Allow all RGMII modes
    (networking-stable-20_01_11).

  - net: usb: lan78xx: Add .ndo_features_check
    (networking-stable-20_01_27).

  - net: usb: lan78xx: Fix suspend/resume PHY register
    access error (networking-stable-19_12_28).

  - net: usb: lan78xx: fix possible skb leak
    (networking-stable-20_01_11).

  - net: usb: lan78xx: limit size of local TSO packets
    (bsc#1051510).

  - net: usb: qmi_wwan: add support for DW5821e with eSIM
    support (networking-stable-19_11_10).

  - net: usb: qmi_wwan: add support for Foxconn T77W968 LTE
    modules (networking-stable-19_11_18).

  - net_sched: ematch: reject invalid TCF_EM_SIMPLE
    (networking-stable-20_01_30).

  - net_sched: fix an OOB access in cls_tcindex
    (networking-stable-20_02_05).

  - net_sched: fix datalen for ematch
    (networking-stable-20_01_27).

  - netfilter: nf_queue: enqueue skbs with NULL dst
    (git-fixes).

  - new helper: lookup_positive_unlocked() (bsc#1159271).

  - nvme: fix the parameter order for nvme_get_log in
    nvme_get_fw_slot_info (bsc#1163774).

  - openvswitch: drop unneeded BUG_ON() in
    ovs_flow_cmd_build_info() (networking-stable-19_12_03).

  - openvswitch: remove another BUG_ON()
    (networking-stable-19_12_03).

  - openvswitch: support asymmetric conntrack
    (networking-stable-19_12_16).

  - orinoco_usb: fix interface sanity check (git-fixes).

  - percpu: Separate decrypted varaibles anytime encryption
    can be enabled (bsc#1114279).

  - perf/x86/intel: Fix inaccurate period in context switch
    for auto-reload (bsc#1164315).

  - phy: qualcomm: Adjust indentation in read_poll_timeout
    (bsc#1051510).

  - pinctrl: cherryview: Fix irq_valid_mask calculation
    (bsc#1111666).

  - pinctrl: qcom: ssbi-gpio: fix gpio-hog related boot
    issues (bsc#1051510).

  - pinctrl: sh-pfc: r8a7778: Fix duplicate SDSELF_B and
    SD1_CLK_B (bsc#1051510).

  - pinctrl: xway: fix gpio-hog related boot issues
    (bsc#1051510).

  - pkt_sched: fq: do not accept silly TCA_FQ_QUANTUM
    (networking-stable-20_01_11).

  - pktcdvd: remove warning on attempting to register
    non-passthrough dev (bsc#1051510).

  - platform/mellanox: fix potential deadlock in the tmfifo
    driver (bsc#1136333 jsc#SLE-4994).

  - platform/x86: asus-wmi: Fix keyboard brightness cannot
    be set to 0 (bsc#1051510).

  - platform/x86: hp-wmi: Fix ACPI errors caused by passing
    0 as input size (bsc#1051510).

  - platform/x86: hp-wmi: Fix ACPI errors caused by too
    small buffer (bsc#1051510).

  - platform/x86: hp-wmi: Make buffer for
    HPWMI_FEATURE2_QUERY 128 bytes (bsc#1051510).

  - platform/x86: pmc_atom: Add Siemens CONNECT X300 to
    critclk_systems DMI table (bsc#1051510).

  - power: supply: ltc2941-battery-gauge: fix use-after-free
    (bsc#1051510).

  - powerpc/archrandom: fix arch_get_random_seed_int()
    (bsc#1065729).

  - powerpc/irq: fix stack overflow verification
    (bsc#1065729).

  - powerpc/mm: Remove kvm radix prefetch workaround for
    Power9 DD2.2 (bsc#1061840).

  - powerpc/mm: drop #ifdef CONFIG_MMU in is_ioremap_addr()
    (bsc#1065729).

  - powerpc/papr_scm: Do not enable direct map for a region
    by default (bsc#1129551).

  - powerpc/papr_scm: Fix leaking 'bus_desc.provider_name'
    in some paths (bsc#1142685 ltc#179509).

  - powerpc/pkeys: remove unused pkey_allows_readwrite
    (bsc#1065729).

  - powerpc/powernv: Disable native PCIe port management
    (bsc#1065729).

  - powerpc/pseries/hotplug-memory: Change rc variable to
    bool (bsc#1065729).

  - powerpc/pseries/lparcfg: Fix display of Maximum Memory
    (bsc#1162028 ltc#181740).

  - powerpc/pseries/memory-hotplug: Only update DT once per
    memory DLPAR request (bsc#1165404 ltc#183498).

  - powerpc/pseries/mobility: notify network peers after
    migration (bsc#1152631 ltc#181798).

  - powerpc/pseries/vio: Fix iommu_table use-after-free
    refcount warning (bsc#1065729).

  - powerpc/pseries: Add cpu DLPAR support for drc-info
    property (bsc#1157480 ltc#181028).

  - powerpc/pseries: Advance pfn if section is not present
    in lmb_is_removable() (bsc#1065729).

  - powerpc/pseries: Allow not having ibm,
    hypertas-functions::hcall-multi-tce for DDW
    (bsc#1065729).

  - powerpc/pseries: Avoid NULL pointer dereference when
    drmem is unavailable (bsc#1160659).

  - powerpc/pseries: Drop pointless static qualifier in
    vpa_debugfs_init() (git-fixes).

  - powerpc/pseries: Enable support for ibm,drc-info
    property (bsc#1157480 ltc#181028).

  - powerpc/pseries: Fix bad drc_index_start value parsing
    of drc-info entry (bsc#1157480 ltc#181028).

  - powerpc/pseries: Fix drc-info mappings of logical cpus
    to drc-index (bsc#1157480 ltc#181028).

  - powerpc/pseries: Fix vector5 in ibm architecture vector
    table (bsc#1157480 ltc#181028).

  - powerpc/pseries: Revert support for ibm,drc-info devtree
    property (bsc#1157480 ltc#181028).

  - powerpc/pseries: group lmb operation and memblock's
    (bsc#1165404 ltc#183498).

  - powerpc/pseries: update device tree before ejecting
    hotplug uevents (bsc#1165404 ltc#183498).

  - powerpc/security: Fix debugfs data leak on 32-bit
    (bsc#1065729).

  - powerpc/smp: Use nid as fallback for package_id
    (bsc#1165813 ltc#184091).

  - powerpc/tm: Fix clearing MSR[TS] in current when
    reclaiming on signal delivery (bsc#1118338 ltc#173734).

  - powerpc/tools: Do not quote $objdump in scripts
    (bsc#1065729).

  - powerpc/xive: Discard ESB load value when interrupt is
    invalid (bsc#1085030).

  - powerpc/xive: Skip ioremap() of ESB pages for LSI
    interrupts (bsc#1085030).

  - powerpc/xmon: do not access ASDR in VMs (bsc#1065729).

  - powerpc: Allow 64bit VDSO __kernel_sync_dicache to work
    across ranges >4GB (bnc#1151927 5.3.17).

  - powerpc: Allow flush_icache_range to work across ranges
    >4GB (bnc#1151927 5.3.17).

  - powerpc: Enable support for ibm,drc-info devtree
    property (bsc#1157480 ltc#181028).

  - powerpc: Fix vDSO clock_getres() (bsc#1065729).

  - powerpc: avoid adjusting memory_limit for capture kernel
    memory reservation (bsc#1140025 ltc#176086).

  - powerpc: reserve memory for capture kernel after
    hugepages init (bsc#1140025 ltc#176086).

  - ppp: Adjust indentation into ppp_async_input
    (git-fixes).

  - prevent active file list thrashing due to refault
    detection (VM Performance, bsc#1156286).

  - pseries/drc-info: Search DRC properties for CPU indexes
    (bsc#1157480 ltc#181028).

  - pstore/ram: Write new dumps to start of recycled zones
    (bsc#1051510).

  - ptr_ring: add include of linux/mm.h (bsc#1109837).

  - pwm: Clear chip_data in pwm_put() (bsc#1051510).

  - pwm: Remove set but not set variable 'pwm' (git-fixes).

  - pwm: clps711x: Fix period calculation (bsc#1051510).

  - pwm: omap-dmtimer: Remove PWM chip in .remove before
    making it unfunctional (git-fixes).

  - pxa168fb: Fix the function used to release some memory
    in an error (bsc#1114279)

  - qede: Disable hardware gro when xdp prog is installed
    (bsc#1086314 bsc#1086313 bsc#1086301 ).

  - qede: Fix multicast mac configuration
    (networking-stable-19_12_28).

  - qede: fix NULL pointer deref in __qede_remove()
    (networking-stable-19_11_10).

  - qmi_wwan: Add support for Quectel RM500Q (bsc#1051510).

  - quota: Check that quota is not dirty before release
    (bsc#1163858).

  - quota: fix livelock in dquot_writeback_dquots
    (bsc#1163857).

  - r8152: add missing endpoint sanity check (bsc#1051510).

  - r8152: get default setting of WOL before initializing
    (bsc#1051510).

  - random: move FIPS continuous test to output functions
    (bsc#1155334).

  - regulator: Fix return value of _set_load() stub
    (bsc#1051510).

  - regulator: rk808: Lower log level on optional GPIOs
    being not available (bsc#1051510).

  - regulator: rn5t618: fix module aliases (bsc#1051510).

  - regulator: tps65910: fix a missing check of return value
    (bsc#1051510).

  - reiserfs: Fix memory leak of journal device string
    (bsc#1163867).

  - reiserfs: Fix spurious unlock in reiserfs_fill_super()
    error handling (bsc#1163869).

  - reset: fix reset_control_ops kerneldoc comment
    (bsc#1051510).

  - resource: fix locking in find_next_iomem_res()
    (bsc#1114279).

  - rpm/kabi.pl: support new (>=5.4) Module.symvers format
    (new symbol namespace field)

  - rpm/kernel-binary.spec.in: Conflict with too old
    powerpc-utils (jsc#ECO-920, jsc#SLE-11054,
    jsc#SLE-11322).

  - rpm/kernel-subpackage-spec: Exclude kernel-firmware
    recommends (bsc#1143959) For reducing the dependency on
    kernel-firmware in sub packages

  - rpm/kernel-subpackage-spec: Fix empty Recommends tag
    (bsc#1143959)

  - rpm/modules.fips: update module list (bsc#1157853)

  - rsi_91x_usb: fix interface sanity check (git-fixes).

  - rtc: cmos: Stop using shared IRQ (bsc#1051510).

  - rtc: dt-binding: abx80x: fix resistance scale
    (bsc#1051510).

  - rtc: hym8563: Return -EINVAL if the time is known to be
    invalid (bsc#1051510).

  - rtc: max8997: Fix the returned value in case of error in
    'max8997_rtc_read_alarm()' (bsc#1051510).

  - rtc: msm6242: Fix reading of 10-hour digit
    (bsc#1051510).

  - rtc: pcf8523: set xtal load capacitance from DT
    (bsc#1051510).

  - rtc: s35390a: Change buf's type to u8 in s35390a_init
    (bsc#1051510).

  - rtl818x: fix potential use after free (bsc#1051510).

  - rtl8xxxu: fix interface sanity check (git-fixes).

  - rtlwifi: Fix MAX MPDU of VHT capability (git-fixes).

  - rtlwifi: Remove redundant semicolon in wifi.h
    (git-fixes).

  - rtlwifi: rtl8192de: Fix missing callback that tests for
    hw release of buffer (bsc#1111666).

  - rxrpc: Fix insufficient receive notification generation
    (networking-stable-20_02_05).

  - s390/qeth: clean up page frag creation (git-fixes).

  - s390/qeth: consolidate skb allocation (git-fixes).

  - s390/qeth: ensure linear access to packet headers
    (git-fixes).

  - s390/qeth: guard against runt packets (git-fixes).

  - sched/fair: Add tmp_alone_branch assertion
    (bnc#1156462).

  - sched/fair: Fix O(nr_cgroups) in the load balancing path
    (bnc#1156462).

  - sched/fair: Fix insertion in rq->leaf_cfs_rq_list
    (bnc#1156462).

  - sched/fair: Optimize update_blocked_averages()
    (bnc#1156462).

  - sched/fair: WARN() and refuse to set buddy when
    !se->on_rq (bsc#1158132).

  - scsi-qla2xxx-Fix-qla2x00_request_irqs-for-MSI.patch

  -
    scsi-qla2xxx-fix-rports-not-being-mark-as-lost-in-sy.pat
    ch

  - scsi-qla2xxx-unregister-ports-after-GPN_FT-failure.patch

  - scsi: fnic: do not queue commands during fwreset
    (bsc#1146539).

  - scsi: ibmvfc: Add failed PRLI to cmd_status lookup array
    (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: Avoid loss of all paths during SVC node
    reboot (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: Byte swap status and error codes when
    logging (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: Clean up transport events (bsc#1161951
    ltc#183551).

  - scsi: ibmvfc: Do not call fc_block_scsi_eh() on host
    reset (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: Mark expected switch fall-throughs
    (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: Remove 'failed' from logged errors
    (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: Remove unneeded semicolons (bsc#1161951
    ltc#183551).

  - scsi: ibmvfc: constify dev_pm_ops structures
    (bsc#1161951 ltc#183551).

  - scsi: ibmvfc: ibmvscsi: ibmvscsi_tgt: constify
    vio_device_id (bsc#1161951 ltc#183551).

  - scsi: ibmvscsi: Do not use rc uninitialized in
    ibmvscsi_do_work (bsc#1161951 ltc#183551).

  - scsi: ibmvscsi: Improve strings handling (bsc#1161951
    ltc#183551).

  - scsi: ibmvscsi: Wire up host_reset() in the driver's
    scsi_host_template (bsc#1161951 ltc#183551).

  - scsi: ibmvscsi: change strncpy+truncation to strlcpy
    (bsc#1161951 ltc#183551).

  - scsi: ibmvscsi: constify dev_pm_ops structures
    (bsc#1161951 ltc#183551).

  - scsi: ibmvscsi: fix tripping of blk_mq_run_hw_queue
    WARN_ON (bsc#1161951 ltc#183551).

  - scsi: ibmvscsi: redo driver work thread to use enum
    action states (bsc#1161951 ltc#183551).

  - scsi: lpfc: fix build failure with DEBUGFS disabled
    (bsc#1154601).

  - scsi: qla2xxx: Add 16.0GT for PCI String (bsc#1157424).

  - scsi: qla2xxx: Add D-Port Diagnostic reason explanation
    logs (bsc#1158013).

  - scsi: qla2xxx: Add a shadow variable to hold disc_state
    history of fcport (bsc#1158013).

  - scsi: qla2xxx: Add beacon LED config sysfs interface
    (bsc#1157424).

  - scsi: qla2xxx: Add changes in preparation for vendor
    extended FDMI/RDP (bsc#1157424).

  - scsi: qla2xxx: Add deferred queue for processing ABTS
    and RDP (bsc#1157424).

  - scsi: qla2xxx: Add endianizer macro calls to fc host
    stats (bsc#1157424).

  - scsi: qla2xxx: Add fixes for mailbox command
    (bsc#1157424).

  - scsi: qla2xxx: Add ql2xrdpenable module parameter for
    RDP (bsc#1157424).

  - scsi: qla2xxx: Add sysfs node for D-Port Diagnostics AEN
    data (bsc#1157424).

  - scsi: qla2xxx: Add vendor extended FDMI commands
    (bsc#1157424).

  - scsi: qla2xxx: Add vendor extended RDP additions and
    amendments (bsc#1157424).

  - scsi: qla2xxx: Added support for MPI and PEP regions for
    ISP28XX (bsc#1157424, bsc#1157908, bsc#1157169,
    bsc#1151548).

  - scsi: qla2xxx: Avoid setting firmware options twice in
    24xx_update_fw_options (bsc#1157424).

  - scsi: qla2xxx: Check locking assumptions at runtime in
    qla2x00_abort_srb() (bsc#1157424).

  - scsi: qla2xxx: Cleanup ELS/PUREX iocb fields
    (bsc#1157424).

  - scsi: qla2xxx: Cleanup unused async_logout_done
    (bsc#1158013).

  - scsi: qla2xxx: Consolidate fabric scan (bsc#1158013).

  - scsi: qla2xxx: Convert MAKE_HANDLE() from a define into
    an inline function (bsc#1157424).

  - scsi: qla2xxx: Correct fcport flags handling
    (bsc#1158013).

  - scsi: qla2xxx: Correction to selection of loopback/echo
    test (bsc#1157424).

  - scsi: qla2xxx: Correctly retrieve and interpret active
    flash region (bsc#1157424, bsc#1157908, bsc#1157169,
    bsc#1151548).

  - scsi: qla2xxx: Display message for FCE enabled
    (bsc#1157424).

  - scsi: qla2xxx: Fix FCP-SCSI FC4 flag passing error
    (bsc#1157424).

  - scsi: qla2xxx: Fix NPIV instantiation after FW dump
    (bsc#1157424).

  - scsi: qla2xxx: Fix RDP respond data format
    (bsc#1157424).

  - scsi: qla2xxx: Fix RDP response size (bsc#1157424).

  - scsi: qla2xxx: Fix RIDA Format-2 (bsc#1158013).

  - scsi: qla2xxx: Fix a NULL pointer dereference in an
    error path (bsc#1157966 bsc#1158013 bsc#1157424).

  - scsi: qla2xxx: Fix control flags for login/logout IOCB
    (bsc#1157424).

  - scsi: qla2xxx: Fix fabric scan hang (bsc#1158013).

  - scsi: qla2xxx: Fix incorrect SFUB length used for Secure
    Flash Update MB Cmd (bsc#1157424, bsc#1157908,
    bsc#1157169, bsc#1151548).

  - scsi: qla2xxx: Fix mtcp dump collection failure
    (bsc#1158013).

  - scsi: qla2xxx: Fix qla2x00_echo_test() based on ISP type
    (bsc#1157424).

  - scsi: qla2xxx: Fix sparse warning reported by kbuild bot
    (bsc#1157424).

  - scsi: qla2xxx: Fix sparse warnings triggered by the PCI
    state checking code (bsc#1157424).

  - scsi: qla2xxx: Fix stuck login session using
    prli_pend_timer (bsc#1158013).

  - scsi: qla2xxx: Fix stuck session in GNL (bsc#1158013).

  - scsi: qla2xxx: Fix the endianness of the
    qla82xx_get_fw_size() return type (bsc#1158013).

  - scsi: qla2xxx: Fix unbound NVME response length
    (bsc#1157966 bsc#1158013 bsc#1157424).

  - scsi: qla2xxx: Fix update_fcport for current_topology
    (bsc#1158013).

  - scsi: qla2xxx: Force semaphore on flash validation
    failure (bsc#1157424).

  - scsi: qla2xxx: Handle NVME status iocb correctly
    (bsc#1157424).

  - scsi: qla2xxx: Handle cases for limiting RDP response
    payload length (bsc#1157424).

  - scsi: qla2xxx: Improve readability of the code that
    handles qla_flt_header (bsc#1158013).

  - scsi: qla2xxx: Improved secure flash support messages
    (bsc#1157424).

  - scsi: qla2xxx: Move free of fcport out of interrupt
    context (bsc#1157424).

  - scsi: qla2xxx: Print portname for logging in
    qla24xx_logio_entry() (bsc#1157424).

  - scsi: qla2xxx: Remove defer flag to indicate immeadiate
    port loss (bsc#1158013).

  - scsi: qla2xxx: Remove restriction of FC T10-PI and
    FC-NVMe (bsc#1157424).

  - scsi: qla2xxx: Return appropriate failure through BSG
    Interface (bsc#1157424).

  - scsi: qla2xxx: Save rscn_gen for new fcport
    (bsc#1157424).

  - scsi: qla2xxx: Serialize fc_port alloc in N2N
    (bsc#1157424).

  - scsi: qla2xxx: Set Nport ID for N2N (bsc#1157424).

  - scsi: qla2xxx: Show correct port speed capabilities for
    RDP command (bsc#1157424).

  - scsi: qla2xxx: Simplify the code for aborting SCSI
    commands (bsc#1157424).

  - scsi: qla2xxx: Suppress endianness complaints in
    qla2x00_configure_local_loop() (bsc#1157424).

  - scsi: qla2xxx: Update BPM enablement semantics
    (bsc#1157424).

  - scsi: qla2xxx: Update driver version to 10.01.00.22-k
    (bsc#1158013).

  - scsi: qla2xxx: Update driver version to 10.01.00.24-k
    (bsc#1157424).

  - scsi: qla2xxx: Update driver version to 10.01.00.25-k
    (bsc#1157424).

  - scsi: qla2xxx: Use FC generic update firmware options
    routine for ISP27xx (bsc#1157424).

  - scsi: qla2xxx: Use QLA_FW_STOPPED macro to propagate
    flag (bsc#1157424).

  - scsi: qla2xxx: Use a dedicated interrupt handler for
    'handshake-required' ISPs (bsc#1157424).

  - scsi: qla2xxx: Use common routine to free fcport struct
    (bsc#1158013).

  - scsi: qla2xxx: Use correct ISP28xx active FW region
    (bsc#1157424).

  - scsi: qla2xxx: Use endian macros to assign static fields
    in fwdump header (bsc#1157424).

  - scsi: qla2xxx: Use get_unaligned_*() instead of
    open-coding these functions (bsc#1158013).

  - scsi: qla2xxx: add more FW debug information
    (bsc#1157424).

  - scsi: qla2xxx: fix FW resource count values
    (bsc#1157424).

  - scsi: tcm_qla2xxx: Make qlt_alloc_qfull_cmd() set
    cmd->se_cmd.map_tag (bsc#1157424).

  - scsi: zfcp: trace channel log even for FCP command
    responses (git-fixes).

  - sctp: cache netns in sctp_ep_common
    (networking-stable-19_12_03).

  - sctp: free cmd->obj.chunk for the unprocessed
    SCTP_CMD_REPLY (networking-stable-20_01_11).

  - sctp: fully initialize v4 addr in some functions
    (networking-stable-19_12_28).

  - serial: 8250_bcm2835aux: Fix line mismatch on driver
    unbind (bsc#1051510).

  - serial: ifx6x60: add missed pm_runtime_disable
    (bsc#1051510).

  - serial: max310x: Fix tx_empty() callback (bsc#1051510).

  - serial: pl011: Fix DMA ->flush_buffer() (bsc#1051510).

  - serial: serial_core: Perform NULL checks for break_ctl
    ops (bsc#1051510).

  - serial: stm32: fix transmit_chars when tx is stopped
    (bsc#1051510).

  - sfc: Only cancel the PPS workqueue if it exists
    (networking-stable-19_11_25).

  - sfc: Remove 'PCIE error reporting unavailable'
    (bsc#1161472).

  - sh_eth: TSU_QTAG0/1 registers the same as TSU_QTAGM0/1
    (bsc#1051510).

  - sh_eth: check sh_eth_cpu_data::dual_port when dumping
    registers (bsc#1051510).

  - sh_eth: fix TSU init on SH7734/R8A7740 (bsc#1051510).

  - sh_eth: fix TXALCR1 offsets (bsc#1051510).

  - sh_eth: fix dumping ARSTR (bsc#1051510).

  - sh_eth: fix invalid context bug while calling
    auto-negotiation by ethtool (bsc#1051510).

  - sh_eth: fix invalid context bug while changing link
    options by ethtool (bsc#1051510).

  - smb3: Add defines for new information level,
    FileIdInformation (bsc#1144333).

  - smb3: Add missing reparse tags (bsc#1144333).

  - smb3: Fix regression in time handling (bsc#1144333).

  - smb3: add debug messages for closing unmatched open
    (bsc#1144333).

  - smb3: add dynamic tracepoints for flush and close
    (bsc#1144333).

  - smb3: add missing flag definitions (bsc#1144333).

  - smb3: add missing worker function for SMB3 change notify
    (bsc#1144333).

  - smb3: add mount option to allow RW caching of share
    accessed by only 1 client (bsc#1144333).

  - smb3: add mount option to allow forced caching of read
    only share (bsc#1144333).

  - smb3: add one more dynamic tracepoint missing from
    strict fsync path (bsc#1144333).

  - smb3: add some more descriptive messages about share
    when mounting cache=ro (bsc#1144333).

  - smb3: allow decryption keys to be dumped by admin for
    debugging (bsc#1144333).

  - smb3: allow disabling requesting leases (bsc#1144333).

  - smb3: allow parallelizing decryption of reads
    (bsc#1144333).

  - smb3: allow skipping signature verification for perf
    sensitive configurations (bsc#1144333).

  - smb3: cleanup some recent endian errors spotted by
    updated sparse (bsc#1144333).

  - smb3: display max smb3 requests in flight at any one
    time (bsc#1144333).

  - smb3: dump in_send and num_waiters stats counters by
    default (bsc#1144333).

  - smb3: enable offload of decryption of large reads via
    mount option (bsc#1144333).

  - smb3: fix default permissions on new files when mounting
    with modefromsid (bsc#1144333).

  - smb3: fix mode passed in on create for modetosid mount
    option (bsc#1144333).

  - smb3: fix performance regression with setting mtime
    (bsc#1144333).

  - smb3: fix potential null dereference in decrypt offload
    (bsc#1144333).

  - smb3: fix problem with null cifs super block with
    previous patch (bsc#1144333).

  - smb3: fix refcount underflow warning on unmount when no
    directory leases (bsc#1144333).

  - smb3: improve check for when we send the security
    descriptor context on create (bsc#1144333).

  - smb3: log warning if CSC policy conflicts with cache
    mount option (bsc#1144333).

  - smb3: missing ACL related flags (bsc#1144333).

  - smb3: only offload decryption of read responses if
    multiple requests (bsc#1144333).

  - smb3: pass mode bits into create calls (bsc#1144333).

  - smb3: query attributes on file close (bsc#1144333).

  - smb3: remove confusing dmesg when mounting with
    encryption ('seal') (bsc#1144333).

  - smb3: remove noisy debug message and minor cleanup
    (bsc#1144333).

  - smb3: remove unused flag passed into close functions
    (bsc#1144333).

  - soc/tegra: fuse: Correct straps' address for older
    Tegra124 device trees (bsc#1051510).

  - soc: renesas: rcar-sysc: Add goto to of_node_put()
    before return (bsc#1051510).

  - soc: ti: wkup_m3_ipc: Fix race condition with rproc_boot
    (bsc#1051510).

  - spi: omap2-mcspi: Fix DMA and FIFO event trigger size
    mismatch (bsc#1051510).

  - spi: omap2-mcspi: Set FIFO DMA trigger level to word
    length (bsc#1051510).

  - spi: tegra114: clear packed bit for unpacked mode
    (bsc#1051510).

  - spi: tegra114: configure dma burst size to fifo trig
    level (bsc#1051510).

  - spi: tegra114: fix for unpacked mode transfers
    (bsc#1051510).

  - spi: tegra114: flush fifos (bsc#1051510).

  - spi: tegra114: terminate dma and reset on transfer
    timeout (bsc#1051510).

  - sr_vendor: support Beurer GL50 evo CD-on-a-chip devices
    (boo#1164632).

  - staging: comedi: adv_pci1710: fix AI channels 16-31 for
    PCI-1713 (bsc#1051510).

  - staging: rtl8188eu: fix interface sanity check
    (bsc#1051510).

  - staging: rtl8192e: fix potential use after free
    (bsc#1051510).

  - staging: rtl8723bs: Add 024c:0525 to the list of SDIO
    device-ids (bsc#1051510).

  - staging: rtl8723bs: Drop ACPI device ids (bsc#1051510).

  - staging: vt6656: Fix false Tx excessive retries
    reporting (bsc#1051510).

  - staging: vt6656: correct packet types for CTS protect,
    mode (bsc#1051510).

  - staging: vt6656: use NULLFUCTION stack on mac80211
    (bsc#1051510).

  - staging: wlan-ng: ensure error return is actually
    returned (bsc#1051510).

  - stm class: Fix a double free of stm_source_device
    (bsc#1051510).

  - stop_machine, sched: Fix migrate_swap() vs.
    active_balance() deadlock (bsc#1088810, bsc#1161702).

  - stop_machine: Atomically queue and wake stopper threads
    (bsc#1088810, bsc#1161702).

  - stop_machine: Disable preemption after queueing stopper
    threads (bsc#1088810, bsc#1161702).

  - stop_machine: Disable preemption when waking two stopper
    threads (bsc#1088810, bsc#1161702).

  - tcp: clear tp->data_segs(in|out) in tcp_disconnect()
    (networking-stable-20_02_05).

  - tcp: clear tp->delivered in tcp_disconnect()
    (networking-stable-20_02_05).

  - tcp: clear tp->packets_out when purging write queue
    (bsc#1160560).

  - tcp: clear tp->segs_(in|out) in tcp_disconnect()
    (networking-stable-20_02_05).

  - tcp: clear tp->total_retrans in tcp_disconnect()
    (networking-stable-20_02_05).

  - tcp: do not send empty skb from tcp_write_xmit()
    (networking-stable-20_01_01).

  - tcp: exit if nothing to retransmit on RTO timeout
    (bsc#1160560, stable 4.14.159).

  - tcp: fix 'old stuff' D-SACK causing SACK to be treated
    as D-SACK (networking-stable-20_01_11).

  - tcp: fix marked lost packets not being retransmitted
    (networking-stable-20_01_20).

  - tcp: md5: fix potential overestimation of TCP option
    space (networking-stable-19_12_16).

  - tcp_bbr: improve arithmetic division in bbr_update_bw()
    (networking-stable-20_01_27).

  - thermal: Fix deadlock in thermal
    thermal_zone_device_check (bsc#1051510).

  - thunderbolt: Prevent crash if non-active NVMem file is
    read (git-fixes).

  - tipc: fix a missing check of genlmsg_put (bsc#1051510).

  - tipc: fix link name length check (bsc#1051510).

  - tipc: fix memory leak in tipc_nl_compat_publ_dump
    (bsc#1051510).

  - tipc: fix skb may be leaky in tipc_link_input
    (bsc#1051510).

  - tools lib traceevent: Do not free tep->cmdlines in
    add_new_comm() on failure (git-fixes).

  - tracing: Annotate ftrace_graph_hash pointer with __rcu
    (git-fixes).

  - tracing: Annotate ftrace_graph_notrace_hash pointer with
    __rcu (git-fixes).

  - tracing: Fix tracing_stat return values in error
    handling paths (git-fixes).

  - tracing: Fix very unlikely race of registering two stat
    tracers (git-fixes).

  - tracing: Have the histogram compare functions convert to
    u64 first (bsc#1160210).

  - tracing: xen: Ordered comparison of function pointers
    (git-fixes).

  - tty/serial: atmel: Add is_half_duplex helper
    (bsc#1051510).

  - tty: n_hdlc: fix build on SPARC (bsc#1051510).

  - tty: serial: msm_serial: Fix lockup for sysrq and oops
    (bsc#1051510).

  - tty: vt: keyboard: reject invalid keycodes
    (bsc#1051510).

  - ttyprintk: fix a potential deadlock in interrupt context
    issue (git-fixes).

  - tun: add mutex_unlock() call and napi.skb clearing in
    tun_get_user() (bsc#1109837).

  - uaccess: Add non-pagefault user-space write function
    (bsc#1083647).

  - ubifs: Fix FS_IOC_SETFLAGS unexpectedly clearing encrypt
    flag (bsc#1163855).

  - ubifs: Fix deadlock in concurrent bulk-read and
    writepage (bsc#1163856).

  - ubifs: Reject unsupported ioctl flags explicitly
    (bsc#1163844).

  - ubifs: do not trigger assertion on invalid no-key
    filename (bsc#1163850).

  - udp: fix integer overflow while computing available
    space in sk_rcvbuf (networking-stable-20_01_01).

  - usb-storage: Disable UAS on JMicron SATA enclosure
    (bsc#1051510).

  - usb: Allow USB device to be warm reset in suspended
    state (bsc#1051510).

  - usb: chipidea: host: Disable port power only if
    previously enabled (bsc#1051510).

  - usb: core: hub: Improved device recognition on remote
    wakeup (bsc#1051510).

  - usb: core: urb: fix URB structure initialization
    function (bsc#1051510).

  - usb: dwc3: debugfs: Properly print/set link state for HS
    (bsc#1051510).

  - usb: dwc3: do not log probe deferrals; but do log other
    error codes (bsc#1051510).

  - usb: dwc3: ep0: Clear started flag on completion
    (bsc#1051510).

  - usb: dwc3: turn off VBUS when leaving host mode
    (bsc#1051510).

  - usb: gadget: Zero ffs_io_data (bsc#1051510).

  - usb: gadget: f_ecm: Use atomic_t to track in-flight
    request (bsc#1051510).

  - usb: gadget: f_ncm: Use atomic_t to track in-flight
    request (bsc#1051510).

  - usb: gadget: legacy: set max_speed to super-speed
    (bsc#1051510).

  - usb: gadget: pch_udc: fix use after free (bsc#1051510).

  - usb: gadget: u_serial: add missing port entry locking
    (bsc#1051510).

  - usb: host: xhci-hub: fix extra endianness conversion
    (bsc#1051510).

  - usb: mon: Fix a deadlock in usbmon between mmap and read
    (bsc#1051510).

  - usb: mtu3: fix dbginfo in qmu_tx_zlp_error_handler
    (bsc#1051510).

  - usb: musb: dma: Correct parameter passed to IRQ handler
    (bsc#1051510).

  - usb: musb: fix idling for suspend after disconnect
    interrupt (bsc#1051510).

  - usb: roles: fix a potential use after free (git-fixes).

  - usb: typec: tcpci: mask event interrupts when remove
    driver (bsc#1051510).

  - usb: xhci: Fix build warning seen with CONFIG_PM=n
    (bsc#1051510).

  - usb: xhci: only set D3hot for pci device (bsc#1051510).

  - usbip: Fix error path of vhci_recv_ret_submit()
    (git-fixes).

  - usbip: Fix receive error in vhci-hcd when using
    scatter-gather (bsc#1051510).

  - usbip: Fix uninitialized symbol 'nents' in
    stub_recv_cmd_submit() (git-fixes).

  - vfs: fix preadv64v2 and pwritev64v2 compat syscalls with
    offset == -1 (bsc#1051510).

  - vhost/vsock: accept only packets with the right dst_cid
    (networking-stable-20_01_01).

  - video: backlight: Add devres versions of
    of_find_backlight (bsc#1090888) Taken for 6010831dde5.

  - video: backlight: Add of_find_backlight helper in
    backlight.c (bsc#1090888) Taken for 6010831dde5.

  - vlan: fix memory leak in vlan_dev_set_egress_priority
    (networking-stable-20_01_11).

  - vlan: vlan_changelink() should propagate errors
    (networking-stable-20_01_11).

  - vxlan: fix tos value before xmit
    (networking-stable-20_01_11).

  - watchdog: max77620_wdt: fix potential build errors
    (bsc#1051510).

  - watchdog: rn5t618_wdt: fix module aliases (bsc#1051510).

  - watchdog: sama5d4: fix WDD value to be always set to max
    (bsc#1051510).

  - watchdog: wdat_wdt: fix get_timeleft call for wdat_wdt
    (bsc#1162557).

  - wireless: fix enabling channel 12 for custom regulatory
    domain (bsc#1051510).

  - wireless: wext: avoid gcc -O3 warning (bsc#1051510).

  - workqueue: Fix pwq ref leak in rescuer_thread()
    (bsc#1160211).

  - x86/MCE/AMD: Allow Reserved types to be overwritten in
    smca_banks (bsc#1114279).

  - x86/MCE/AMD: Do not use rdmsr_safe_on_cpu() in
    smca_configure() (bsc#1114279).

  - x86/amd_nb: Add PCI device IDs for family 17h, model 70h
    (bsc#1163206).

  - x86/cpu: Update cached HLE state on write to
    TSX_CTRL_CPUID_CLEAR (bsc#1162619).

  - x86/intel_rdt: Split resource group removal in two
    (bsc#1112178).

  - x86/intel_rdt: Split resource group removal in two
    (bsc#1112178).

  - x86/kgbd: Use NMI_VECTOR not APIC_DM_NMI (bsc#1114279).

  - x86/mce/AMD: Allow any CPU to initialize the smca_banks
    array (bsc#1114279).

  - x86/mce: Fix possibly incorrect severity calculation on
    AMD (bsc#1114279).

  - x86/resctrl: Check monitoring static key in the MBM
    overflow handler (bsc#1114279).

  - x86/resctrl: Fix a deadlock due to inaccurate reference
    (bsc#1112178).

  - x86/resctrl: Fix a deadlock due to inaccurate reference
    (bsc#1112178).

  - x86/resctrl: Fix an imbalance in domain_remove_cpu()
    (bsc#1114279).

  - x86/resctrl: Fix potential memory leak (bsc#1114279).

  - x86/resctrl: Fix use-after-free due to inaccurate
    refcount of rdtgroup (bsc#1112178).

  - x86/resctrl: Fix use-after-free due to inaccurate
    refcount of rdtgroup (bsc#1112178).

  - x86/resctrl: Fix use-after-free when deleting resource
    groups (bsc#1114279).

  - x86/speculation: Fix incorrect MDS/TAA mitigation status
    (bsc#1114279).

  - x86/speculation: Fix redundant MDS mitigation message
    (bsc#1114279).

  - xen-blkfront: switch kcalloc to kvcalloc for large array
    allocation (bsc#1160917).

  - xen/balloon: Support xend-based toolstack take two
    (bsc#1065600).

  - xen/blkback: Avoid unmapping unmapped grant pages
    (bsc#1065600).

  - xen/blkfront: Adjust indentation in xlvbd_alloc_gendisk
    (bsc#1065600).

  - xen: Enable interrupts when calling _cond_resched()
    (bsc#1065600).

  - xfrm: Fix transport mode skb control buffer usage
    (bsc#1161552).

  - xfs: Fix tail rounding in xfs_alloc_file_space()
    (bsc#1161087, bsc#1153917).

  - xhci: Fix memory leak in xhci_add_in_port()
    (bsc#1051510).

  - xhci: Increase STS_HALT timeout in xhci_suspend()
    (bsc#1051510).

  - xhci: fix USB3 device initiated resume race with roothub
    autosuspend (bsc#1051510).

  - xhci: handle some XHCI_TRUST_TX_LENGTH quirks cases as
    default behaviour (bsc#1051510).

  - xhci: make sure interrupts are restored to correct state
    (bsc#1051510).

  - zd1211rw: fix storage endpoint lookup (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103992"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112504"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165881"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.40.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.40.1") ) flag++;

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
