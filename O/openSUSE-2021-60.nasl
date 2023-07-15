#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-60.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145320);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2020-0444",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-11668",
    "CVE-2020-25639",
    "CVE-2020-27068",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-27825",
    "CVE-2020-27830",
    "CVE-2020-27835",
    "CVE-2020-28374",
    "CVE-2020-29370",
    "CVE-2020-29373",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158"
  );

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-60)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-27835: A use after free in the Linux kernel
    infiniband hfi1 driver was found in the way user calls
    Ioctl after open dev file and fork. A local user could
    use this flaw to crash the system (bnc#1179878).

  - CVE-2020-25639: Fixed a NULL pointer dereference via
    nouveau ioctl (bnc#1176846).

  - CVE-2020-28374: In drivers/target/target_core_xcopy.c
    insufficient identifier checking in the LIO SCSI target
    code can be used by remote attackers to read or write
    files via directory traversal in an XCOPY request, aka
    CID-2896c93811e3. For example, an attack can occur over
    a network if the attacker has access to one iSCSI LUN.
    The attacker gains control over file access because I/O
    operations are proxied via an attacker-selected
    backstore (bnc#1178372).

  - CVE-2020-36158: mwifiex_cmd_802_11_ad_hoc_start in
    drivers/net/wireless/marvell/mwifiex/join.c might have
    allowed remote attackers to execute arbitrary code via a
    long SSID value, aka CID-5c455c5ab332 (bnc#1180559).

  - CVE-2020-27825: A use-after-free flaw was found in
    kernel/trace/ring_buffer.c. There was a race problem in
    trace_open and resize of cpu buffer running parallely on
    different cpus, may cause a denial of service problem
    (DOS). This flaw could even allow a local attacker with
    special user privilege to a kernel information leak
    threat (bnc#1179960).

  - CVE-2020-0466: In do_epoll_ctl and ep_loop_check_proc of
    eventpoll.c, there is a possible use after free due to a
    logic error. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1180031).

  - CVE-2020-27068: In the nl80211_policy policy of
    nl80211.c, there is a possible out of bounds read due to
    a missing bounds check. This could lead to local
    information disclosure with System execution privileges
    needed. User interaction is not required for
    exploitation (bnc#1180086).

  - CVE-2020-0444: In audit_free_lsm_field of auditfilter.c,
    there is a possible bad kfree due to a logic error in
    audit_data_to_entry. This could lead to local escalation
    of privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1180027).

  - CVE-2020-0465: In various methods of hid-multitouch.c,
    there is a possible out of bounds write due to a missing
    bounds check. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1180029).

  - CVE-2020-29661: A locking issue was discovered in the
    tty subsystem of the Linux kernel
    drivers/tty/tty_jobctrl.c allowed a use-after-free
    attack against TIOCSPGRP, aka CID-54ffccbf053b
    (bnc#1179745).

  - CVE-2020-29660: A locking inconsistency issue was
    discovered in the tty subsystem of the Linux kernel
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    have allowed a read-after-free attack against TIOCGSID,
    aka CID-c8bcd9c5be24 (bnc#1179745).

  - CVE-2020-27777: A flaw was found in the way RTAS handled
    memory accesses in userspace to kernel communication. On
    a locked down (usually due to Secure Boot) guest system
    running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to
    further increase their privileges to that of a running
    kernel (bnc#1179107).

  - CVE-2020-29373: An issue was discovered in fs/io_uring.c
    in the Linux kernel It unsafely handles the root
    directory during path lookups, and thus a process inside
    a mount namespace can escape to unintended filesystem
    locations, aka CID-ff002b30181d (bnc#1179434).

  - CVE-2020-11668: drivers/media/usb/gspca/xirlink_cit.c
    (aka the Xirlink camera USB driver) mishandled invalid
    descriptors, aka CID-a246b4d54770 (bnc#1168952).

  - CVE-2020-27830: Fixed a NULL-ptr deref bug in
    spk_ttyio_receive_buf2 (bnc#1179656).

  - CVE-2020-29370: An issue was discovered in
    kmem_cache_alloc_bulk in mm/slub.c. The slowpath lacks
    the required TID increment, aka CID-fd4d9c7d0c71
    (bnc#1179435).

  - CVE-2020-27786: A flaw was found in the Linux kernels
    implementation of MIDI, where an attacker with a local
    account and the permissions to issue an ioctl commands
    to midi devices, could trigger a use-after-free. A write
    to this specific memory while freed and before use could
    cause the flow of execution to change and possibly allow
    for memory corruption or privilege escalation
    (bnc#1179601).

The following non-security bugs were fixed :

  - ACPI: APEI: Kick the memory_failure() queue for
    synchronous errors (jsc#SLE-16610).

  - ACPI: PNP: compare the string length in the
    matching_id() (git-fixes).

  - ALSA/hda: apply jack fixup for the Acer Veriton
    N4640G/N6640G/N2510G (git-fixes).

  - ALSA: core: memalloc: add page alignment for iram
    (git-fixes).

  - ALSA: hda/ca0132 - Change Input Source enum strings
    (git-fixes).

  - ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg
    (git-fixes).

  - ALSA: hda/conexant: add a new hda codec CX11970
    (git-fixes).

  - ALSA: hda/generic: Add option to enforce preferred_dacs
    pairs (git-fixes).

  - ALSA: hda/hdmi: always print pin NIDs as hexadecimal
    (git-fixes).

  - ALSA: hda/hdmi: packet buffer index must be set before
    reading value (git-fixes).

  - ALSA: hda/proc - print DP-MST connections (git-fixes).

  - ALSA: hda/realtek - Add new codec supported for ALC897
    (git-fixes).

  - ALSA: hda/realtek - Add supported for more Lenovo ALC285
    Headset Button (git-fixes).

  - ALSA: hda/realtek - Enable headset mic of ASUS Q524UQK
    with ALC255 (git-fixes).

  - ALSA: hda/realtek - Enable headset mic of ASUS X430UN
    with ALC256 (git-fixes).

  - ALSA: hda/realtek - Fix speaker volume control on Lenovo
    C940 (git-fixes).

  - ALSA: hda/realtek - Fixed Dell AIO wrong sound tone
    (git-fixes).

  - ALSA: hda/realtek - Modify Dell platform name
    (git-fixes).

  - ALSA: hda/realtek - Supported Dell fixed type headset
    (git-fixes).

  - ALSA: hda/realtek: Add mute LED quirk for more HP
    laptops (git-fixes).

  - ALSA: hda/realtek: Add mute LED quirk to yet another HP
    x360 model (git-fixes).

  - ALSA: hda/realtek: Add quirk for MSI-GP73 (git-fixes).

  - ALSA: hda/realtek: Add two 'Intel Reference board' SSID
    in the ALC256 (git-fixes).

  - ALSA: hda/realtek: Apply jack fixup for Quanta NL3
    (git-fixes).

  - ALSA: hda/realtek: Enable headset of ASUS UX482EG &
    B9400CEA with ALC294 (git-fixes).

  - ALSA: hda/realtek: Enable mute and micmute LED on HP
    EliteBook 850 G7 (git-fixes).

  - ALSA: hda/realtek: Fix bass speaker DAC assignment on
    Asus Zephyrus G14 (git-fixes).

  - ALSA: hda/realtek: Remove dummy lineout on Acer
    TravelMate P648/P658 (git-fixes).

  - ALSA: hda/realtek: make bass spk volume adjustable on a
    yoga laptop (git-fixes).

  - ALSA: hda/via: Fix runtime PM for Clevo W35xSS
    (git-fixes).

  - ALSA: hda: Fix regressions on clear and reconfig sysfs
    (git-fixes).

  - ALSA: pcm: Clear the full allocated memory at hw_params
    (git-fixes).

  - ALSA: pcm: oss: Fix a few more UBSAN fixes (git-fixes).

  - ALSA: pcm: oss: Fix potential out-of-bounds shift
    (git-fixes).

  - ALSA: rawmidi: Access runtime->avail always in spinlock
    (git-fixes).

  - ALSA: seq: remove useless function (git-fixes).

  - ALSA: usb-audio: Add VID to support native DSD
    reproduction on FiiO devices (git-fixes).

  - ALSA: usb-audio: Add generic implicit fb parsing
    (bsc#1178203).

  - ALSA: usb-audio: Add hw constraint for implicit fb sync
    (bsc#1178203).

  - ALSA: usb-audio: Add implicit fb support for Steinberg
    UR22 (git-fixes).

  - ALSA: usb-audio: Add implicit_fb module option
    (bsc#1178203).

  - ALSA: usb-audio: Add quirk for BOSS AD-10 (git-fixes).

  - ALSA: usb-audio: Add quirk for Pioneer DJ DDJ-SR2
    (git-fixes).

  - ALSA: usb-audio: Add quirk for RC-505 (git-fixes).

  - ALSA: usb-audio: Add snd_usb_get_endpoint() helper
    (bsc#1178203).

  - ALSA: usb-audio: Add snd_usb_get_host_interface() helper
    (bsc#1178203).

  - ALSA: usb-audio: Add support for Pioneer DJ DDJ-RR
    controller (git-fixes).

  - ALSA: usb-audio: Always set up the parameters after
    resume (bsc#1178203).

  - ALSA: usb-audio: Avoid doubly initialization for
    implicit fb (bsc#1178203).

  - ALSA: usb-audio: Check implicit feedback EP generically
    for UAC2 (bsc#1178203).

  - ALSA: usb-audio: Check valid altsetting at parsing rates
    for UAC2/3 (bsc#1178203).

  - ALSA: usb-audio: Constify audioformat pointer references
    (bsc#1178203).

  - ALSA: usb-audio: Convert to the common vmalloc memalloc
    (bsc#1178203).

  - ALSA: usb-audio: Correct wrongly matching entries with
    audio class (bsc#1178203).

  - ALSA: usb-audio: Create endpoint objects at parsing
    phase (bsc#1178203).

  - ALSA: usb-audio: Disable sample read check if firmware
    does not give back (git-fixes).

  - ALSA: usb-audio: Do not call usb_set_interface() at
    trigger callback (bsc#1178203).

  - ALSA: usb-audio: Do not set altsetting before
    initializing sample rate (bsc#1178203).

  - ALSA: usb-audio: Drop debug.h (bsc#1178203).

  - ALSA: usb-audio: Drop keep_interface flag again
    (bsc#1178203).

  - ALSA: usb-audio: Drop unneeded snd_usb_substream fields
    (bsc#1178203).

  - ALSA: usb-audio: Factor out the implicit feedback quirk
    code (bsc#1178203).

  - ALSA: usb-audio: Fix EP matching for continuous rates
    (bsc#1178203).

  - ALSA: usb-audio: Fix MOTU M-Series quirks (bsc#1178203).

  - ALSA: usb-audio: Fix UBSAN warnings for MIDI jacks
    (git-fixes).

  - ALSA: usb-audio: Fix control 'access overflow' errors
    from chmap (git-fixes).

  - ALSA: usb-audio: Fix possible stall of implicit fb
    packet ring-buffer (bsc#1178203).

  - ALSA: usb-audio: Fix potential out-of-bounds shift
    (git-fixes).

  - ALSA: usb-audio: Fix quirks for other BOSS devices
    (bsc#1178203).

  - ALSA: usb-audio: Handle discrete rates properly in hw
    constraints (bsc#1178203).

  - ALSA: usb-audio: Improve some debug prints
    (bsc#1178203).

  - ALSA: usb-audio: Move device rename and profile quirks
    to an internal table (bsc#1178203).

  - ALSA: usb-audio: Move snd_usb_autoresume() call out of
    setup_hw_info() (bsc#1178203).

  - ALSA: usb-audio: Pass snd_usb_audio object to quirk
    functions (bsc#1178203).

  - ALSA: usb-audio: Properly match with audio interface
    class (bsc#1178203).

  - ALSA: usb-audio: Quirk for BOSS GT-001 (bsc#1178203).

  - ALSA: usb-audio: Refactor endpoint management
    (bsc#1178203).

  - ALSA: usb-audio: Refactoring endpoint URB deactivation
    (bsc#1178203).

  - ALSA: usb-audio: Replace slave/master terms
    (bsc#1178203).

  - ALSA: usb-audio: Set and clear sync EP link properly
    (bsc#1178203).

  - ALSA: usb-audio: Set callbacks via
    snd_usb_endpoint_set_callback() (bsc#1178203).

  - ALSA: usb-audio: Show sync endpoint information in proc
    outputs (bsc#1178203).

  - ALSA: usb-audio: Simplify hw_params rules (bsc#1178203).

  - ALSA: usb-audio: Simplify quirk entries with a macro
    (bsc#1178203).

  - ALSA: usb-audio: Simplify rate_min/max and rates set up
    (bsc#1178203).

  - ALSA: usb-audio: Simplify snd_usb_init_pitch() arguments
    (bsc#1178203).

  - ALSA: usb-audio: Simplify snd_usb_init_sample_rate()
    arguments (bsc#1178203).

  - ALSA: usb-audio: Stop both endpoints properly at error
    (bsc#1178203).

  - ALSA: usb-audio: Support PCM sync_stop (bsc#1178203).

  - ALSA: usb-audio: Track implicit fb sync endpoint in
    audioformat list (bsc#1178203).

  - ALSA: usb-audio: US16x08: fix value count for level
    meters (git-fixes).

  - ALSA: usb-audio: Unify the code for the next packet size
    calculation (bsc#1178203).

  - ALSA: usb-audio: Use ALC1220-VB-DT mapping for ASUS ROG
    Strix TRX40 mobo (bsc#1178203).

  - ALSA: usb-audio: Use atomic_t for endpoint use_count
    (bsc#1178203).

  - ALSA: usb-audio: Use managed buffer allocation
    (bsc#1178203).

  - ALSA: usb-audio: Use unsigned char for iface and
    altsettings fields (bsc#1178203).

  - ALSA: usb-audio: workaround for iface reset issue
    (bsc#1178203).

  - ASoC: Intel: bytcr_rt5640: Fix HP Pavilion x2 Detachable
    quirks (git-fixes).

  - ASoC: SOF: control: fix size checks for ext_bytes
    control .get() (git-fixes).

  - ASoC: amd: change clk_get() to devm_clk_get() and add
    missed checks (git-fixes).

  - ASoC: arizona: Fix a wrong free in wm8997_probe
    (git-fixes).

  - ASoC: cx2072x: Fix doubly definitions of Playback and
    Capture streams (git-fixes).

  - ASoC: jz4740-i2s: add missed checks for clk_get()
    (git-fixes).

  - ASoC: meson: fix COMPILE_TEST error (git-fixes).

  - ASoC: pcm: DRAIN support reactivation (git-fixes).

  - ASoC: sun4i-i2s: Fix lrck_period computation for I2S
    justified mode (git-fixes).

  - ASoC: tegra20-spdif: remove 'default m' (git-fixes).

  - ASoC: ti: davinci-mcasp: remove always zero of
    davinci_mcasp_get_dt_params (git-fixes).

  - ASoC: wm8998: Fix PM disable depth imbalance on error
    (git-fixes).

  - ASoC: wm_adsp: fix error return code in wm_adsp_load()
    (git-fixes).

  - ASoC: wm_adsp: remove 'ctl' from list on error in
    wm_adsp_create_control() (git-fixes).

  - Bluetooth: Fix NULL pointer dereference in
    hci_event_packet() (git-fixes).

  - Bluetooth: Fix slab-out-of-bounds read in
    hci_le_direct_adv_report_evt() (git-fixes).

  - Bluetooth: btmtksdio: Add the missed release_firmware()
    in mtk_setup_firmware() (git-fixes).

  - Bluetooth: btusb: Add the missed release_firmware() in
    btusb_mtk_setup_firmware() (git-fixes).

  - Bluetooth: hci_h5: close serdev device and free hu in
    h5_close (git-fixes).

  - Bluetooth: hci_h5: fix memory leak in h5_close
    (git-fixes).

  - Drop a backported uvcvideo patch that caused a
    regression (bsc#1180117) Also blacklisting the commit

  - EDAC/amd64: Do not load on family 0x15, model 0x13
    (bsc#1179763).

  - EDAC/amd64: Fix PCI component registration
    (bsc#1152489).

  - EDAC/i10nm: Use readl() to access MMIO registers
    (bsc#1152489).

  - EDAC/mce_amd: Use struct cpuinfo_x86.cpu_die_id for AMD
    NodeId (bsc#1152489).

  - HID: Add Logitech Dinovo Edge battery quirk (git-fixes).

  - HID: add HID_QUIRK_INCREMENT_USAGE_ON_DUPLICATE for
    Gamevice devices (git-fixes).

  - HID: add support for Sega Saturn (git-fixes).

  - HID: cypress: Support Varmilo Keyboards' media hotkeys
    (git-fixes).

  - HID: hid-sensor-hub: Fix issue with devices with no
    report ID (git-fixes).

  - HID: i2c-hid: add Vero K147 to descriptor override
    (git-fixes).

  - HID: ite: Replace ABS_MISC 120/121 events with touchpad
    on/off keypresses (git-fixes).

  - HID: logitech-hidpp: Add HIDPP_CONSUMER_VENDOR_KEYS
    quirk for the Dinovo Edge (git-fixes).

  - HID: uclogic: Add ID for Trust Flex Design Tablet
    (git-fixes).

  - HMAT: Register memory-side cache after parsing
    (bsc#1178660).

  - HMAT: Skip publishing target info for nodes with no
    online memory (bsc#1178660).

  - HSI: omap_ssi: Do not jump to free ID in
    ssi_add_controller() (git-fixes).

  - IB/hfi1: Remove kobj from hfi1_devdata (bsc#1179878).

  - IB/hfi1: Remove module parameter for KDETH qpns
    (bsc#1179878).

  - IB/isert: Fix unaligned immediate-data handling
    (bsc#1152489)

  - IB/mlx4: Add and improve logging (bsc#1152489)

  - IB/mlx4: Add support for MRA (bsc#1152489)

  - IB/mlx4: Adjust delayed work when a dup is observed
    (bsc#1152489)

  - IB/mlx4: Fix starvation in paravirt mux/demux
    (bsc#1152489)

  - IB/mthca: fix return value of error branch in
    mthca_init_cq() (bsc#1152489)

  - IB/rdmavt: Fix sizeof mismatch (bsc#1152489)

  - IB/srpt: Fix memory leak in srpt_add_one (bsc#1152489)

  - IB/uverbs: Set IOVA on IB MR in uverbs layer
    (bsc#1152489)

  - Input: ads7846 - fix integer overflow on Rt calculation
    (git-fixes).

  - Input: ads7846 - fix race that causes missing releases
    (git-fixes).

  - Input: ads7846 - fix unaligned access on 7845
    (git-fixes).

  - Input: cm109 - do not stomp on control URB (git-fixes).

  - Input: cros_ec_keyb - send 'scancodes' in addition to
    key events (git-fixes).

  - Input: cyapa_gen6 - fix out-of-bounds stack access
    (git-fixes).

  - Input: goodix - add upside-down quirk for Teclast X98
    Pro tablet (git-fixes).

  - Input: i8042 - add Acer laptops to the i8042 reset list
    (git-fixes).

  - Input: i8042 - add ByteSpeed touchpad to noloop table
    (git-fixes).

  - Input: i8042 - allow insmod to succeed on devices
    without an i8042 controller (git-fixes).

  - Input: i8042 - fix error return code in
    i8042_setup_aux() (git-fixes).

  - Input: omap4-keypad - fix runtime PM error handling
    (git-fixes).

  - Input: xpad - support Ardwiino Controllers (git-fixes).

  - KVM: PPC: Book3S HV: XIVE: Fix possible oops when
    accessing ESB page (bsc#1156395).

  - Move 'btrfs: qgroup: do not try to wait flushing if
    we're already holding a transaction (bsc#1179575).' to
    sorted section

  - Move upstreamed USB-audio patches into sorted section

  - PCI: Fix overflow in command-line resource alignment
    requests (git-fixes).

  - PCI: Fix pci_slot_release() NULL pointer dereference
    (git-fixes).

  - PCI: brcmstb: Initialize 'tmp' before use (git-fixes).

  - PCI: iproc: Fix out-of-bound array accesses (git-fixes).

  - RDMA/addr: Fix race with
    netevent_callback()/rdma_addr_cancel() (bsc#1152489)

  - RDMA/bnxt_re: Do not add user qps to flushlist
    (bsc#1152489)

  - RDMA/bnxt_re: Fix sizeof mismatch for allocation of
    pbl_tbl. (bsc#1152489)

  - RDMA/core: Fix bogus WARN_ON during
    ib_unregister_device_queued() (bsc#1152489)

  - RDMA/core: Fix reported speed and width (bsc#1152489)

  - RDMA/core: Fix return error value in _ib_modify_qp() to
    negative (bsc#1152489)

  - RDMA/core: Free DIM memory in error unwind (bsc#1152489)

  - RDMA/core: Stop DIM before destroying CQ (bsc#1152489)

  - RDMA/counter: Allow manually bind QPs with different
    pids to same counter (bsc#1152489)

  - RDMA/counter: Only bind user QPs in auto mode
    (bsc#1152489)

  - RDMA/hns: Add check for the validity of sl configuration
    (bsc#1152489)

  - RDMA/hns: Bugfix for memory window mtpt configuration
    (bsc#1152489)

  - RDMA/hns: Correct typo of hns_roce_create_cq()
    (bsc#1152489)

  - RDMA/hns: Fix missing sq_sig_type when querying QP
    (bsc#1152489)

  - RDMA/hns: Set the unsupported wr opcode (bsc#1152489)

  - RDMA/ipoib: Set rtnl_link_ops for ipoib interfaces
    (bsc#1152489)

  - RDMA/mlx5: Disable IB_DEVICE_MEM_MGT_EXTENSIONS if
    IB_WR_REG_MR can't work (bsc#1152489)

  - RDMA/netlink: Remove CAP_NET_RAW check when dump a raw
    QP (bsc#1152489)

  - RDMA/pvrdma: Fix missing kfree() in
    pvrdma_register_device() (bsc#1152489)

  - RDMA/qedr: Endianness warnings cleanup (bsc#1152489)

  - RDMA/qedr: Fix doorbell setting (bsc#1152489)

  - RDMA/qedr: Fix iWARP active mtu display (bsc#1152489)

  - RDMA/qedr: Fix inline size returned for iWARP
    (bsc#1152489)

  - RDMA/qedr: Fix memory leak in iWARP CM (bsc#1152489)

  - RDMA/qedr: Fix qp structure memory leak (bsc#1152489)

  - RDMA/qedr: Fix resource leak in qedr_create_qp
    (bsc#1152489)

  - RDMA/qedr: Fix use of uninitialized field (bsc#1152489)

  - RDMA/qedr: SRQ's bug fixes (bsc#1152489)

  - RDMA/rxe: Drop pointless checks in rxe_init_ports
    (bsc#1152489)

  - RDMA/rxe: Fix memleak in rxe_mem_init_user (bsc#1152489)

  - RDMA/rxe: Fix skb lifetime in rxe_rcv_mcast_pkt()
    (bsc#1152489)

  - RDMA/rxe: Fix the parent sysfs read when the interface
    has 15 chars (bsc#1152489)

  - RDMA/rxe: Handle skb_clone() failure in rxe_recv.c
    (bsc#1152489)

  - RDMA/rxe: Prevent access to wr->next ptr afrer wr is
    posted to send queue (bsc#1152489)

  - RDMA/rxe: Remove unused rxe_mem_map_pages (bsc#1152489)

  - RDMA/rxe: Return void from rxe_init_port_param()
    (bsc#1152489)

  - RDMA/rxe: Return void from rxe_mem_init_dma()
    (bsc#1152489)

  - RDMA/rxe: Skip dgid check in loopback mode (bsc#1152489)

  - RDMA/srpt: Fix typo in srpt_unregister_mad_agent
    docstring (bsc#1152489)

  - RDMA/umem: Fix ib_umem_find_best_pgsz() for mappings
    that cross a page boundary (bsc#1152489)

  - RDMA/umem: Prevent small pages from being returned by
    ib_umem_find_best_pgsz() (bsc#1152489)

  - Re-import the upstream uvcvideo fix; one more fix will
    be added later (bsc#1180117)

  - Revert 'ACPI / resources: Use AE_CTRL_TERMINATE to
    terminate resources walks' (git-fixes).

  - Revert 'ceph: allow rename operation under different
    quota realms' (bsc#1180541).

  - Revert 'geneve: pull IP header before ECN decapsulation'
    (git-fixes).

  - Revert 'i2c: i2c-qcom-geni: Fix DMA transfer race'
    (git-fixes).

  - Revert 'platform/x86: wmi: Destroy on cleanup rather
    than unregister' (git-fixes).

  - Revert 'powerpc/pseries/hotplug-cpu: Remove double free
    in error path' (bsc#1065729).

  - USB: UAS: introduce a quirk to set no_write_same
    (git-fixes).

  - USB: add RESET_RESUME quirk for Snapscan 1212
    (git-fixes).

  - USB: dummy-hcd: Fix uninitialized array use in init()
    (git-fixes).

  - USB: gadget: f_acm: add support for SuperSpeed Plus
    (git-fixes).

  - USB: gadget: f_midi: setup SuperSpeed Plus descriptors
    (git-fixes).

  - USB: gadget: f_rndis: fix bitrate for SuperSpeed and
    above (git-fixes).

  - USB: gadget: legacy: fix return error code in
    acm_ms_bind() (git-fixes).

  - USB: quirks: Add USB_QUIRK_DISCONNECT_SUSPEND quirk for
    Lenovo A630Z TIO built-in usb-audio card (git-fixes).

  - USB: serial: ch341: add new Product ID for CH341A
    (git-fixes).

  - USB: serial: ch341: sort device-id entries (git-fixes).

  - USB: serial: digi_acceleport: fix write-wakeup deadlocks
    (git-fixes).

  - USB: serial: iuu_phoenix: fix DMA from stack
    (git-fixes).

  - USB: serial: keyspan_pda: fix dropped unthrottle
    interrupts (git-fixes).

  - USB: serial: keyspan_pda: fix stalled writes
    (git-fixes).

  - USB: serial: keyspan_pda: fix tx-unthrottle
    use-after-free (git-fixes).

  - USB: serial: keyspan_pda: fix write deadlock
    (git-fixes).

  - USB: serial: keyspan_pda: fix write unthrottling
    (git-fixes).

  - USB: serial: keyspan_pda: fix write-wakeup
    use-after-free (git-fixes).

  - USB: serial: kl5kusb105: fix memleak on open
    (git-fixes).

  - USB: serial: kl5kusb105: fix memleak on open
    (git-fixes).

  - USB: serial: mos7720: fix parallel-port state restore
    (git-fixes).

  - USB: serial: option: add Fibocom NL668 variants
    (git-fixes).

  - USB: serial: option: add interface-number sanity check
    to flag handling (git-fixes).

  - USB: serial: option: add support for Thales Cinterion
    EXS82 (git-fixes).

  - USB: serial: option: fix Quectel BG96 matching
    (git-fixes).

  - USB: xhci: fix U1/U2 handling for hardware with
    XHCI_INTEL_HOST quirk set (git-fixes).

  - USB: yurex: fix control-URB timeout handling
    (git-fixes).

  - arm64: acpi: Make apei_claim_sea() synchronise with
    APEI's irq work (jsc#SLE-16610).

  - arm64: mm: Fix ARCH_LOW_ADDRESS_LIMIT when
    !CONFIG_ZONE_DMA (git-fixes).

  - ath10k: Fix an error handling path (git-fixes).

  - ath10k: Release some resources in an error handling path
    (git-fixes).

  - ath6kl: fix enum-conversion warning (git-fixes).

  - batman-adv: Consider fragmentation for needed_headroom
    (git-fixes).

  - batman-adv: Do not always reallocate the fragmentation
    skb head (git-fixes).

  - batman-adv: Reserve needed_*room for fragments
    (git-fixes).

  - bitmap: remove unused function declaration (git-fixes).

  - blk-mq-blk-mq-provide-forced-completion-method.patch:
    (bsc#1175995,jsc#SLE-15608,bsc#1178756).

  - blk-mq: Remove 'running from the wrong CPU' warning
    (bsc#1174486).

  - block: return status code in blk_mq_end_request()
    (bsc#1171000, bsc#1165933).

  - bpf: Fix bpf_put_raw_tracepoint()'s use of
    __module_address() (git-fixes).

  - btrfs: add missing check for nocow and compression inode
    flags (bsc#1178780).

  - btrfs: allow btrfs_truncate_block() to fallback to nocow
    for data space reservation (bsc#1161099).

  - btrfs: delete duplicated words + other fixes in comments
    (bsc#1180566).

  - btrfs: do not commit logs and transactions during link
    and rename operations (bsc#1180566).

  - btrfs: do not take the log_mutex of the subvolume when
    pinning the log (bsc#1180566).

  - btrfs: fix missing delalloc new bit for new delalloc
    ranges (bsc#1180773).

  - btrfs: fix readahead hang and use-after-free after
    removing a device (bsc#1179963).

  - btrfs: fix use-after-free on readahead extent after
    failure to create it (bsc#1179963).

  - btrfs: make btrfs_dirty_pages take btrfs_inode
    (bsc#1180773).

  - btrfs: make btrfs_set_extent_delalloc take btrfs_inode
    (bsc#1180773).

  - btrfs: qgroup: do not commit transaction when we already
    hold the handle (bsc#1178634).

  - btrfs: qgroup: do not try to wait flushing if we're
    already holding a transaction (bsc#1179575).

  - bus/fsl_mc: Do not rely on caller to provide non NULL
    mc_io (git-fixes).

  - bus: fsl-mc: fix error return code in
    fsl_mc_object_allocate() (git-fixes).

  - can: c_can: c_can_power_up(): fix error handling
    (git-fixes).

  - can: sja1000: sja1000_err(): do not count arbitration
    lose as an error (git-fixes).

  - can: softing: softing_netdev_open(): fix error handling
    (git-fixes).

  - can: sun4i_can: sun4i_can_err(): do not count
    arbitration lose as an error (git-fixes).

  - cfg80211: initialize rekey_data (git-fixes).

  - cifs: Fix an error pointer dereference in cifs_mount()
    (bsc#1178270).

  - cifs: add NULL check for ses->tcon_ipc (bsc#1178270).

  - cifs: allow syscalls to be restarted in
    __smb_send_rqst() (bsc#1176956).

  - cifs: do not share tcons with DFS (bsc#1178270).

  - cifs: document and cleanup dfs mount (bsc#1178270).

  - cifs: ensure correct super block for DFS reconnect
    (bsc#1178270).

  - cifs: fix DFS mount with cifsacl/modefromsid
    (bsc#1178270).

  - cifs: fix check of tcon dfs in smb1 (bsc#1178270).

  - cifs: fix double free error on share and prefix
    (bsc#1178270).

  - cifs: fix leaked reference on requeued write
    (bsc#1178270).

  - cifs: fix potential use-after-free in
    cifs_echo_request() (bsc#1139944).

  - cifs: fix uninitialised lease_key in open_shroot()
    (bsc#1178270).

  - cifs: get rid of unused parameter in
    reconn_setup_dfs_targets() (bsc#1178270).

  - cifs: handle RESP_GET_DFS_REFERRAL.PathConsumed in
    reconnect (bsc#1178270).

  - cifs: handle empty list of targets in cifs_reconnect()
    (bsc#1178270).

  - cifs: handle hostnames that resolve to same ip in
    failover (bsc#1178270).

  - cifs: merge __(cifs,smb2)_reconnect[_tcon]() into
    cifs_tree_connect() (bsc#1178270).

  - cifs: only update prefix path of DFS links in
    cifs_tree_connect() (bsc#1178270).

  - cifs: reduce number of referral requests in DFS link
    lookups (bsc#1178270).

  - cifs: rename reconn_inval_dfs_target() (bsc#1178270).

  - cifs: set up next DFS target before generic_ip_connect()
    (bsc#1178270).

  - clk: at91: sam9x60: remove atmel,osc-bypass support
    (git-fixes).

  - clk: ingenic: Fix divider calculation with div tables
    (git-fixes).

  - clk: mediatek: Make mtk_clk_register_mux() a static
    function (git-fixes).

  - clk: mvebu: a3700: fix the XTAL MODE pin to MPP1_9
    (git-fixes).

  - clk: renesas: r9a06g032: Drop __packed for portability
    (git-fixes).

  - clk: s2mps11: Fix a resource leak in error handling
    paths in the probe function (git-fixes).

  - clk: sunxi-ng: Make sure divider tables have sentinel
    (git-fixes).

  - clk: tegra: Do not return 0 on failure (git-fixes).

  - clk: tegra: Fix duplicated SE clock entry (git-fixes).

  - clk: ti: Fix memleak in ti_fapll_synth_setup
    (git-fixes).

  - clocksource/drivers/arm_arch_timer: Correct fault
    programming of CNTKCTL_EL1.EVNTI (git-fixes).

  - clocksource/drivers/arm_arch_timer: Use stable count
    reader in erratum sne (git-fixes).

  - clocksource/drivers/cadence_ttc: Fix memory leak in
    ttc_setup_clockevent() (git-fixes).

  - clocksource/drivers/orion: Add missing
    clk_disable_unprepare() on error path (git-fixes).

  - compiler_attributes.h: Add 'fallthrough' pseudo keyword
    for switch/case use (bsc#1178203).

  - coredump: fix core_pattern parse error (git-fixes).

  - cpufreq: ap806: Add missing MODULE_DEVICE_TABLE
    (git-fixes).

  - cpufreq: highbank: Add missing MODULE_DEVICE_TABLE
    (git-fixes).

  - cpufreq: loongson1: Add missing MODULE_ALIAS
    (git-fixes).

  - cpufreq: mediatek: Add missing MODULE_DEVICE_TABLE
    (git-fixes).

  - cpufreq: scpi: Add missing MODULE_ALIAS (git-fixes).

  - cpufreq: st: Add missing MODULE_DEVICE_TABLE
    (git-fixes).

  - cpufreq: vexpress-spc: Add missing MODULE_ALIAS
    (git-fixes).

  - crypto: af_alg - avoid undefined behavior accessing
    salg_name (git-fixes).

  - crypto: atmel-i2c - select CONFIG_BITREVERSE
    (git-fixes).

  - crypto: crypto4xx - Replace bitwise OR with logical OR
    in crypto4xx_build_pd (git-fixes).

  - crypto: ecdh - avoid buffer overflow in
    ecdh_set_secret() (git-fixes).

  - crypto: ecdh - avoid unaligned accesses in
    ecdh_set_secret() (git-fixes).

  - crypto: inside-secure - Fix sizeof() mismatch
    (git-fixes).

  - crypto: omap-aes - Fix PM disable depth imbalance in
    omap_aes_probe (git-fixes).

  - crypto: qat - fix status check in
    qat_hal_put_rel_rd_xfer() (git-fixes).

  - crypto: sun4i-ss - add the A33 variant of SS
    (git-fixes).

  - crypto: talitos - Endianess in current_desc_hdr()
    (git-fixes).

  - crypto: talitos - Fix return type of current_desc_hdr()
    (git-fixes).

  - cw1200: fix missing destroy_workqueue() on error in
    cw1200_init_common (git-fixes).

  - dmaengine: at_hdmac: Substitute kzalloc with kmalloc
    (git-fixes).

  - dmaengine: at_hdmac: add missing kfree() call in
    at_dma_xlate() (git-fixes).

  - dmaengine: at_hdmac: add missing put_device() call in
    at_dma_xlate() (git-fixes).

  - dmaengine: dw-edma: Fix use after free in
    dw_edma_alloc_chunk() (git-fixes).

  - dmaengine: mediatek: mtk-hsdma: Fix a resource leak in
    the error handling path of the probe function
    (git-fixes).

  - dmaengine: mv_xor_v2: Fix error return code in
    mv_xor_v2_probe() (git-fixes).

  - dmaengine: xilinx_dma: check dma_async_device_register
    return value (git-fixes).

  - dmaengine: xilinx_dma: fix incompatible param warning in
    _child_probe() (git-fixes).

  - dmaengine: xilinx_dma: fix mixed_enum_type coverity
    warning (git-fixes).

  - drivers: soc: ti: knav_qmss_queue: Fix error return code
    in knav_queue_probe (git-fixes).

  - drm/amd/display: Fix wrong return value in
    dm_update_plane_state() (bsc#1152489)

  - drm/amdgpu: pass NULL pointer instead of 0 (bsc#1152489)
    Backporting changes: &#9;* context fixes

  - drm/crc-debugfs: Fix memleak in crc_control_write
    (bsc#1152472)

  - drm/gma500: fix error check (bsc#1152472) Backporting
    changes: &#9;* context fixes

  - drm/i915/gem: Avoid implicit vmap for highmem on x86-32
    (bsc#1152489) Backporting changes: &#9;* context fixes

  - drm/i915: Fix sha_text population code (bsc#1152489)
    Backporting changes: &#9;* context fixes &#9;* adapted
    I/O functions to old driver

  - drm/imx: tve remove extraneous type qualifier
    (bsc#1152489)

  - drm/mediatek: Add exception handing in mtk_drm_probe()
    if component (bsc#1152472)

  - drm/mediatek: Add missing put_device() call in
    (bsc#1152472)

  - drm/mediatek: Add missing put_device() call in
    mtk_drm_kms_init() (bsc#1152472) Backporting changes:
    &#9;* context fixes &#9;* adapted to function layout

  - drm/msm: Avoid div-by-zero in dpu_crtc_atomic_check()
    (bsc#1152489)

  - drm/msm: Drop debug print in _dpu_crtc_setup_lm_bounds()
    (bsc#1152489) Backporting changes: &#9;* context fixes

  - drm/panfrost: Ensure GPU quirks are always initialised
    (bsc#1152489)

  - drm/panfrost: increase readl_relaxed_poll_timeout values
    (bsc#1152472) Backporting changes: &#9;* context fixes

  - drm/radeon: Prefer lower feedback dividers (bsc#1152489)

  - drm/sun4i: sun8i-csc: Secondary CSC register correction
    (bsc#1152489)

  - drm/vc4/vc4_hdmi: fill ASoC card owner (bsc#1152489)

  - drm/vc4: crtc: Rework a bit the CRTC state code
    (bsc#1152472) Backporting changes: &#9;* context fixes

  - drm/vc4: hdmi: Avoid sleeping in atomic context
    (bsc#1152489) Backporting changes: &#9;* context fixes

  - drm/vkms: fix xrgb on compute crc (bsc#1152472)
    Backporting changes: &#9;* changed filename from
    vkms_composer.c to vkms_crc.c &#9;* context fixes

  - drm: mxsfb: Remove fbdev leftovers (bsc#1152472)
    Backporting changes: &#9;* context fixes

  - drm: mxsfb: check framebuffer pitch (bsc#1152472)
    Backporting changes: &#9;* context fixes

  - drm: panel: Fix bpc for OrtusTech COM43H4M85ULC panel
    (bsc#1152489)

  - drm: panel: Fix bus format for OrtusTech COM43H4M85ULC
    panel (bsc#1152472) Backporting changes: &#9;* context
    fixes

  - drm: rcar-du: Put reference to VSP device (bsc#1152489)

  - epoll: Keep a reference on files added to the check list
    (bsc#1180031).

  - ethtool: fix error handling in ethtool_phys_id
    (git-fixes).

  - ext4: correctly report 'not supported' for
    (usr,grp)jquota when !CONFIG_QUOTA (bsc#1179672).

  - ext4: fix bogus warning in ext4_update_dx_flag()
    (bsc#1179716).

  - ext4: fix leaking sysfs kobject after failed mount
    (bsc#1179670).

  - ext4: limit entries returned when counting fsmap records
    (bsc#1179671).

  - ext4: unlock xattr_sem properly in
    ext4_inline_data_truncate() (bsc#1179673).

  - extcon: max77693: Fix modalias string (git-fixes).

  - fail_function: Remove a redundant mutex unlock
    (bsc#1149032).

  - fbcon: Remove the superfluous break (bsc#1152472)

  - firmware: arm_sdei: Document the motivation behind these
    set_fs() calls (jsc#SLE-16610).

  - fix regression in 'epoll: Keep a reference on files
    added to the check list' (bsc#1180031, git-fixes).

  - fs/minix: check return value of sb_getblk()
    (bsc#1179676).

  - fs/minix: do not allow getting deleted inodes
    (bsc#1179677).

  - fs/minix: fix block limit check for V1 filesystems
    (bsc#1179680).

  - fs/minix: reject too-large maximum file size
    (bsc#1179678).

  - fs/minix: remove expected error message in
    block_to_path() (bsc#1179681).

  - fs/minix: set s_maxbytes correctly (bsc#1179679).

  - fs/ufs: avoid potential u32 multiplication overflow
    (bsc#1179682).

  - fs: Do not invalidate page buffers in
    block_write_full_page() (bsc#1179711).

  - ftrace: Fix updating FTRACE_FL_TRAMP (git-fixes).

  - geneve: pull IP header before ECN decapsulation
    (git-fixes).

  - genirq/irqdomain: Add an irq_create_mapping_affinity()
    function (bsc#1065729).

  - genirq/matrix: Deal with the sillyness of for_each_cpu()
    on UP (bsc#1156315).

  - gpio: mvebu: fix potential user-after-free on probe
    (git-fixes).

  - gpio: mvebu: update Armada XP per-CPU comment
    (git-fixes).

  - i2c: i801: Fix the i2c-mux gpiod_lookup_table not being
    properly terminated (git-fixes).

  - i2c: qup: Fix error return code in
    qup_i2c_bam_schedule_desc() (git-fixes).

  - i2c: sprd: use a specific timeout to avoid system hang
    up issue (git-fixes).

  - i3c master: fix missing destroy_workqueue() on error in
    i3c_master_register (git-fixes).

  - ibmvnic: add some debugs (bsc#1179896 ltc#190255).

  - ibmvnic: avoid memset null scrq msgs (bsc#1044767
    ltc#155231 git-fixes).

  - ibmvnic: continue fatal error reset after passive init
    (bsc#1171078 ltc#184239 git-fixes).

  - ibmvnic: delay next reset if hard reset fails
    (bsc#1094840 ltc#167098 git-fixes).

  - ibmvnic: enhance resetting status check during module
    exit (bsc#1065729).

  - ibmvnic: fix NULL pointer dereference in
    reset_sub_crq_queues (bsc#1040855 ltc#155067 git-fixes).

  - ibmvnic: fix call_netdevice_notifiers in do_reset
    (bsc#1115431 ltc#171853 git-fixes).

  - ibmvnic: fix: NULL pointer dereference (bsc#1044767
    ltc#155231 git-fixes).

  - ibmvnic: notify peers when failover and migration happen
    (bsc#1044120 ltc#155423 git-fixes).

  - ibmvnic: restore adapter state on failed reset
    (bsc#1152457 ltc#174432 git-fixes).

  - iio: adc: rockchip_saradc: fix missing
    clk_disable_unprepare() on error in
    rockchip_saradc_resume (git-fixes).

  - iio: buffer: Fix demux update (git-fixes).

  - iio:adc:ti-ads124s08: Fix alignment and data leak issues
    (git-fixes).

  - iio:adc:ti-ads124s08: Fix buffer being too long
    (git-fixes).

  - iio:imu:bmi160: Fix too large a buffer (git-fixes).

  - iio:light:rpr0521: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:light:st_uvis25: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:magnetometer:mag3110: Fix alignment and data leak
    issues (git-fixes).

  - iio:pressure:mpl3115: Force alignment of buffer
    (git-fixes).

  - inet_ecn: Fix endianness of checksum update when setting
    ECT(1) (git-fixes).

  - iomap: Clear page error before beginning a write
    (bsc#1179683).

  - iomap: Mark read blocks uptodate in write_begin
    (bsc#1179684).

  - iomap: Set all uptodate bits for an Uptodate page
    (bsc#1179685).

  -
    iommu-amd-Increase-interrupt-remapping-table-limit-t.pat
    ch: (bsc#1179652).

  - iommu/amd: Set DTE[IntTabLen] to represent 512 IRTEs
    (bsc#1179652).

  - iwlwifi: mvm: fix kernel panic in case of assert during
    CSA (git-fixes).

  - iwlwifi: mvm: hook up missing RX handlers (git-fixes).

  - iwlwifi: pcie: add one missing entry for AX210
    (git-fixes).

  - iwlwifi: pcie: limit memory read spin time (git-fixes).

  - jbd2: fix up sparse warnings in checkpoint code
    (bsc#1179707).

  - kABI workaround for HD-audio generic parser (git-fixes).

  - kABI workaround for USB audio driver (bsc#1178203).

  - kABI: genirq: add back irq_create_mapping (bsc#1065729).

  - kdb: Fix pager search for multi-line strings
    (git-fixes).

  - kernel/cpu: add arch override for
    clear_tasks_mm_cpumask() mm handling (bsc#1055117
    ltc#159753 git-fixes bsc#1179888 ltc#190253).

  - kgdb: Drop malformed kernel doc comment (git-fixes).

  - lan743x: fix for potential NULL pointer dereference with
    bare card (git-fixes).

  - lib/string: remove unnecessary #undefs (git-fixes).

  - libfs: fix error cast of negative value in
    simple_attr_write() (bsc#1179709).

  - locking/percpu-rwsem: Use this_cpu_(inc,dec)() for
    read_count (bsc#1149032).

  - mac80211: do not set set TDLS STA bandwidth wider than
    possible (git-fixes).

  - mac80211: mesh: fix mesh_pathtbl_init() error path
    (git-fixes).

  - md-cluster: fix rmmod issue when md_cluster convert
    bitmap to none (bsc#1163727).

  - md-cluster: fix safemode_delay value when converting to
    clustered bitmap (bsc#1163727).

  - md-cluster: fix wild pointer of unlock_all_bitmaps()
    (bsc#1163727).

  - md/bitmap: fix memory leak of temporary bitmap
    (bsc#1163727).

  - md/bitmap: md_bitmap_get_counter returns wrong blocks
    (bsc#1163727).

  - md/bitmap: md_bitmap_read_sb uses wrong bitmap blocks
    (bsc#1163727).

  - md/cluster: block reshape with remote resync job
    (bsc#1163727).

  - md/cluster: fix deadlock when node is doing resync job
    (bsc#1163727).

  - media: gp8psk: initialize stats at power control logic
    (git-fixes).

  - media: gspca: Fix memory leak in probe (git-fixes).

  - media: imx214: Fix stop streaming (git-fixes).

  - media: ipu3-cio2: Make the field on subdev format
    V4L2_FIELD_NONE (git-fixes).

  - media: ipu3-cio2: Remove traces of returned buffers
    (git-fixes).

  - media: ipu3-cio2: Return actual subdev format
    (git-fixes).

  - media: ipu3-cio2: Serialise access to pad format
    (git-fixes).

  - media: ipu3-cio2: Validate mbus format in setting subdev
    format (git-fixes).

  - media: max2175: fix max2175_set_csm_mode() error code
    (git-fixes).

  - media: msi2500: assign SPI bus number dynamically
    (git-fixes).

  - media: mtk-vcodec: add missing put_device() call in
    mtk_vcodec_init_dec_pm() (git-fixes).

  - media: mtk-vcodec: add missing put_device() call in
    mtk_vcodec_init_enc_pm() (git-fixes).

  - media: mtk-vcodec: add missing put_device() call in
    mtk_vcodec_release_dec_pm() (git-fixes).

  - media: saa7146: fix array overflow in vidioc_s_audio()
    (git-fixes).

  - media: siano: fix memory leak of debugfs members in
    smsdvb_hotplug (git-fixes).

  - media: solo6x10: fix missing snd_card_free in error
    handling case (git-fixes).

  - media: sunxi-cir: ensure IR is handled when it is
    continuous (git-fixes).

  - media: tm6000: Fix sizeof() mismatches (git-fixes).

  - media: uvcvideo: Accept invalid bFormatIndex and
    bFrameIndex values (bsc#1180117).

  - memstick: fix a double-free bug in memstick_check
    (git-fixes).

  - memstick: r592: Fix error return in r592_probe()
    (git-fixes).

  - mfd: rt5033: Fix errorneous defines (git-fixes).

  - misc: vmw_vmci: fix kernel info-leak by initializing
    dbells in vmci_ctx_get_chkpt_doorbells() (git-fixes).

  - mm,memory_failure: always pin the page in
    madvise_inject_error (bsc#1180258).

  - mm/error_inject: Fix allow_error_inject function
    signatures (bsc#1179710).

  - mm/memory-failure: Add memory_failure_queue_kick()
    (jsc#SLE-16610).

  - mm/memory_hotplug: shrink zones when offlining memory
    (bsc#1177679).

  - mm/userfaultfd: do not access vma->vm_mm after calling
    handle_userfault() (bsc#1179204).

  - mm: memcg: fix memcg reclaim soft lockup (VM
    Functionality, bsc#1180056).

  - mmc: block: Fixup condition for CMD13 polling for RPMB
    requests (git-fixes).

  - mmc: pxamci: Fix error return code in pxamci_probe
    (git-fixes).

  - mtd: rawnand: gpmi: Fix the random DMA timeout issue
    (git-fixes).

  - mtd: rawnand: gpmi: fix reference count leak in gpmi ops
    (git-fixes).

  - mtd: rawnand: meson: Fix a resource leak in init
    (git-fixes).

  - mtd: rawnand: meson: fix meson_nfc_dma_buffer_release()
    arguments (git-fixes).

  - mtd: rawnand: qcom: Fix DMA sync on FLASH_STATUS
    register read (git-fixes).

  - mtd: spinand: Fix OOB read (git-fixes).

  - mwifiex: fix mwifiex_shutdown_sw() causing sw reset
    failure (git-fixes).

  - net/x25: prevent a couple of overflows (bsc#1178590).

  - net: sctp: Rename fallthrough label to unhandled
    (bsc#1178203).

  - nfc: s3fwrn5: Release the nfc firmware (git-fixes).

  - nvme-fabrics: allow to queue requests for live queues
    (git-fixes).

  - nvme-fabrics: do not check state NVME_CTRL_NEW for
    request acceptance (bsc#1179519).

  - nvme-fc: avoid calling _nvme_fc_abort_outstanding_ios
    from interrupt context (bsc#1177326).

  - nvme-fc: cancel async events before freeing event struct
    (git-fixes).

  - nvme-fc: eliminate terminate_io use by
    nvme_fc_error_recovery (bsc#1177326).

  - nvme-fc: fix error loop in create_hw_io_queues
    (git-fixes).

  - nvme-fc: fix io timeout to abort I/O (bsc#1177326).

  - nvme-fc: remove err_work work item (bsc#1177326).

  - nvme-fc: remove nvme_fc_terminate_io() (bsc#1177326).

  - nvme-fc: shorten reconnect delay if possible for FC
    (git-fixes).

  - nvme-fc: track error_recovery while connecting
    (bsc#1177326).

  - nvme-fc: wait for queues to freeze before calling
    (git-fixes).

  - nvme-force-complete-cancelled-requests.patch:
    (bsc#1175995,bsc#1178756,jsc#SLE-15608). Without this we
    can end up with a series of nvme QID timeouts,
    regardless of filesystem when fstests is used or any
    error injection mechanism is used. Without this fix, we
    end up with 9 failures on xfs, but due to its generic
    nature, will likely end up with other failures on other
    filesystems. This does not allow a clean slate reliable
    fstests run. This fixes that issue. Through code
    inspection I found these changes were already present on
    SLE15-SP3 but not on SLE15-SP2.

  - nvme-multipath: fix bogus request queue reference put
    (bsc#1175389).

  - nvme-multipath: fix deadlock between ana_work and
    scan_work (git-fixes).

  - nvme-multipath: fix deadlock due to head->lock
    (git-fixes).

  - nvme-pci: properly print controller address (git-fixes).

  - nvme-rdma: avoid race between time out and tear down
    (bsc#1179519).

  - nvme-rdma: avoid repeated request completion
    (bsc#1179519).

  - nvme-rdma: cancel async events before freeing event
    struct (git-fixes).

  - nvme-rdma: fix controller reset hang during traffic
    (bsc#1179519).

  - nvme-rdma: fix reset hang if controller died in the
    middle of a reset (bsc#1179519).

  - nvme-rdma: fix timeout handler (bsc#1179519).

  - nvme-rdma: handle unexpected nvme completion data length
    (bsc#1178612).

  - nvme-rdma: serialize controller teardown sequences
    (bsc#1179519).

  - nvme-tcp: avoid race between time out and tear down
    (bsc#1179519).

  - nvme-tcp: avoid repeated request completion
    (bsc#1179519).

  - nvme-tcp: avoid scheduling io_work if we are already
    polling (bsc#1179519).

  - nvme-tcp: break from io_work loop if recv failed
    (bsc#1179519).

  - nvme-tcp: cancel async events before freeing event
    struct (git-fixes).

  - nvme-tcp: do not poll a non-live queue (bsc#1179519).

  - nvme-tcp: fix controller reset hang during traffic
    (bsc#1179519).

  - nvme-tcp: fix possible crash in recv error flow
    (bsc#1179519).

  - nvme-tcp: fix possible leakage during error flow
    (git-fixes).

  - nvme-tcp: fix reset hang if controller died in the
    middle of a reset (bsc#1179519).

  - nvme-tcp: fix timeout handler (bsc#1179519).

  - nvme-tcp: have queue prod/cons send list become a llist
    (bsc#1179519).

  - nvme-tcp: leverage request plugging (bsc#1179519).

  - nvme-tcp: move send failure to nvme_tcp_try_send
    (bsc#1179519).

  - nvme-tcp: optimize network stack with setting msg flags
    (bsc#1179519).

  - nvme-tcp: optimize queue io_cpu assignment for multiple
    queue (git-fixes).

  - nvme-tcp: serialize controller teardown sequences
    (bsc#1179519).

  - nvme-tcp: set MSG_SENDPAGE_NOTLAST with MSG_MORE when we
    have (bsc#1179519).

  - nvme-tcp: try to send request in queue_rq context
    (bsc#1179519).

  - nvme-tcp: use bh_lock in data_ready (bsc#1179519).

  - nvme: Revert: Fix controller creation races with
    teardown (git-fixes).

  - nvme: do not protect ns mutation with ns->head->lock
    (git-fixes).

  - nvme: have nvme_wait_freeze_timeout return if it timed
    out (bsc#1179519).

  - nvme: introduce nvme_sync_io_queues (bsc#1179519).

  - nvmet-fc: fix missing check for no hostport struct
    (bsc#1176942).

  - nvmet-tcp: fix maxh2cdata icresp parameter
    (bsc#1179892).

  - ocfs2: fix unbalanced locking (bsc#1180506).

  - orinoco: Move context allocation after processing the
    skb (git-fixes).

  - pinctrl: amd: remove debounce filter setting in IRQ type
    setting (git-fixes).

  - pinctrl: aspeed: Fix GPIO requests on pass-through banks
    (git-fixes).

  - pinctrl: baytrail: Avoid clearing debounce value when
    turning it off (git-fixes).

  - pinctrl: falcon: add missing put_device() call in
    pinctrl_falcon_probe() (git-fixes).

  - pinctrl: merrifield: Set default bias in case no
    particular value given (git-fixes).

  - platform/chrome: cros_ec_spi: Do not overwrite spi::mode
    (git-fixes).

  - platform/x86: acer-wmi: add automatic keyboard
    background light toggle key as KEY_LIGHTS_TOGGLE
    (git-fixes).

  - platform/x86: dell-smbios-base: Fix error return code in
    dell_smbios_init (git-fixes).

  - platform/x86: intel-vbtn: Allow switch events on Acer
    Switch Alpha 12 (git-fixes).

  - platform/x86: intel-vbtn: Support for tablet mode on HP
    Pavilion 13 x360 PC (git-fixes).

  - platform/x86: mlx-platform: Fix item counter assignment
    for MSN2700, MSN24xx systems (git-fixes).

  - platform/x86: mlx-platform: Remove PSU EEPROM from
    MSN274x platform configuration (git-fixes).

  - platform/x86: mlx-platform: Remove PSU EEPROM from
    default platform configuration (git-fixes).

  - platform/x86: mlx-platform: remove an unused variable
    (git-fixes).

  - platform/x86: thinkpad_acpi: Add BAT1 is primary battery
    quirk for Thinkpad Yoga 11e 4th gen (git-fixes).

  - platform/x86: thinkpad_acpi: Do not report
    SW_TABLET_MODE on Yoga 11e (git-fixes).

  - platform/x86: touchscreen_dmi: Add info for the Irbis
    TW118 tablet (git-fixes).

  - power: supply: axp288_charger: Fix HP Pavilion x2 10 DMI
    matching (git-fixes).

  - power: supply: bq24190_charger: fix reference leak
    (git-fixes).

  - powerpc/64: Set up a kernel stack for secondaries before
    cpu_restore() (bsc#1065729).

  - powerpc/64s/powernv: Fix memory corruption when saving
    SLB entries on MCE (jsc#SLE-9246 git-fixes).

  - powerpc/64s/pseries: Fix hash tlbiel_all_isa300 for
    guest kernels (bsc#1179888 ltc#190253).

  - powerpc/64s: Fix allnoconfig build since uaccess flush
    (bsc#1177666 git-fixes).

  - powerpc/64s: Fix hash ISA v3.0 TLBIEL instruction
    generation (bsc#1055117 ltc#159753 git-fixes bsc#1179888
    ltc#190253).

  - powerpc/64s: Trim offlined CPUs from mm_cpumasks
    (bsc#1055117 ltc#159753 git-fixes bsc#1179888
    ltc#190253).

  - powerpc/bitops: Fix possible undefined behaviour with
    fls() and fls64() (bsc#1156395).

  - powerpc/eeh_cache: Fix a possible debugfs deadlock
    (bsc#1156395).

  - powerpc/numa: Fix a regression on memoryless node 0
    (bsc#1179639 ltc#189002).

  - powerpc/pci: Remove LSI mappings on device teardown
    (bsc#1172145 ltc#184630).

  - powerpc/perf: Fix crash with is_sier_available when pmu
    is not set (bsc#1179578 ltc#189313).

  - powerpc/pseries/hibernation: remove redundant cacheinfo
    update (bsc#1138374 ltc#178199 git-fixes).

  - powerpc/pseries: Pass MSI affinity to
    irq_create_mapping() (bsc#1065729).

  - powerpc/smp: Add __init to init_big_cores() (bsc#1109695
    ltc#171067 git-fixes).

  - powerpc/xmon: Change printk() to pr_cont()
    (bsc#1065729).

  - powerpc: Avoid broken GCC __attribute__((optimize))
    (bsc#1156395).

  - powerpc: Fix incorrect stw(, ux, u, x) instructions in
    __set_pte_at (bsc#1065729).

  - pwm: lp3943: Dynamically allocate PWM chip base
    (git-fixes).

  - pwm: zx: Add missing cleanup in error path (git-fixes).

  - qede: Notify qedr when mtu has changed (bsc#1152489)

  - qtnfmac: fix error return code in qtnf_pcie_probe()
    (git-fixes).

  - quota: clear padding in v2r1_mem2diskdqb()
    (bsc#1179714).

  - r8169: work around power-saving bug on some chip
    versions (git-fixes).

  - regmap: Remove duplicate `type` field from regmap
    `regcache_sync` trace event (git-fixes).

  - regmap: debugfs: Fix a memory leak when calling
    regmap_attach_dev (git-fixes).

  - regmap: debugfs: Fix a reversed if statement in
    regmap_debugfs_init() (git-fixes).

  - regulator: axp20x: Fix DLDO2 voltage control register
    mask for AXP22x (git-fixes).

  - regulator: mcp16502: add linear_min_sel (git-fixes).

  - reiserfs: Fix oops during mount (bsc#1179715).

  - reiserfs: Initialize inode keys properly (bsc#1179713).

  - remoteproc: q6v5-mss: fix error handling in
    q6v5_pds_enable (git-fixes).

  - remoteproc: qcom: Fix potential NULL dereference in
    adsp_init_mmio() (git-fixes).

  - remoteproc: qcom: fix reference leak in adsp_start
    (git-fixes).

  - rsi: fix error return code in rsi_reset_card()
    (git-fixes).

  - rtc: ep93xx: Fix NULL pointer dereference in
    ep93xx_rtc_read_time (git-fixes).

  - rtc: hym8563: enable wakeup when applicable (git-fixes).

  - rtc: pl031: fix resource leak in pl031_probe
    (git-fixes).

  - rtc: sun6i: Fix memleak in sun6i_rtc_clk_init
    (git-fixes).

  - rtw88: debug: Fix uninitialized memory in debugfs code
    (git-fixes).

  - s390/cpuinfo: show processor physical address
    (git-fixes).

  - s390/pci: fix CPU address in MSI for directed IRQ
    (git-fixes).

  - s390/qeth: delay draining the TX buffers (git-fixes).

  - s390/qeth: fix af_iucv notification race (git-fixes).

  - s390/qeth: fix tear down of async TX buffers
    (git-fixes).

  - s390/qeth: make af_iucv TX notification call more robust
    (bsc#1179604 LTC#190151).

  - s390: add 3f program exception handler (git-fixes).

  - samples/bpf: Remove unused test_ipip.sh (bsc#1155518).

  - samples: bpf: Refactor test_cgrp2_sock2 program with
    libbpf (bsc#1155518).

  - sched/fair: Check for idle core in wake_affine (git
    fixes (sched)).

  - sched/fair: Fix overutilized update in
    enqueue_task_fair() (git-fixes)

  - sched/fair: Fix race between runtime distribution and
    (git-fixes)

  - sched/fair: Fix wrong cpu selecting from isolated domain
    (git-fixes)

  - sched/fair: Refill bandwidth before scaling (git-fixes)

  - sched: correct SD_flags returned by tl->sd_flags()
    (git-fixes)

  - scsi: Remove unneeded break statements (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: core: Fix VPD LUN ID designator priorities
    (bsc#1178049).

  - scsi: core: Return BLK_STS_AGAIN for ALUA transitioning
    (bsc#1165933, bsc#1171000).

  - scsi: fnic: Avoid looping in TRANS ETH on unload
    (bsc#1175079).

  - scsi: fnic: Change shost_printk() to FNIC_FCS_DBG()
    (bsc#1175079).

  - scsi: fnic: Change shost_printk() to FNIC_MAIN_DBG()
    (bsc#1175079).

  - scsi: fnic: Set scsi_set_resid() only for underflow
    (bsc#1175079).

  - scsi: fnic: Validate io_req before others (bsc#1175079).

  - scsi: lpfc: Add FDMI Vendor MIB support (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Convert SCSI I/O completions to SLI-3 and
    SLI-4 handlers (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Convert SCSI path to use common I/O
    submission path (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Convert abort handling to SLI-3 and SLI-4
    handlers (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Correct null ndlp reference on routine exit
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Drop nodelist reference on error in
    lpfc_gen_req() (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Enable common send_io interface for SCSI and
    NVMe (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Enable common wqe_template support for both
    SCSI and NVMe (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Enlarge max_sectors in scsi host templates
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Extend the RDF FPIN Registration descriptor
    for additional events (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix FLOGI/PLOGI receive race condition in
    pt2pt discovery (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Fix NPIV Fabric Node reference counting
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix NPIV discovery and Fabric Node detection
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix duplicate wq_create_version check
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix fall-through warnings for Clang
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix initial FLOGI failure due to BBSCN not
    supported (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Fix invalid sleeping context in
    lpfc_sli4_nvmet_alloc() (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix memory leak on lcb_context (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix missing prototype for
    lpfc_nvmet_prep_abort_wqe() (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix missing prototype warning for
    lpfc_fdmi_vendor_attr_mi() (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix pointer defereference before it is null
    checked issue (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Fix refcounting around SCSI and NVMe
    transport APIs (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Fix removal of SCSI transport device get and
    put on dev structure (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix scheduling call while in softirq context
    in lpfc_unreg_rpi (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Fix set but not used warnings from Rework
    remote port lock handling (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix set but unused variables in
    lpfc_dev_loss_tmo_handler() (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix spelling mistake 'Cant' -> 'Can't'
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Fix variable 'vport' set but not used in
    lpfc_sli4_abts_err_handler() (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Re-fix use after free in lpfc_rq_buf_free()
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Refactor WQE structure definitions for
    common use (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Reject CT request for MIB commands
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Remove dead code on second !ndlp check
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Remove ndlp when a PLOGI/ADISC/PRLI/REG_RPI
    ultimately fails (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Remove set but not used 'qp' (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Remove unneeded variable 'status' in
    lpfc_fcp_cpu_map_store() (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Removed unused macros in lpfc_attr.c
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Rework locations of ndlp reference taking
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Rework remote port lock handling
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Rework remote port ref counting and node
    freeing (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: Unsolicited ELS leaves node in incorrect
    state while dropping it (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: Update changed file copyrights for 2020
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Update lpfc version to 12.8.0.4 (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Update lpfc version to 12.8.0.5 (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Update lpfc version to 12.8.0.6 (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: Use generic power management (bsc#1175480
    bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: lpfc_attr: Demote kernel-doc format for
    redefined functions (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: lpfc_attr: Fix-up a bunch of kernel-doc
    misdemeanours (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: lpfc_bsg: Provide correct documentation for
    a bunch of functions (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: lpfc_debugfs: Fix a couple of function
    documentation issues (bsc#1175480 bsc#1176396
    bsc#1176942 bsc#1177500).

  - scsi: lpfc: lpfc_nvme: Fix some kernel-doc related
    issues (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: lpfc_nvme: Remove unused variable 'phba'
    (bsc#1175480 bsc#1176396 bsc#1176942 bsc#1177500).

  - scsi: lpfc: lpfc_nvmet: Fix-up some formatting and
    doc-rot issues (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: lpfc: lpfc_scsi: Fix a whole host of kernel-doc
    issues (bsc#1175480 bsc#1176396 bsc#1176942
    bsc#1177500).

  - scsi: mpt3sas: A small correction in
    _base_process_reply_queue (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Add bypass_dirty_port_flag parameter
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Add functions to check if any cmd is
    outstanding on Target and LUN (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Add module parameter multipath_on_hba
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Allocate memory for hba_port objects
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Bump driver version to 35.101.00.00
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Cancel the running work during host reset
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Capture IOC data for debugging purposes
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Define hba_port structure (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Detect tampered Aero and Sea adapters
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Disable DIF when prot_mask set to zero
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Do not call disable_irq from IRQ poll
    handler (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Do not change the DMA coherent mask after
    allocations (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Dump system registers for debugging
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Fix double free warnings (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Fix error returns in BRM_status_show
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Fix memset() in non-RDPQ mode
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Fix reply queue count in non RDPQ mode
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Fix set but unused variable
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Fix sync irqs (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Fix unlock imbalance (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Get device objects using sas_address &
    portID (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Get sas_device objects using device's
    rphy (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Handle RDPQ DMA allocation in same 4G
    region (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Handle vSES vphy object during HBA reset
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Handling HBA vSES device (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Memset config_cmds.reply buffer with
    zeros (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Postprocessing of target and LUN reset
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Rearrange
    _scsih_mark_responding_sas_device() (jsc#SLE-16914,
    bsc#1177733).

  - scsi: mpt3sas: Remove NULL check before freeing function
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Remove pci-dma-compat wrapper API
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Remove superfluous memset()
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Rename and export interrupt mask/unmask
    functions (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Rename function name is_MSB_are_same
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Rename
    transport_del_phy_from_an_existing_port()
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Separate out RDPQ allocation to new
    function (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Set valid PhysicalPort in SMPPassThrough
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Update driver version to 35.100.00.00
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Update hba_port objects after host reset
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Update hba_port's sas_address & phy_mask
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Update mpt3sas version to 33.101.00.00
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: Use true, false for ioc->use_32bit_dma
    (jsc#SLE-16914, bsc#1177733).

  - scsi: mpt3sas: use true,false for bool variables
    (jsc#SLE-16914, bsc#1177733).

  - scsi: qla2xxx: Change post del message from debug level
    to log level (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Convert to DEFINE_SHOW_ATTRIBUTE
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Do not check for fw_started while posting
    NVMe command (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Do not consume srb greedily (bsc#1171688
    bsc#1172733).

  - scsi: qla2xxx: Drop TARGET_SCF_LOOKUP_LUN_FROM_TAG
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix FW initialization error on big endian
    machines (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix N2N and NVMe connect retry failure
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix compilation issue in PPC systems
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix crash during driver load on big
    endian machines (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix device loss on 4G and older HBAs
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix flash update in 28XX adapters on big
    endian machines (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix return of uninitialized value in rval
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Fix the call trace for flush workqueue
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Handle aborts correctly for port
    undergoing deletion (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Handle incorrect entry_type entries
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: If fcport is undergoing deletion complete
    I/O with retry (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Initialize variable in qla8044_poll_reg()
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Limit interrupt vectors to number of CPUs
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Move sess cmd list/lock to driver
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Remove in_interrupt() from
    qla82xx-specific code (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Remove in_interrupt() from
    qla83xx-specific code (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Return EBUSY on fcport deletion
    (bsc#1171688 bsc#1172733). Replace
    patches.suse/qla2xxx-return-ebusy-on-fcport-deletion.pat
    ch with upstream version.

  - scsi: qla2xxx: Tear down session if FW say it is down
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Update version to 10.02.00.104-k
    (bsc#1171688 bsc#1172733).

  - scsi: qla2xxx: Use constant when it is known
    (bsc#1171688 bsc#1172733). Refresh: -
    patches.suse/qla2xxx-return-ebusy-on-fcport-deletion.pat
    ch

  - scsi: qla2xxx: remove incorrect sparse #ifdef
    (bsc#1171688 bsc#1172733).

  - scsi: storvsc: Fix error return in storvsc_probe()
    (git-fixes).

  - scsi: target: tcm_qla2xxx: Remove BUG_ON(in_interrupt())
    (bsc#1171688 bsc#1172733).

  - scsi_dh_alua: return BLK_STS_AGAIN for ALUA
    transitioning state (bsc#1165933, bsc#1171000).

  - scsi_dh_alua: set 'transitioning' state on unit
    attention (bsc#1171000, bsc#1165933).

  - selftest/bpf: Add missed ip6ip6 test back (bsc#1155518).

  - selftests/bpf/test_offload.py: Reset ethtool features
    after failed setting (bsc#1155518).

  - selftests/bpf: Fix invalid use of strncat in
    test_sockmap (bsc#1155518).

  - selftests/bpf: Print reason when a tester could not run
    a program (bsc#1155518).

  - serial: 8250_omap: Avoid FIFO corruption caused by MDR1
    access (git-fixes).

  - serial_core: Check for port state when tty is in error
    state (git-fixes).

  - slimbus: qcom-ngd-ctrl: Avoid sending power requests
    without QMI (git-fixes).

  - soc/tegra: fuse: Fix index bug in get_process_id
    (git-fixes).

  - soc: amlogic: canvas: add missing put_device() call in
    meson_canvas_get() (git-fixes).

  - soc: fsl: dpio: Get the cpumask through cpumask_of(cpu)
    (git-fixes).

  - soc: mediatek: Check if power domains can be powered on
    at boot time (git-fixes).

  - soc: qcom: geni: More properly switch to DMA mode
    (git-fixes).

  - soc: qcom: smp2p: Safely acquire spinlock without IRQs
    (git-fixes).

  - soc: renesas: rmobile-sysc: Fix some leaks in
    rmobile_init_pm_domains() (git-fixes).

  - soc: ti: Fix reference imbalance in knav_dma_probe
    (git-fixes).

  - soc: ti: knav_qmss: fix reference leak in
    knav_queue_probe (git-fixes).

  - speakup: fix uninitialized flush_lock (git-fixes).

  - spi: atmel-quadspi: Disable clock in probe error path
    (git-fixes).

  - spi: atmel-quadspi: Fix AHB memory accesses (git-fixes).

  - spi: bcm63xx-hsspi: fix missing clk_disable_unprepare()
    on error in bcm63xx_hsspi_resume (git-fixes).

  - spi: davinci: Fix use-after-free on unbind (git-fixes).

  - spi: fix resource leak for drivers without .remove
    callback (git-fixes).

  - spi: img-spfi: fix reference leak in img_spfi_resume
    (git-fixes).

  - spi: mt7621: Disable clock in probe error path
    (git-fixes).

  - spi: mt7621: fix missing clk_disable_unprepare() on
    error in mt7621_spi_probe (git-fixes).

  - spi: mxs: fix reference leak in mxs_spi_probe
    (git-fixes).

  - spi: pic32: Do not leak DMA channels in probe error path
    (git-fixes).

  - spi: spi-mem: Fix passing zero to 'PTR_ERR' warning
    (git-fixes).

  - spi: spi-mem: fix reference leak in spi_mem_access_start
    (git-fixes).

  - spi: spi-nxp-fspi: fix fspi panic by unexpected
    interrupts (git-fixes).

  - spi: spi-ti-qspi: fix reference leak in ti_qspi_setup
    (git-fixes).

  - spi: sprd: fix reference leak in sprd_spi_remove
    (git-fixes).

  - spi: st-ssc4: Fix unbalanced pm_runtime_disable() in
    probe error path (git-fixes).

  - spi: stm32: FIFO threshold level - fix align packet size
    (git-fixes).

  - spi: stm32: fix reference leak in stm32_spi_resume
    (git-fixes).

  - spi: synquacer: Disable clock in probe error path
    (git-fixes).

  - spi: tegra114: fix reference leak in tegra spi ops
    (git-fixes).

  - spi: tegra20-sflash: fix reference leak in
    tegra_sflash_resume (git-fixes).

  - spi: tegra20-slink: fix reference leak in slink ops of
    tegra20 (git-fixes).

  - staging: comedi: mf6x4: Fix AI end-of-conversion
    detection (git-fixes).

  - staging: mt7621-dma: Fix a resource leak in an error
    handling path (git-fixes).

  - staging: olpc_dcon: Do not call
    platform_device_unregister() in dcon_probe()
    (git-fixes).

  - staging: wlan-ng: fix out of bounds read in
    prism2sta_probe_usb() (git-fixes).

  - swiotlb: fix 'x86: Do not panic if can not alloc buffer
    for swiotlb' (git-fixes).

  - swiotlb: using SIZE_MAX needs limits.h included
    (git-fixes).

  - thunderbolt: Fix use-after-free in
    remove_unplugged_switch() (git-fixes).

  - tty: Fix ->pgrp locking in tiocspgrp() (git-fixes).

  - tty: Fix ->session locking (bsc#1179745).

  - ubifs: Do not parse authentication mount options in
    remount process (bsc#1179688).

  - ubifs: Fix a memleak after dumping authentication mount
    options (bsc#1179687).

  - ubifs: Fix wrong orphan node deletion in
    ubifs_jnl_update|rename (bsc#1179675).

  - ubifs: dent: Fix some potential memory leaks while
    iterating entries (bsc#1179703).

  - ubifs: journal: Make sure to not dirty twice for auth
    nodes (bsc#1179704).

  - ubifs: mount_ubifs: Release authentication resource in
    error handling path (bsc#1179689).

  - ubifs: xattr: Fix some potential memory leaks while
    iterating entries (bsc#1179690).

  - udf: Fix memory leak when mounting (bsc#1179712).

  - usb/max3421: fix return error code in max3421_probe()
    (git-fixes).

  - usb: chipidea: ci_hdrc_imx: Pass
    DISABLE_DEVICE_STREAMING flag to imx6ul (git-fixes).

  - usb: chipidea: ci_hdrc_imx: add missing put_device()
    call in usbmisc_get_init_data() (git-fixes).

  - usb: dwc3: ulpi: Use VStsDone to detect PHY regs access
    completion (git-fixes).

  - usb: ehci-omap: Fix PM disable depth umbalance in
    ehci_hcd_omap_probe (git-fixes).

  - usb: gadget: configfs: Preserve function ordering after
    bind failure (git-fixes).

  - usb: gadget: f_fs: Re-use SS descriptors for
    SuperSpeedPlus (git-fixes).

  - usb: gadget: f_fs: Use local copy of descriptors for
    userspace copy (git-fixes).

  - usb: gadget: f_uac2: reset wMaxPacketSize (git-fixes).

  - usb: gadget: select CONFIG_CRC32 (git-fixes).

  - usb: gadget: u_ether: Fix MTU size mismatch with RX
    packet size (git-fixes).

  - usb: host: ehci-tegra: Fix error handling in
    tegra_ehci_probe() (git-fixes).

  - usb: mtu3: fix memory corruption in
    mtu3_debugfs_regset() (git-fixes).

  - usb: oxu210hp-hcd: Fix memory leak in oxu_create
    (git-fixes).

  - usb: usbip: vhci_hcd: protect shift size (git-fixes).

  - usbnet: ipheth: fix connectivity with iOS 14
    (git-fixes).

  - video: fbdev: radeon: Fix memleak in
    radeonfb_pci_register (bsc#1152472)

  - video: fbdev: sis: fix null ptr dereference
    (bsc#1152472)

  - wan: ds26522: select CONFIG_BITREVERSE (git-fixes).

  - watchdog: Fix potential dereferencing of NULL pointer
    (git-fixes).

  - watchdog: armada_37xx: Add missing dependency on
    HAS_IOMEM (git-fixes).

  - watchdog: coh901327: add COMMON_CLK dependency
    (git-fixes).

  - watchdog: qcom: Avoid context switch in restart handler
    (git-fixes).

  - watchdog: sirfsoc: Add missing dependency on HAS_IOMEM
    (git-fixes).

  - watchdog: sprd: change to use usleep_range() instead of
    busy loop (git-fixes).

  - watchdog: sprd: check busy bit before new loading rather
    than after that (git-fixes).

  - watchdog: sprd: remove watchdog disable from resume fail
    path (git-fixes).

  - wil6210: select CONFIG_CRC32 (git-fixes).

  - wimax: fix duplicate initializer warning (git-fixes).

  - x86/CPU/AMD: Remove amd_get_nb_id() (bsc#1152489).

  - x86/CPU/AMD: Save AMD NodeId as cpu_die_id
    (bsc#1152489).

  - x86/apic/vector: Fix ordering in vector assignment
    (bsc#1156315).

  - x86/ima: use correct identifier for SetupMode variable
    (bsc#1152489).

  - x86/insn-eval: Use new for_each_insn_prefix() macro to
    loop over prefixes bytes (bsc#1152489).

  - x86/mce: Do not overwrite no_way_out if mce_end() fails
    (bsc#1152489).

  - x86/mm/ident_map: Check for errors from ident_pud_init()
    (bsc#1152489).

  - x86/mm/mem_encrypt: Fix definition of PMD_FLAGS_DEC_WP
    (bsc#1152489).

  - x86/mm/numa: Remove uninitialized_var() usage
    (bsc#1152489).

  - x86/mm: Fix leak of pmd ptlock (bsc#1152489).

  - x86/mtrr: Correct the range check before performing MTRR
    type lookups (bsc#1152489).

  - x86/resctrl: Add necessary kernfs_put() calls to prevent
    refcount leak (bsc#1152489).

  - x86/resctrl: Do not move a task to the same resource
    group (bsc#1152489).

  - x86/resctrl: Fix AMD L3 QOS CDP enable/disable
    (bsc#1152489).

  - x86/resctrl: Fix incorrect local bandwidth when mba_sc
    is enabled (bsc#1152489).

  - x86/resctrl: Remove superfluous kernfs_get() calls to
    prevent refcount leak (bsc#1152489).

  - x86/resctrl: Remove unused struct mbm_state::chunks_bw
    (bsc#1152489).

  - x86/resctrl: Use an IPI instead of task_work_add() to
    update PQR_ASSOC MSR (bsc#1152489).

  - x86/speculation: Fix prctl() when
    spectre_v2_user=(seccomp,prctl),ibpb (bsc#1152489).

  - x86/topology: Set cpu_die_id only if DIE_TYPE found
    (bsc#1152489).

  - x86/uprobes: Do not use prefixes.nbytes when looping
    over prefixes.bytes (bsc#1152489).

  - xhci-pci: Allow host runtime PM as default for Intel
    Alpine Ridge LP (git-fixes).

  - xhci: Give USB2 ports time to enter U3 in bus suspend
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180773");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.60.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.60.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-debuginfo / kernel-debug-debugsource / etc");
}
