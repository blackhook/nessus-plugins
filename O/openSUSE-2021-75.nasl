#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-75.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145287);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2019-20934",
    "CVE-2020-0444",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-4788",
    "CVE-2020-11668",
    "CVE-2020-25639",
    "CVE-2020-27068",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-27825",
    "CVE-2020-28374",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158"
  );

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-75)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-29568: An issue was discovered in Xen through
    4.14.x. Some OSes (such as Linux, FreeBSD, and NetBSD)
    are processing watch events using a single thread. If
    the events are received faster than the thread is able
    to handle, they will get queued. As the queue is
    unbounded, a guest may be able to trigger an OOM in the
    backend. All systems with a FreeBSD, Linux, or NetBSD
    (any version) dom0 are vulnerable (bnc#1179508).

  - CVE-2020-29569: The Linux kernel PV block backend
    expects the kernel thread handler to reset ring->xenblkd
    to NULL when stopped. However, the handler may not have
    time to run if the frontend quickly toggles between the
    states connect and disconnect. As a consequence, the
    block backend may re-use a pointer after it was freed. A
    misbehaving guest can trigger a dom0 crash by
    continuously connecting / disconnecting a block
    frontend. Privilege escalation and information leaks
    cannot be ruled out. This only affects systems with a
    Linux blkback (bnc#1179509).

  - CVE-2020-25639: Bail out of nouveau_channel_new if
    channel init fails (bsc#1176846).

  - CVE-2020-28374: In drivers/target/target_core_xcopy.c
    insufficient identifier checking in the LIO SCSI target
    code can be used by remote attackers to read or write
    files via directory traversal in an XCOPY request, aka
    CID-2896c93811e3. For example, an attack can occur over
    a network if the attacker has access to one iSCSI LUN.
    The attacker gains control over file access because I/O
    operations are proxied via an attacker-selected
    backstore (bnc#1178372 1180676).

  - CVE-2020-36158: mwifiex_cmd_802_11_ad_hoc_start in
    drivers/net/wireless/marvell/mwifiex/join.c might allow
    remote attackers to execute arbitrary code via a long
    SSID value, aka CID-5c455c5ab332 (bnc#1180559).

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

  - CVE-2020-0465: In various methods of hid-multitouch.c,
    there is a possible out of bounds write due to a missing
    bounds check. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1180029).

  - CVE-2020-0444: In audit_free_lsm_field of auditfilter.c,
    there is a possible bad kfree due to a logic error in
    audit_data_to_entry. This could lead to local escalation
    of privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1180027).

  - CVE-2020-29660: A locking inconsistency issue was
    discovered in the tty subsystem of the Linux kernel
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    have allowed a read-after-free attack against TIOCGSID,
    aka CID-c8bcd9c5be24 (bnc#1179745).

  - CVE-2020-29661: A locking issue was discovered in the
    tty subsystem of the Linux kernel
    drivers/tty/tty_jobctrl.c allowed a use-after-free
    attack against TIOCSPGRP, aka CID-54ffccbf053b
    (bnc#1179745).

  - CVE-2020-27777: A flaw was found in the way RTAS handled
    memory accesses in userspace to kernel communication. On
    a locked down (usually due to Secure Boot) guest system
    running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to
    further increase their privileges to that of a running
    kernel (bnc#1179107).

  - CVE-2020-11668: In the Linux kernel before 5.6.1,
    drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink
    camera USB driver) mishandled invalid descriptors, aka
    CID-a246b4d54770 (bnc#1168952).

  - CVE-2019-20934: An issue was discovered in the Linux
    kernel On NUMA systems, the Linux fair scheduler has a
    use-after-free in show_numa_stats() because NUMA fault
    statistics are inappropriately freed, aka
    CID-16d51a590a8c (bnc#1179663).

  - CVE-2020-27786: A flaw was found in the Linux kernels
    implementation of MIDI, where an attacker with a local
    account and the permissions to issue an ioctl commands
    to midi devices, could trigger a use-after-free. A write
    to this specific memory while freed and before use could
    cause the flow of execution to change and possibly allow
    for memory corruption or privilege escalation
    (bnc#1179601).

  - CVE-2020-4788: IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1)
    processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under
    extenuating circumstances. IBM X-Force ID: 189296
    (bnc#1177666).

The following non-security bugs were fixed :

  - ACPI: PNP: compare the string length in the
    matching_id() (git-fixes).

  - ACPICA: Disassembler: create buffer fields in
    ACPI_PARSE_LOAD_PASS1 (git-fixes).

  - ACPICA: Do not increment operation_region reference
    counts for field units (git-fixes).

  - ALSA: ca0106: fix error code handling (git-fixes).

  - ALSA: ctl: allow TLV read operation for callback type of
    element in locked case (git-fixes).

  - ALSA: hda - Fix silent audio output and corrupted input
    on MSI X570-A PRO (git-fixes).

  - ALSA: hda/ca0132 - Change Input Source enum strings
    (git-fixes).

  - ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg
    (git-fixes).

  - ALSA: hda/generic: Add option to enforce preferred_dacs
    pairs (git-fixes).

  - ALSA: hda/hdmi: always check pin power status in i915
    pin fixup (git-fixes).

  - ALSA: hda/realtek - Add new codec supported for ALC897
    (git-fixes).

  - ALSA: hda/realtek - Couldn't detect Mic if booting with
    headset plugged (git-fixes).

  - ALSA: hda/realtek - Enable headset mic of ASUS Q524UQK
    with ALC255 (git-fixes).

  - ALSA: hda/realtek: Add mute LED quirk to yet another HP
    x360 model (git-fixes).

  - ALSA: hda/realtek: Add some Clove SSID in the
    ALC293(ALC1220) (git-fixes).

  - ALSA: hda/realtek: Enable front panel headset LED on
    Lenovo ThinkStation P520 (git-fixes).

  - ALSA: hda/realtek: Enable headset of ASUS UX482EG &
    B9400CEA with ALC294 (git-fixes).

  - ALSA: hda/via: Fix runtime PM for Clevo W35xSS
    (git-fixes).

  - ALSA: hda: Add NVIDIA codec IDs 9a & 9d through a0 to
    patch table (git-fixes).

  - ALSA: hda: Fix potential race in unsol event handler
    (git-fixes).

  - ALSA: hda: Fix regressions on clear and reconfig sysfs
    (git-fixes).

  - ALSA: info: Drop WARN_ON() from buffer NULL sanity check
    (git-fixes).

  - ALSA: isa/wavefront: prevent out of bounds write in
    ioctl (git-fixes).

  - ALSA: line6: Perform sanity check for each URB creation
    (git-fixes).

  - ALSA: pcm: Clear the full allocated memory at hw_params
    (git-fixes).

  - ALSA: pcm: oss: Fix a few more UBSAN fixes (git-fixes).

  - ALSA: pcm: oss: Fix potential out-of-bounds shift
    (git-fixes).

  - ALSA: pcm: oss: Remove superfluous WARN_ON() for mulaw
    sanity check (git-fixes).

  - ALSA: timer: Limit max amount of slave instances
    (git-fixes).

  - ALSA: usb-audio: Add delay quirk for H570e USB headsets
    (git-fixes).

  - ALSA: usb-audio: Add delay quirk for all Logitech USB
    devices (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for MODX
    (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for Qu-16
    (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for Zoom
    UAC-2 (git-fixes).

  - ALSA: usb-audio: Add registration quirk for Kingston
    HyperX Cloud Alpha S (git-fixes).

  - ALSA: usb-audio: Add registration quirk for Kingston
    HyperX Cloud Flight S (git-fixes).

  - ALSA: usb-audio: Disable sample read check if firmware
    does not give back (git-fixes).

  - ALSA: usb-audio: Fix OOB access of mixer element list
    (git-fixes).

  - ALSA: usb-audio: Fix control 'access overflow' errors
    from chmap (git-fixes).

  - ALSA: usb-audio: Fix potential out-of-bounds shift
    (git-fixes).

  - ALSA: usb-audio: Fix race against the error recovery URB
    submission (git-fixes).

  - ALSA: usb-audio: US16x08: fix value count for level
    meters (git-fixes).

  - ALSA: usb-audio: add quirk for Denon DCD-1500RE
    (git-fixes).

  - ALSA: usb-audio: add quirk for Samsung USBC Headset
    (AKG) (git-fixes).

  - ALSA: usb-audio: add usb vendor id as DSD-capable for
    Khadas devices (git-fixes).

  - ASoC: arizona: Fix a wrong free in wm8997_probe
    (git-fixes).

  - ASoC: cx2072x: Fix doubly definitions of Playback and
    Capture streams (git-fixes).

  - ASoC: fsl_asrc_dma: Fix dma_chan leak when config DMA
    channel failed (git-fixes).

  - ASoC: jz4740-i2s: add missed checks for clk_get()
    (git-fixes).

  - ASoC: pcm3168a: The codec does not support S32_LE
    (git-fixes).

  - ASoC: pcm: DRAIN support reactivation (git-fixes).

  - ASoC: rt5677: Mark reg RT5677_PWR_ANLG2 as volatile
    (git-fixes).

  - ASoC: sti: fix possible sleep-in-atomic (git-fixes).

  - ASoC: wm8904: fix regcache handling (git-fixes).

  - ASoC: wm8998: Fix PM disable depth imbalance on error
    (git-fixes).

  - ASoC: wm_adsp: Do not generate kcontrols without READ
    flags (git-fixes).

  - ASoC: wm_adsp: remove 'ctl' from list on error in
    wm_adsp_create_control() (git-fixes).

  - Avoid a GCC warning about '/*' within a comment.

  - Bluetooth: Fix advertising duplicated flags (git-fixes).

  - Bluetooth: Fix NULL pointer dereference in
    hci_event_packet() (git-fixes).

  - Bluetooth: Fix slab-out-of-bounds read in
    hci_le_direct_adv_report_evt() (git-fixes).

  - Bluetooth: add a mutex lock to avoid UAF in do_enale_set
    (git-fixes).

  - Bluetooth: btusb: Fix detection of some fake CSR
    controllers with a bcdDevice val of 0x0134 (git-fixes).

  - Drop a backported uvcvideo patch that caused a
    regression (bsc#1180117) Also blacklisting the commit

  - EDAC/amd64: Fix PCI component registration
    (bsc#1112178).

  - HID: Add another Primax PIXART OEM mouse quirk
    (git-fixes).

  - HID: Fix slab-out-of-bounds read in hid_field_extract
    (bsc#1180052).

  - HID: Improve Windows Precision Touchpad detection
    (git-fixes).

  - HID: apple: Disable Fn-key key-re-mapping on clone
    keyboards (git-fixes).

  - HID: core: Correctly handle ReportSize being zero
    (git-fixes).

  - HID: core: check whether Usage Page item is after Usage
    ID items (git-fixes).

  - HID: cypress: Support Varmilo Keyboards' media hotkeys
    (git-fixes).

  - HID: hid-sensor-hub: Fix issue with devices with no
    report ID (git-fixes).

  - HID: intel-ish-hid: fix wrong error handling in
    ishtp_cl_alloc_tx_ring() (git-fixes).

  - HID: logitech-hidpp: Silence intermittent
    get_battery_capacity errors (git-fixes).

  - HSI: omap_ssi: Do not jump to free ID in
    ssi_add_controller() (git-fixes).

  - Input: ads7846 - fix integer overflow on Rt calculation
    (git-fixes).

  - Input: ads7846 - fix race that causes missing releases
    (git-fixes).

  - Input: ads7846 - fix unaligned access on 7845
    (git-fixes).

  - Input: atmel_mxt_ts - disable IRQ across suspend
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

  - Input: i8042 - add Entroware Proteus EL07R4 to nomux and
    reset lists (git-fixes).

  - Input: i8042 - allow insmod to succeed on devices
    without an i8042 controller (git-fixes).

  - Input: i8042 - fix error return code in
    i8042_setup_aux() (git-fixes).

  - Input: omap4-keypad - fix runtime PM error handling
    (git-fixes).

  - Input: synaptics - enable InterTouch for ThinkPad X1E
    1st gen (git-fixes).

  - Input: trackpoint - add new trackpoint variant IDs
    (git-fixes).

  - Input: trackpoint - enable Synaptics trackpoints
    (git-fixes).

  - Input: xpad - support Ardwiino Controllers (git-fixes).

  - KVM: x86: reinstate vendor-agnostic check on SPEC_CTRL
    cpuid bits (bsc#1112178).

  - NFC: st95hf: Fix memleak in st95hf_in_send_cmd
    (git-fixes).

  - NFS: fix nfs_path in case of a rename retry (git-fixes).

  - NFSD: Add missing NFSv2 .pc_func methods (git-fixes).

  - NFSv4.2: fix client's attribute cache management for
    copy_file_range (git-fixes).

  - NFSv4.2: support EXCHGID4_FLAG_SUPP_FENCE_OPS 4.2
    EXCHANGE_ID flag (git-fixes).

  - PCI/ASPM: Allow ASPM on links to PCIe-to-PCI/PCI-X
    Bridges (git-fixes).

  - PCI/ASPM: Disable ASPM on ASMedia ASM1083/1085
    PCIe-to-PCI bridge (git-fixes).

  - PCI: Do not disable decoding when mmio_always_on is set
    (git-fixes).

  - PCI: Fix pci_slot_release() NULL pointer dereference
    (git-fixes).

  - PM / hibernate: memory_bm_find_bit(): Tighten node
    optimisation (git-fixes).

  - PM: ACPI: Output correct message on target power state
    (git-fixes).

  - PM: hibernate: Freeze kernel threads in
    software_resume() (git-fixes).

  - PM: hibernate: remove the bogus call to get_gendisk() in
    software_resume() (git-fixes).

  - Revert 'ACPI / resources: Use AE_CTRL_TERMINATE to
    terminate resources walks' (git-fixes).

  - Revert 'ALSA: hda - Fix silent audio output and
    corrupted input on MSI X570-A PRO' (git-fixes).

  - Revert 'PM / devfreq: Modify the device name as
    devfreq(X) for sysfs' (git-fixes).

  - Revert 'device property: Keep secondary firmware node
    secondary by type' (git-fixes).

  - Revert 'platform/x86: wmi: Destroy on cleanup rather
    than unregister' (git-fixes).

  - Revert 'powerpc/pseries/hotplug-cpu: Remove double free
    in error path' (bsc#1065729).

  - Revert 'serial: amba-pl011: Make sure we initialize the
    port.lock spinlock' (git-fixes).

  - SMB3: Honor 'handletimeout' flag for multiuser mounts
    (bsc#1176558).

  - SMB3: Honor 'posix' flag for multiuser mounts
    (bsc#1176559).

  - SMB3: Honor lease disabling for multiuser mounts
    (git-fixes).

  - SUNRPC: Properly set the @subbuf parameter of
    xdr_buf_subsegment() (git-fixes).

  - SUNRPC: The RDMA back channel mustn't disappear while
    requests are outstanding (git-fixes).

  - USB: Fix: Do not skip endpoint descriptors with
    maxpacket=0 (git-fixes).

  - USB: Skip endpoints with 0 maxpacket length (git-fixes).

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

  - USB: ldusb: use unsigned size format specifiers
    (git-fixes).

  - USB: serial: ch341: add new Product ID for CH341A
    (git-fixes).

  - USB: serial: ch341: sort device-id entries (git-fixes).

  - USB: serial: digi_acceleport: clean up modem-control
    handling (git-fixes).

  - USB: serial: digi_acceleport: clean up set_termios
    (git-fixes).

  - USB: serial: digi_acceleport: fix write-wakeup deadlocks
    (git-fixes).

  - USB: serial: digi_acceleport: remove in_interrupt()
    usage.

  - USB: serial: digi_acceleport: remove redundant
    assignment to pointer priv (git-fixes).

  - USB: serial: digi_acceleport: rename tty flag variable
    (git-fixes).

  - USB: serial: digi_acceleport: use irqsave() in USB's
    complete callback (git-fixes).

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

  - ata/libata: Fix usage of page address by page_address in
    ata_scsi_mode_select_xlat function (git-fixes).

  - ath10k: Fix an error handling path (git-fixes).

  - ath10k: Release some resources in an error handling path
    (git-fixes).

  - ath10k: Remove msdu from idr when management pkt send
    fails (git-fixes).

  - ath10k: fix backtrace on coredump (git-fixes).

  - ath10k: fix get invalid tx rate for Mesh metric
    (git-fixes).

  - ath10k: fix offchannel tx failure when no
    ath10k_mac_tx_frm_has_freq (git-fixes).

  - ath6kl: fix enum-conversion warning (git-fixes).

  - ath9k_htc: Discard undersized packets (git-fixes).

  - ath9k_htc: Modify byte order for an error message
    (git-fixes).

  - ath9k_htc: Silence undersized packet warnings
    (git-fixes).

  - ath9k_htc: Use appropriate rs_datalen type (git-fixes).

  - backlight: lp855x: Ensure regulators are disabled on
    probe failure (git-fixes).

  - btmrvl: Fix firmware filename for sd8997 chipset
    (bsc#1172694).

  - btrfs: fix use-after-free on readahead extent after
    failure to create it (bsc#1179963).

  - btrfs: qgroup: do not commit transaction when we already
    hold the handle (bsc#1178634).

  - btrfs: qgroup: do not try to wait flushing if we're
    already holding a transaction (bsc#1179575).

  - btrfs: remove a BUG_ON() from merge_reloc_roots()
    (bsc#1174784).

  - bus: fsl-mc: fix error return code in
    fsl_mc_object_allocate() (git-fixes).

  - can: mcp251x: add error check when wq alloc failed
    (git-fixes).

  - can: softing: softing_netdev_open(): fix error handling
    (git-fixes).

  - cfg80211: initialize rekey_data (git-fixes).

  - cfg80211: regulatory: Fix inconsistent format argument
    (git-fixes).

  - cifs: add NULL check for ses->tcon_ipc (bsc#1178270).

  - cifs: allow syscalls to be restarted in
    __smb_send_rqst() (bsc#1176956).

  - cifs: fix check of tcon dfs in smb1 (bsc#1178270).

  - cifs: fix potential use-after-free in
    cifs_echo_request() (bsc#1139944).

  - cirrus: cs89x0: remove set but not used variable 'lp'
    (git-fixes).

  - cirrus: cs89x0: use devm_platform_ioremap_resource() to
    simplify code (git-fixes).

  - clk: at91: usb: continue if clk_hw_round_rate() return
    zero (git-fixes).

  - clk: mvebu: a3700: fix the XTAL MODE pin to MPP1_9
    (git-fixes).

  - clk: qcom: Allow constant ratio freq tables for rcg
    (git-fixes).

  - clk: qcom: msm8916: Fix the address location of
    pll->config_reg (git-fixes).

  - clk: s2mps11: Fix a resource leak in error handling
    paths in the probe function (git-fixes).

  - clk: samsung: exynos5433: Add IGNORE_UNUSED flag to
    sclk_i2s1 (git-fixes).

  - clk: sunxi-ng: Make sure divider tables have sentinel
    (git-fixes).

  - clk: tegra: Fix Tegra PMC clock out parents (git-fixes).

  - clk: tegra: Fix duplicated SE clock entry (git-fixes).

  - clk: ti: Fix memleak in ti_fapll_synth_setup
    (git-fixes).

  - clk: ti: composite: fix memory leak (git-fixes).

  - clk: ti: dra7-atl-clock: Remove ti_clk_add_alias call
    (git-fixes).

  - clocksource/drivers/asm9260: Add a check for of_clk_get
    (git-fixes).

  - coredump: fix core_pattern parse error (git-fixes).

  - cpufreq: highbank: Add missing MODULE_DEVICE_TABLE
    (git-fixes).

  - cpufreq: loongson1: Add missing MODULE_ALIAS
    (git-fixes).

  - cpufreq: scpi: Add missing MODULE_ALIAS (git-fixes).

  - cpufreq: st: Add missing MODULE_DEVICE_TABLE
    (git-fixes).

  - crypto: af_alg - avoid undefined behavior accessing
    salg_name (git-fixes).

  - crypto: omap-aes - Fix PM disable depth imbalance in
    omap_aes_probe (git-fixes).

  - crypto: qat - fix status check in
    qat_hal_put_rel_rd_xfer() (git-fixes).

  - crypto: talitos - Fix return type of current_desc_hdr()
    (git-fixes).

  - cw1200: fix missing destroy_workqueue() on error in
    cw1200_init_common (git-fixes).

  - dmaengine: xilinx_dma: check dma_async_device_register
    return value (git-fixes).

  - dmaengine: xilinx_dma: fix mixed_enum_type coverity
    warning (git-fixes).

  - docs: Fix reST markup when linking to sections
    (git-fixes).

  - drivers: base: Fix NULL pointer exception in
    __platform_driver_probe() if a driver developer is
    foolish (git-fixes).

  - drivers: soc: ti: knav_qmss_queue: Fix error return code
    in knav_queue_probe (git-fixes).

  - drm/amd/display: remove useless if/else (git-fixes).

  - drm/amdgpu: fix build_coefficients() argument
    (git-fixes).

  - drm/dp_aux_dev: check aux_dev before use in
    drm_dp_aux_dev_get_by_minor() (git-fixes).

  - drm/gma500: Fix out-of-bounds access to struct
    drm_device.vblank[] (bsc#1129770)

  - drm/gma500: fix double free of gma_connector
    (git-fixes).

  - drm/meson: dw-hdmi: Register a callback to disable the
    regulator (git-fixes).

  - drm/msm/dpu: Add newline to printks (git-fixes).

  - drm/msm/dsi_phy_10nm: implement PHY disabling
    (git-fixes).

  - drm/omap: dmm_tiler: fix return error code in
    omap_dmm_probe() (git-fixes).

  - drm/rockchip: Avoid uninitialized use of endpoint id in
    LVDS (git-fixes).

  - epoll: Keep a reference on files added to the check list
    (bsc#1180031).

  - ethernet: ucc_geth: fix use-after-free in
    ucc_geth_remove() (git-fixes).

  - ext4: correctly report 'not supported' for
    (usr,grp)jquota when !CONFIG_QUOTA (bsc#1179672).

  - ext4: fix bogus warning in ext4_update_dx_flag()
    (bsc#1179716).

  - ext4: fix error handling code in add_new_gdb
    (bsc#1179722).

  - ext4: fix invalid inode checksum (bsc#1179723).

  - ext4: fix leaking sysfs kobject after failed mount
    (bsc#1179670).

  - ext4: limit entries returned when counting fsmap records
    (bsc#1179671).

  - ext4: unlock xattr_sem properly in
    ext4_inline_data_truncate() (bsc#1179673).

  - extcon: max77693: Fix modalias string (git-fixes).

  - fbcon: Fix user font detection test at fbcon_resize().
    (bsc#1112178)

  - fbcon: Remove the superfluous break (bsc#1129770)

  - firmware: qcom: scm: Ensure 'a0' status code is treated
    as signed (git-fixes).

  - fix regression in 'epoll: Keep a reference on files
    added to the check list' (bsc#1180031, git-fixes).

  - forcedeth: use per cpu to collect xmit/recv statistics
    (git-fixes).

  - fs: Do not invalidate page buffers in
    block_write_full_page() (bsc#1179711).

  - geneve: change from tx_error to tx_dropped on missing
    metadata (git-fixes).

  - genirq/irqdomain: Add an irq_create_mapping_affinity()
    function (bsc#1065729).

  - gpio: arizona: handle pm_runtime_get_sync failure case
    (git-fixes).

  - gpio: gpio-grgpio: fix possible sleep-in-atomic-context
    bugs in grgpio_irq_map/unmap() (git-fixes).

  - gpio: max77620: Add missing dependency on
    GPIOLIB_IRQCHIP (git-fixes).

  - gpio: max77620: Fixup debounce delays (git-fixes).

  - gpio: max77620: Use correct unit for debounce times
    (git-fixes).

  - gpio: mpc8xxx: Add platform device to gpiochip->parent
    (git-fixes).

  - gpio: mvebu: fix potential user-after-free on probe
    (git-fixes).

  - gpiolib: acpi: Add honor_wakeup module-option + quirk
    mechanism (git-fixes).

  - gpiolib: acpi: Add quirk to ignore EC wakeups on HP x2
    10 BYT + AXP288 model (git-fixes).

  - gpiolib: acpi: Add quirk to ignore EC wakeups on HP x2
    10 CHT + AXP288 model (git-fixes).

  - gpiolib: acpi: Correct comment for HP x2 10 honor_wakeup
    quirk (git-fixes).

  - gpiolib: acpi: Rework honor_wakeup option into an
    ignore_wake option (git-fixes).

  - gpiolib: acpi: Turn dmi_system_id table into a generic
    quirk table (git-fixes).

  - gpiolib: fix up emulated open drain outputs (git-fixes).

  - hwmon: (aspeed-pwm-tacho) Avoid possible buffer overflow
    (git-fixes).

  - hwmon: (jc42) Fix name to have no illegal characters
    (git-fixes).

  - i2c: algo: pca: Reapply i2c bus settings after reset
    (git-fixes).

  - i2c: i801: Fix resume bug (git-fixes).

  - i2c: piix4: Detect secondary SMBus controller on AMD AM4
    chipsets (git-fixes).

  - i2c: pxa: clear all master action bits in
    i2c_pxa_stop_message() (git-fixes).

  - i2c: pxa: fix i2c_pxa_scream_blue_murder() debug output
    (git-fixes).

  - i2c: qup: Fix error return code in
    qup_i2c_bam_schedule_desc() (git-fixes).

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

  - iio: adc: max1027: Reset the device at probe time
    (git-fixes).

  - iio: adc: rockchip_saradc: fix missing
    clk_disable_unprepare() on error in
    rockchip_saradc_resume (git-fixes).

  - iio: bmp280: fix compensation of humidity (git-fixes).

  - iio: buffer: Fix demux update (git-fixes).

  - iio: dac: ad5592r: fix unbalanced mutex unlocks in
    ad5592r_read_raw() (git-fixes).

  - iio: fix center temperature of bmc150-accel-core
    (git-fixes).

  - iio: humidity: hdc100x: fix IIO_HUMIDITYRELATIVE channel
    reporting (git-fixes).

  - iio: light: bh1750: Resolve compiler warning and make
    code more readable (git-fixes).

  - iio: srf04: fix wrong limitation in distance measuring
    (git-fixes).

  - iio:imu:bmi160: Fix too large a buffer (git-fixes).

  - iio:pressure:mpl3115: Force alignment of buffer
    (git-fixes).

  - inet_ecn: Fix endianness of checksum update when setting
    ECT(1) (git-fixes).

  - ipw2x00: Fix -Wcast-function-type (git-fixes).

  - irqchip/alpine-msi: Fix freeing of interrupts on
    allocation error path (git-fixes).

  - iwlwifi: mvm: fix kernel panic in case of assert during
    CSA (git-fixes).

  - iwlwifi: mvm: fix unaligned read of rx_pkt_status
    (git-fixes).

  - iwlwifi: pcie: limit memory read spin time (git-fixes).

  - kABI fix for g2d (git-fixes).

  - kABI workaround for HD-audio generic parser (git-fixes).

  - kABI workaround for dsa/b53 changes (git-fixes).

  - kABI workaround for net/ipvlan changes (git-fixes).

  - kABI: ath10k: move a new structure member to the end
    (git-fixes).

  - kABI: genirq: add back irq_create_mapping (bsc#1065729).

  - kernel-source.spec: Fix build with rpm 4.16
    (boo#1179015).

  - kernel-(binary,source).spec.in: do not create loop
    symlinks (bsc#1179082)

  - kgdb: Fix spurious true from in_dbg_master()
    (git-fixes).

  - mac80211: Check port authorization in the
    ieee80211_tx_dequeue() case (git-fixes).

  - mac80211: allow rx of mesh eapol frames with default rx
    key (git-fixes).

  - mac80211: do not set set TDLS STA bandwidth wider than
    possible (git-fixes).

  - mac80211: fix authentication with iwlwifi/mvm
    (git-fixes).

  - mac80211: fix use of skb payload instead of header
    (git-fixes).

  - mac80211: mesh: fix mesh_pathtbl_init() error path
    (git-fixes).

  - matroxfb: avoid -Warray-bounds warning (git-fixes).

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

  - md/raid5: fix oops during stripe resizing (git-fixes).

  - media: am437x-vpfe: Setting STD to current value is not
    an error (git-fixes).

  - media: cec-funcs.h: add status_req checks (git-fixes).

  - media: cx88: Fix some error handling path in
    'cx8800_initdev()' (git-fixes).

  - media: gp8psk: initialize stats at power control logic
    (git-fixes).

  - media: gspca: Fix memory leak in probe (git-fixes).

  - media: i2c: mt9v032: fix enum mbus codes and frame sizes
    (git-fixes).

  - media: i2c: ov2659: Fix missing 720p register config
    (git-fixes).

  - media: i2c: ov2659: fix s_stream return value
    (git-fixes).

  - media: msi2500: assign SPI bus number dynamically
    (git-fixes).

  - media: mtk-mdp: Fix a refcounting bug on error in init
    (git-fixes).

  - media: mtk-vcodec: add missing put_device() call in
    mtk_vcodec_release_dec_pm() (git-fixes).

  - media: platform: add missing put_device() call in
    mtk_jpeg_probe() and mtk_jpeg_remove() (git-patches).

  - media: pvrusb2: Fix oops on tear-down when radio support
    is not present (git-fixes).

  - media: s5p-g2d: Fix a memory leak in an error handling
    path in 'g2d_probe()' (git-fixes).

  - media: saa7146: fix array overflow in vidioc_s_audio()
    (git-fixes).

  - media: si470x-i2c: add missed operations in remove
    (git-fixes).

  - media: siano: fix memory leak of debugfs members in
    smsdvb_hotplug (git-fixes).

  - media: solo6x10: fix missing snd_card_free in error
    handling case (git-fixes).

  - media: sti: bdisp: fix a possible
    sleep-in-atomic-context bug in bdisp_device_run()
    (git-fixes).

  - media: sunxi-cir: ensure IR is handled when it is
    continuous (git-fixes).

  - media: ti-vpe: vpe: Make sure YUYV is set as default
    format (git-fixes).

  - media: ti-vpe: vpe: ensure buffers are cleaned up
    properly in abort cases (git-fixes).

  - media: ti-vpe: vpe: fix a v4l2-compliance failure about
    frame sequence number (git-fixes).

  - media: ti-vpe: vpe: fix a v4l2-compliance failure about
    invalid sizeimage (git-fixes).

  - media: ti-vpe: vpe: fix a v4l2-compliance failure
    causing a kernel panic (git-fixes).

  - media: ti-vpe: vpe: fix a v4l2-compliance warning about
    invalid pixel format (git-fixes).

  - media: uvcvideo: Set media controller entity functions
    (git-fixes).

  - media: uvcvideo: Silence shift-out-of-bounds warning
    (git-fixes).

  - media: v4l2-async: Fix trivial documentation typo
    (git-fixes).

  - media: v4l2-core: fix touch support in v4l_g_fmt
    (git-fixes).

  - media: v4l2-device.h: Explicitly compare grp(id,mask) to
    zero in v4l2_device macros (git-fixes).

  - mei: bus: do not clean driver pointer (git-fixes).

  - mei: protect mei_cl_mtu from null dereference
    (git-fixes).

  - memstick: fix a double-free bug in memstick_check
    (git-fixes).

  - memstick: r592: Fix error return in r592_probe()
    (git-fixes).

  - mfd: rt5033: Fix errorneous defines (git-fixes).

  - mfd: wm8994: Fix driver operation if loaded as modules
    (git-fixes).

  - misc: vmw_vmci: fix kernel info-leak by initializing
    dbells in vmci_ctx_get_chkpt_doorbells() (git-fixes).

  - mm,memory_failure: always pin the page in
    madvise_inject_error (bsc#1180258).

  - mm/userfaultfd: do not access vma->vm_mm after calling
    handle_userfault() (bsc#1179204).

  - mm: do not wake kswapd prematurely when watermark
    boosting is disabled (git fixes (mm/vmscan)).

  - mwifiex: fix mwifiex_shutdown_sw() causing sw reset
    failure (git-fixes).

  - net/smc: fix valid DMBE buffer sizes (git-fixes).

  - net/x25: prevent a couple of overflows (bsc#1178590).

  - net: aquantia: Fix aq_vec_isr_legacy() return value
    (git-fixes).

  - net: aquantia: fix LRO with FCS error (git-fixes).

  - net: bcmgenet: reapply manual settings to the PHY
    (git-fixes).

  - net: broadcom/bcmsysport: Fix signedness in
    bcm_sysport_probe() (git-fixes).

  - net: dsa: b53: Always use dev->vlan_enabled in
    b53_configure_vlan() (git-fixes).

  - net: dsa: b53: Ensure the default VID is untagged
    (git-fixes).

  - net: dsa: b53: Fix default VLAN ID (git-fixes).

  - net: dsa: b53: Properly account for VLAN filtering
    (git-fixes).

  - net: dsa: bcm_sf2: Do not assume DSA master supports WoL
    (git-fixes).

  - net: dsa: bcm_sf2: potential array overflow in
    bcm_sf2_sw_suspend() (git-fixes).

  - net: dsa: qca8k: remove leftover phy accessors
    (git-fixes).

  - net: ethernet: stmmac: Fix signedness bug in
    ipq806x_gmac_of_parse() (git-fixes).

  - net: ethernet: ti: cpsw: clear all entries when delete
    vid (git-fixes).

  - net: ethernet: ti: cpsw: fix runtime_pm while add/kill
    vlan (git-fixes).

  - net: hisilicon: Fix signedness bug in
    hix5hd2_dev_probe() (git-fixes).

  - net: macb: add missing barriers when reading descriptors
    (git-fixes).

  - net: macb: fix dropped RX frames due to a race
    (git-fixes).

  - net: macb: fix error format in dev_err() (git-fixes).

  - net: macb: fix random memory corruption on RX with
    64-bit DMA (git-fixes). - blacklist.conf :

  - net: pasemi: fix an use-after-free in
    pasemi_mac_phy_init() (git-fixes).

  - net: phy: Avoid multiple suspends (git-fixes).

  - net: phy: micrel: Discern KSZ8051 and KSZ8795 PHYs
    (git-fixes).

  - net: phy: micrel: make sure the factory test bit is
    cleared (git-fixes).

  - net: qca_spi: Move reset_count to struct qcaspi
    (git-fixes).

  - net: seeq: Fix the function used to release some memory
    in an error handling path (git-fixes).

  - net: sh_eth: fix a missing check of of_get_phy_mode
    (git-fixes).

  - net: sonic: replace dev_kfree_skb in sonic_send_packet
    (git-fixes).

  - net: sonic: return NETDEV_TX_OK if failed to map buffer
    (git-fixes).

  - net: stmmac: Fix reception of Broadcom switches tags
    (git-fixes).

  - net: stmmac: dwmac-meson8b: Fix signedness bug in probe
    (git-fixes).

  - net: stmmac: fix csr_clk can't be zero issue
    (git-fixes).

  - net: stmmac: fix length of PTP clock's name string
    (git-fixes).

  - net: stmmac: gmac4+: Not all Unicast addresses may be
    available (git-fixes).

  - net: usb: sr9800: fix uninitialized local variable
    (git-fixes).

  - net:ethernet:aquantia: Extra spinlocks removed
    (git-fixes).

  - nfc: s3fwrn5: Release the nfc firmware (git-fixes).

  - nfc: s3fwrn5: add missing release on skb in
    s3fwrn5_recv_frame (git-fixes).

  - ocfs2: fix unbalanced locking (bsc#1180506).

  - ocfs2: initialize ip_next_orphan (bsc#1179724).

  - orinoco: Move context allocation after processing the
    skb (git-fixes).

  - pNFS/flexfiles: Fix list corruption if the mirror count
    changes (git-fixes).

  - parport: load lowlevel driver if ports not found
    (git-fixes).

  - phy: Revert toggling reset changes (git-fixes).

  - pinctrl: amd: fix __iomem annotation in
    amd_gpio_irq_handler() (git-fixes).

  - pinctrl: amd: fix npins for uart0 in kerncz_groups
    (git-fixes).

  - pinctrl: amd: remove debounce filter setting in IRQ type
    setting (git-fixes).

  - pinctrl: baytrail: Avoid clearing debounce value when
    turning it off (git-fixes).

  - pinctrl: falcon: add missing put_device() call in
    pinctrl_falcon_probe() (git-fixes).

  - pinctrl: merrifield: Set default bias in case no
    particular value given (git-fixes).

  - pinctrl: sh-pfc: sh7734: Fix duplicate TCLK1_B
    (git-fixes).

  - platform/x86: acer-wmi: add automatic keyboard
    background light toggle key as KEY_LIGHTS_TOGGLE
    (git-fixes).

  - platform/x86: dell-smbios-base: Fix error return code in
    dell_smbios_init (git-fixes).

  - platform/x86: mlx-platform: Fix item counter assignment
    for MSN2700, MSN24xx systems (git-fixes).

  - platform/x86: mlx-platform: Remove PSU EEPROM from
    MSN274x platform configuration (git-fixes).

  - platform/x86: mlx-platform: Remove PSU EEPROM from
    default platform configuration (git-fixes).

  - platform/x86: mlx-platform: remove an unused variable
    (git-fixes).

  - power: supply: bq24190_charger: fix reference leak
    (git-fixes).

  - power: supply: bq27xxx_battery: Silence deferred-probe
    error (git-fixes).

  - powerpc/64: Set up a kernel stack for secondaries before
    cpu_restore() (bsc#1065729).

  - powerpc/64s/pseries: Fix hash tlbiel_all_isa300 for
    guest kernels (bsc#1179888 ltc#190253).

  - powerpc/64s: Fix hash ISA v3.0 TLBIEL instruction
    generation (bsc#1055117 ltc#159753 git-fixes bsc#1179888
    ltc#190253).

  - powerpc/pci: Fix broken INTx configuration via OF
    (bsc#1172145 ltc#184630).

  - powerpc/pci: Remove LSI mappings on device teardown
    (bsc#1172145 ltc#184630).

  - powerpc/pci: Remove legacy debug code (bsc#1172145
    ltc#184630 git-fixes).

  - powerpc/pci: Use of_irq_parse_and_map_pci() helper
    (bsc#1172145 ltc#184630).

  - powerpc/perf: Add generic compat mode pmu driver
    (bsc#1178900 ltc#189284).

  - powerpc/perf: Fix crash with is_sier_available when pmu
    is not set (bsc#1179578 ltc#189313).

  - powerpc/perf: Fix crashes with generic_compat_pmu & BHRB
    (bsc#1178900 ltc#189284 git-fixes).

  - powerpc/perf: init pmu from core-book3s (bsc#1178900
    ltc#189284).

  - powerpc/pseries/hibernation: remove redundant cacheinfo
    update (bsc#1138374 ltc#178199 git-fixes).

  - powerpc/pseries: Pass MSI affinity to
    irq_create_mapping() (bsc#1065729).

  - powerpc/smp: Add __init to init_big_cores() (bsc#1109695
    ltc#171067 git-fixes).

  - powerpc/xmon: Change printk() to pr_cont()
    (bsc#1065729).

  - powerpc: Convert to using %pOF instead of full_name
    (bsc#1172145 ltc#184630).

  - powerpc: Fix incorrect stw(, ux, u, x) instructions in
    __set_pte_at (bsc#1065729).

  - ppp: remove the PPPIOCDETACH ioctl (git-fixes).

  - pwm: lp3943: Dynamically allocate PWM chip base
    (git-fixes).

  - quota: clear padding in v2r1_mem2diskdqb()
    (bsc#1179714).

  - radeon: insert 10ms sleep in dce5_crtc_load_lut
    (git-fixes).

  - ravb: Fix use-after-free ravb_tstamp_skb (git-fixes).

  - regmap: Remove duplicate `type` field from regmap
    `regcache_sync` trace event (git-fixes).

  - regmap: debugfs: check count when read regmap file
    (git-fixes).

  - regmap: dev_get_regmap_match(): fix string comparison
    (git-fixes).

  - regulator: max8907: Fix the usage of uninitialized
    variable in max8907_regulator_probe() (git-fixes).

  - regulator: pfuze100-regulator: Variable 'val' in
    pfuze100_regulator_probe() could be uninitialized
    (git-fixes).

  - regulator: ti-abb: Fix timeout in
    ti_abb_wait_txdone/ti_abb_clear_all_txdone (git-fixes).

  - reiserfs: Fix oops during mount (bsc#1179715).

  - reiserfs: Initialize inode keys properly (bsc#1179713).

  - remoteproc: Fix wrong rvring index computation
    (git-fixes).

  - rfkill: Fix incorrect check to avoid NULL pointer
    dereference (git-fixes).

  - rpm/kernel-binary.spec.in: avoid using barewords
    (bsc#1179014) 

  - rpm/kernel-binary.spec.in: avoid using more barewords
    (bsc#1179014) 

  - rpm/kernel-binary.spec.in: use grep -E instead of egrep
    (bsc#1179045) 

  - rpm/kernel-obs-build.spec.in: Add -q option to modprobe
    calls (bsc#1178401)

  - rpm/kernel-(source,binary).spec: do not include ghost
    symlinks (boo#1179082).

  - rtc: 88pm860x: fix possible race condition (git-fixes).

  - rtc: hym8563: enable wakeup when applicable (git-fixes).

  - rtl8xxxu: fix RTL8723BU connection failure issue after
    warm reboot (git-fixes).

  - rtlwifi: fix memory leak in rtl92c_set_fw_rsvdpagepkt()
    (git-fixes).

  - s390/bpf: Fix multiple tail calls (git-fixes).

  - s390/cpuinfo: show processor physical address
    (git-fixes).

  - s390/cpum_sf.c: fix file permission for cpum_sfb_size
    (git-fixes).

  - s390/dasd: fix hanging device offline processing
    (bsc#1144912).

  - s390/dasd: fix NULL pointer dereference for ERP requests
    (git-fixes).

  - s390/pci: fix CPU address in MSI for directed IRQ
    (git-fixes).

  - s390/qeth: fix af_iucv notification race (git-fixes).

  - s390/qeth: fix tear down of async TX buffers
    (git-fixes).

  - s390/qeth: make af_iucv TX notification call more robust
    (git-fixes).

  - s390/stp: add locking to sysfs functions (git-fixes).

  - s390/zcrypt: Fix ZCRYPT_PERDEV_REQCNT ioctl (git-fixes).

  - scripts/lib/SUSE/MyBS.pm: properly close prjconf Macros:
    section

  - scsi: Remove unneeded break statements (bsc#1164780).

  - scsi: core: Fix VPD LUN ID designator priorities
    (bsc#1178049, git-fixes).

  - scsi: lpfc: Add FDMI Vendor MIB support (bsc#1164780).

  - scsi: lpfc: Convert SCSI I/O completions to SLI-3 and
    SLI-4 handlers (bsc#1164780).

  - scsi: lpfc: Convert SCSI path to use common I/O
    submission path (bsc#1164780).

  - scsi: lpfc: Convert abort handling to SLI-3 and SLI-4
    handlers (bsc#1164780).

  - scsi: lpfc: Correct null ndlp reference on routine exit
    (bsc#1164780).

  - scsi: lpfc: Drop nodelist reference on error in
    lpfc_gen_req() (bsc#1164780).

  - scsi: lpfc: Enable common send_io interface for SCSI and
    NVMe (bsc#1164780).

  - scsi: lpfc: Enable common wqe_template support for both
    SCSI and NVMe (bsc#1164780).

  - scsi: lpfc: Enlarge max_sectors in scsi host templates
    (bsc#1164780).

  - scsi: lpfc: Extend the RDF FPIN Registration descriptor
    for additional events (bsc#1164780).

  - scsi: lpfc: Fix FLOGI/PLOGI receive race condition in
    pt2pt discovery (bsc#1164780).

  - scsi: lpfc: Fix NPIV Fabric Node reference counting
    (bsc#1164780).

  - scsi: lpfc: Fix NPIV discovery and Fabric Node detection
    (bsc#1164780).

  - scsi: lpfc: Fix duplicate wq_create_version check
    (bsc#1164780).

  - scsi: lpfc: Fix fall-through warnings for Clang
    (bsc#1164780).

  - scsi: lpfc: Fix invalid sleeping context in
    lpfc_sli4_nvmet_alloc() (bsc#1164780).

  - scsi: lpfc: Fix memory leak on lcb_context
    (bsc#1164780).

  - scsi: lpfc: Fix missing prototype for
    lpfc_nvmet_prep_abort_wqe() (bsc#1164780).

  - scsi: lpfc: Fix missing prototype warning for
    lpfc_fdmi_vendor_attr_mi() (bsc#1164780).

  - scsi: lpfc: Fix pointer defereference before it is null
    checked issue (bsc#1164780).

  - scsi: lpfc: Fix refcounting around SCSI and NVMe
    transport APIs (bsc#1164780).

  - scsi: lpfc: Fix removal of SCSI transport device get and
    put on dev structure (bsc#1164780).

  - scsi: lpfc: Fix scheduling call while in softirq context
    in lpfc_unreg_rpi (bsc#1164780).

  - scsi: lpfc: Fix set but not used warnings from Rework
    remote port lock handling (bsc#1164780).

  - scsi: lpfc: Fix set but unused variables in
    lpfc_dev_loss_tmo_handler() (bsc#1164780).

  - scsi: lpfc: Fix spelling mistake 'Cant' -> 'Can't'
    (bsc#1164780).

  - scsi: lpfc: Fix variable 'vport' set but not used in
    lpfc_sli4_abts_err_handler() (bsc#1164780).

  - scsi: lpfc: Refactor WQE structure definitions for
    common use (bsc#1164780).

  - scsi: lpfc: Reject CT request for MIB commands
    (bsc#1164780).

  - scsi: lpfc: Remove dead code on second !ndlp check
    (bsc#1164780).

  - scsi: lpfc: Remove ndlp when a PLOGI/ADISC/PRLI/REG_RPI
    ultimately fails (bsc#1164780).

  - scsi: lpfc: Remove set but not used 'qp' (bsc#1164780).

  - scsi: lpfc: Remove unneeded variable 'status' in
    lpfc_fcp_cpu_map_store() (bsc#1164780).

  - scsi: lpfc: Removed unused macros in lpfc_attr.c
    (bsc#1164780).

  - scsi: lpfc: Rework locations of ndlp reference taking
    (bsc#1164780).

  - scsi: lpfc: Rework remote port lock handling
    (bsc#1164780).

  - scsi: lpfc: Rework remote port ref counting and node
    freeing (bsc#1164780).

  - scsi: lpfc: Unsolicited ELS leaves node in incorrect
    state while dropping it (bsc#1164780).

  - scsi: lpfc: Update changed file copyrights for 2020
    (bsc#1164780).

  - scsi: lpfc: Update lpfc version to 12.8.0.4
    (bsc#1164780).

  - scsi: lpfc: Update lpfc version to 12.8.0.5
    (bsc#1164780).

  - scsi: lpfc: Update lpfc version to 12.8.0.6
    (bsc#1164780).

  - scsi: lpfc: Use generic power management (bsc#1164780).

  - scsi: lpfc: lpfc_attr: Demote kernel-doc format for
    redefined functions (bsc#1164780).

  - scsi: lpfc: lpfc_attr: Fix-up a bunch of kernel-doc
    misdemeanours (bsc#1164780).

  - scsi: lpfc: lpfc_debugfs: Fix a couple of function
    documentation issues (bsc#1164780).

  - scsi: lpfc: lpfc_scsi: Fix a whole host of kernel-doc
    issues (bsc#1164780).

  - scsi: qla2xxx: Change post del message from debug level
    to log level (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Convert to DEFINE_SHOW_ATTRIBUTE
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Do not check for fw_started while posting
    NVMe command (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Do not consume srb greedily (bsc#1172538
    bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Drop TARGET_SCF_LOOKUP_LUN_FROM_TAG
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix FW initialization error on big endian
    machines (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix N2N and NVMe connect retry failure
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix compilation issue in PPC systems
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix crash during driver load on big
    endian machines (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix device loss on 4G and older HBAs
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix flash update in 28XX adapters on big
    endian machines (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix return of uninitialized value in rval
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Fix the call trace for flush workqueue
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Handle aborts correctly for port
    undergoing deletion (bsc#1172538 bsc#1179142
    bsc#1179810).

  - scsi: qla2xxx: Handle incorrect entry_type entries
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: If fcport is undergoing deletion complete
    I/O with retry (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Initialize variable in qla8044_poll_reg()
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Limit interrupt vectors to number of CPUs
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Move sess cmd list/lock to driver
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Remove in_interrupt() from
    qla82xx-specific code (bsc#1172538 bsc#1179142
    bsc#1179810).

  - scsi: qla2xxx: Remove in_interrupt() from
    qla83xx-specific code (bsc#1172538 bsc#1179142
    bsc#1179810).

  - scsi: qla2xxx: Remove trailing semicolon in macro
    definition (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Return EBUSY on fcport deletion
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Tear down session if FW say it is down
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Update version to 10.02.00.104-k
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: Use constant when it is known
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: qla2xxx: remove incorrect sparse #ifdef
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - scsi: storvsc: Fix error return in storvsc_probe()
    (git-fixes).

  - scsi: target: tcm_qla2xxx: Remove BUG_ON(in_interrupt())
    (bsc#1172538 bsc#1179142 bsc#1179810).

  - serial: 8250_omap: Avoid FIFO corruption caused by MDR1
    access (git-fixes).

  - serial: 8250_pci: Add Realtek 816a and 816b (git-fixes).

  - serial: amba-pl011: Make sure we initialize the
    port.lock spinlock (git-fixes).

  - serial: ar933x_uart: set UART_CS_(RX,TX)_READY_ORIDE
    (git-fixes).

  - serial: txx9: add missing platform_driver_unregister()
    on error in serial_txx9_init (git-fixes).

  - serial_core: Check for port state when tty is in error
    state (git-fixes).

  - soc/tegra: fuse: Fix index bug in get_process_id
    (git-fixes).

  - soc: imx: gpc: fix power up sequencing (git-fixes).

  - soc: mediatek: Check if power domains can be powered on
    at boot time (git-fixes).

  - soc: qcom: smp2p: Safely acquire spinlock without IRQs
    (git-fixes).

  - soc: ti: Fix reference imbalance in knav_dma_probe
    (git-fixes).

  - soc: ti: knav_qmss: fix reference leak in
    knav_queue_probe (git-fixes).

  - spi: Add call to spi_slave_abort() function when spidev
    driver is released (git-fixes).

  - spi: Fix memory leak on splited transfers (git-fixes).

  - spi: bcm63xx-hsspi: fix missing clk_disable_unprepare()
    on error in bcm63xx_hsspi_resume (git-fixes).

  - spi: davinci: Fix use-after-free on unbind (git-fixes).

  - spi: dw: Enable interrupts in accordance with DMA xfer
    mode (git-fixes).

  - spi: dw: Fix Rx-only DMA transfers (git-fixes).

  - spi: dw: Return any value retrieved from the
    dma_transfer callback (git-fixes).

  - spi: img-spfi: fix potential double release (git-fixes).

  - spi: img-spfi: fix reference leak in img_spfi_resume
    (git-fixes).

  - spi: pic32: Do not leak DMA channels in probe error path
    (git-fixes).

  - spi: pxa2xx: Add missed security checks (git-fixes).

  - spi: spi-cavium-thunderx: Add missing
    pci_release_regions() (git-fixes).

  - spi: spi-loopback-test: Fix out-of-bounds read
    (git-fixes).

  - spi: spi-mem: Fix passing zero to 'PTR_ERR' warning
    (git-fixes).

  - spi: spi-mem: fix reference leak in spi_mem_access_start
    (git-fixes).

  - spi: spi-ti-qspi: fix reference leak in ti_qspi_setup
    (git-fixes).

  - spi: spidev: fix a potential use-after-free in
    spidev_release() (git-fixes).

  - spi: st-ssc4: Fix unbalanced pm_runtime_disable() in
    probe error path (git-fixes).

  - spi: st-ssc4: add missed pm_runtime_disable (git-fixes).

  - spi: tegra114: fix reference leak in tegra spi ops
    (git-fixes).

  - spi: tegra20-sflash: fix reference leak in
    tegra_sflash_resume (git-fixes).

  - spi: tegra20-slink: add missed clk_unprepare
    (git-fixes).

  - spi: tegra20-slink: fix reference leak in slink ops of
    tegra20 (git-fixes).

  - splice: only read in as much information as there is
    pipe buffer space (bsc#1179520).

  - staging: comedi: check validity of wMaxPacketSize of usb
    endpoints found (git-fixes).

  - staging: comedi: gsc_hpdi: check dma_alloc_coherent()
    return value (git-fixes).

  - staging: comedi: mf6x4: Fix AI end-of-conversion
    detection (git-fixes).

  - staging: olpc_dcon: Do not call
    platform_device_unregister() in dcon_probe()
    (git-fixes).

  - staging: olpc_dcon: add a missing dependency
    (git-fixes).

  - staging: rtl8188eu: Add device code for TP-Link
    TL-WN727N v5.21 (git-fixes).

  - staging: rtl8188eu: Add device id for MERCUSYS MW150US
    v2 (git-fixes).

  - staging: rtl8188eu: fix possible null dereference
    (git-fixes).

  - staging: rtl8192u: fix multiple memory leaks on error
    path (git-fixes).

  - staging: vt6656: set usb_set_intfdata on driver fail
    (git-fixes).

  - staging: wlan-ng: fix out of bounds read in
    prism2sta_probe_usb() (git-fixes).

  - staging: wlan-ng: properly check endpoint types
    (git-fixes).

  - sunrpc: fixed rollback in rpc_gssd_dummy_populate()
    (git-fixes).

  - thunderbolt: Use 32-bit writes when writing ring
    producer/consumer (git-fixes).

  - timer: Fix wheel index calculation on last level (git
    fixes)

  - timer: Prevent base->clk from moving backward
    (git-fixes)

  - tty: Fix ->pgrp locking in tiocspgrp() (git-fixes).

  - tty: always relink the port (git-fixes).

  - tty: link tty and port before configuring it as console
    (git-fixes).

  - tty: synclink_gt: Adjust indentation in several
    functions (git-fixes).

  - tty: synclinkmp: Adjust indentation in several functions
    (git-fixes).

  - tty:serial:mvebu-uart:fix a wrong return (git-fixes).

  - uapi/if_ether.h: move __UAPI_DEF_ETHHDR libc define
    (git-fixes).

  - uapi/if_ether.h: prevent redefinition of struct ethhdr
    (git-fixes).

  - usb: chipidea: ci_hdrc_imx: Pass
    DISABLE_DEVICE_STREAMING flag to imx6ul (git-fixes).

  - usb: chipidea: ci_hdrc_imx: add missing put_device()
    call in usbmisc_get_init_data() (git-fixes).

  - usb: dwc2: Fix IN FIFO allocation (git-fixes).

  - usb: dwc3: remove the call trace of USBx_GFLADJ
    (git-fixes).

  - usb: dwc3: ulpi: Use VStsDone to detect PHY regs access
    completion (git-fixes).

  - usb: ehci-omap: Fix PM disable depth umbalance in
    ehci_hcd_omap_probe (git-fixes).

  - usb: fsl: Check memory resource before releasing it
    (git-fixes).

  - usb: gadget: composite: Fix possible double free memory
    bug (git-fixes).

  - usb: gadget: configfs: Fix missing spin_lock_init()
    (git-fixes).

  - usb: gadget: configfs: Preserve function ordering after
    bind failure (git-fixes).

  - usb: gadget: configfs: fix concurrent issue between
    composite APIs (git-fixes).

  - usb: gadget: f_fs: Use local copy of descriptors for
    userspace copy (git-fixes).

  - usb: gadget: f_uac2: reset wMaxPacketSize (git-fixes).

  - usb: gadget: ffs: ffs_aio_cancel(): Save/restore IRQ
    flags (git-fixes).

  - usb: gadget: fix wrong endpoint desc (git-fixes).

  - usb: gadget: goku_udc: fix potential crashes in probe
    (git-fixes).

  - usb: gadget: net2280: fix memory leak on probe error
    handling paths (git-fixes).

  - usb: gadget: select CONFIG_CRC32 (git-fixes).

  - usb: gadget: serial: fix Tx stall after buffer overflow
    (git-fixes).

  - usb: gadget: udc: fix possible sleep-in-atomic-context
    bugs in gr_probe() (git-fixes).

  - usb: gadget: udc: gr_udc: fix memleak on error handling
    path in gr_ep_init() (git-fixes).

  - usb: hso: Fix debug compile warning on sparc32
    (git-fixes).

  - usb: musb: omap2430: Get rid of musb .set_vbus for
    omap2430 glue (git-fixes).

  - usb: oxu210hp-hcd: Fix memory leak in oxu_create
    (git-fixes).

  - usb: usbfs: Suppress problematic bind and unbind uevents
    (git-fixes).

  - usblp: poison URBs upon disconnect (git-fixes).

  - usbnet: ipheth: fix connectivity with iOS 14
    (git-fixes).

  - video: fbdev: neofb: fix memory leak in
    neo_scan_monitor() (git-fixes).

  - vt: Reject zero-sized screen buffer size (git-fixes).

  - vt: do not hardcode the mem allocation upper bound
    (git-fixes).

  - wan: ds26522: select CONFIG_BITREVERSE (git-fixes).

  - watchdog: coh901327: add COMMON_CLK dependency
    (git-fixes).

  - watchdog: da9062: No need to ping manually before
    setting timeout (git-fixes).

  - watchdog: da9062: do not ping the hw during stop()
    (git-fixes).

  - watchdog: qcom: Avoid context switch in restart handler
    (git-fixes).

  - watchdog: sirfsoc: Add missing dependency on HAS_IOMEM
    (git-fixes).

  - wil6210: select CONFIG_CRC32 (git-fixes).

  - wimax: fix duplicate initializer warning (git-fixes).

  - wireless: Use linux/stddef.h instead of stddef.h
    (git-fixes).

  - wireless: Use offsetof instead of custom macro
    (git-fixes).

  - x86/apic: Fix integer overflow on 10 bit left shift of
    cpu_khz (bsc#1112178).

  - x86/i8259: Use printk_deferred() to prevent deadlock
    (bsc#1112178).

  - x86/insn-eval: Use new for_each_insn_prefix() macro to
    loop over prefixes bytes (bsc#1112178).

  - x86/mm/ident_map: Check for errors from ident_pud_init()
    (bsc#1112178).

  - x86/mm/mem_encrypt: Fix definition of PMD_FLAGS_DEC_WP
    (bsc#1112178).

  - x86/mm/numa: Remove uninitialized_var() usage
    (bsc#1112178).

  - x86/mm: Fix leak of pmd ptlock (bsc#1112178).

  - x86/mtrr: Correct the range check before performing MTRR
    type lookups (bsc#1112178).

  - x86/resctrl: Add necessary kernfs_put() calls to prevent
    refcount leak (bsc#1112178).

  - x86/resctrl: Do not move a task to the same resource
    group (bsc#1112178).

  - x86/resctrl: Fix incorrect local bandwidth when mba_sc
    is enabled (bsc#1112178).

  - x86/resctrl: Remove superfluous kernfs_get() calls to
    prevent refcount leak (bsc#1112178).

  - x86/resctrl: Remove unused struct mbm_state::chunks_bw
    (bsc#1112178).

  - x86/resctrl: Use an IPI instead of task_work_add() to
    update PQR_ASSOC MSR (bsc#1112178).

  - x86/speculation: Fix prctl() when
    spectre_v2_user=(seccomp,prctl),ibpb (bsc#1112178).

  - x86/tracing: Introduce a static key for exception
    tracing (bsc#1179895).

  - x86/traps: Simplify pagefault tracing logic
    (bsc#1179895).

  - x86/uprobes: Do not use prefixes.nbytes when looping
    over prefixes.bytes (bsc#1112178).

  - xhci: Give USB2 ports time to enter U3 in bus suspend
    (git-fixes).

  - xprtrdma: fix incorrect header size calculations
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180676");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.91.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.91.1") ) flag++;

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
