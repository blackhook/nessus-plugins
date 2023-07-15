#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2392.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130338);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-16232", "CVE-2019-16234", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2392)");
  script_summary(english:"Check for the openSUSE-2019-2392 patch");

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

  - CVE-2019-17666: rtl_p2p_noa_ie in
    drivers/net/wireless/realtek/rtlwifi/ps.c lacked a
    certain upper-bound check, leading to a buffer overflow
    (bnc#1154372).

  - CVE-2019-16232:
    drivers/net/wireless/marvell/libertas/if_sdio.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150465).

  - CVE-2019-16234:
    drivers/net/wireless/intel/iwlwifi/pcie/trans.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150452).

  - CVE-2019-17133: cfg80211_mgd_wext_giwessid in
    net/wireless/wext-sme.c did not reject a long SSID IE,
    leading to a Buffer Overflow (bnc#1153158).

  - CVE-2019-17056: llcp_sock_create in net/nfc/llcp_sock.c
    in the AF_NFC network module did not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka CID-3a359798b176 (bnc#1152788).

The following non-security bugs were fixed :

  - 9p: avoid attaching writeback_fid on mmap with type
    PRIVATE (bsc#1051510).

  - ACPI / CPPC: do not require the _PSD method
    (bsc#1051510).

  - ACPI: CPPC: Set pcc_data[pcc_ss_id] to NULL in
    acpi_cppc_processor_exit() (bsc#1051510).

  - ACPI / processor: do not print errors for processorIDs
    == 0xff (bsc#1051510).

  - act_mirred: Fix mirred_init_module error handling
    (bsc#1051510).

  - Add kernel module compression support (bsc#1135854) For
    enabling the kernel module compress, add the item
    COMPRESS_MODULES='xz' in config.sh, then mkspec will
    pass it to the spec file.

  - ALSA: hda - Add laptop imic fixup for ASUS M9V laptop
    (bsc#1051510).

  - ALSA: hda: Add support of Zhaoxin controller
    (bsc#1051510).

  - ALSA: hda - Apply AMD controller workaround for Raven
    platform (bsc#1051510).

  - ALSA: hda - Define a fallback_pin_fixup_tbl for alc269
    family (bsc#1051510).

  - ALSA: hda - Drop unsol event handler for Intel HDMI
    codecs (bsc#1051510).

  - ALSA: hda - Expand pin_match function to match upcoming
    new tbls (bsc#1051510).

  - ALSA: hda: Flush interrupts on disabling (bsc#1051510).

  - ALSA: hda/hdmi: remove redundant assignment to variable
    pcm_idx (bsc#1051510).

  - ALSA: hda - Inform too slow responses (bsc#1051510).

  - ALSA: hda/realtek - Blacklist PC beep for Lenovo
    ThinkCentre M73/93 (bsc#1051510).

  - ALSA: hda/realtek - Check beep whitelist before
    assigning in all codecs (bsc#1051510).

  - ALSA: hda/realtek - Fix alienware headset mic
    (bsc#1051510).

  - ALSA: hda/realtek: Reduce the Headphone static noise on
    XPS 9350/9360 (bsc#1051510).

  - ALSA: hda: Set fifo_size for both playback and capture
    streams (bsc#1051510).

  - ALSA: hda - Show the fatal CORB/RIRB error more clearly
    (bsc#1051510).

  - ALSA: hda/sigmatel - remove unused variable
    'stac9200_core_init' (bsc#1051510).

  - ALSA: i2c: ak4xxx-adda: Fix a possible NULL pointer
    dereference in build_adc_controls() (bsc#1051510).

  - ALSA: line6: sizeof (byte) is always 1, use that fact
    (bsc#1051510).

  - ALSA: usb-audio: Add Pioneer DDJ-SX3 PCM quirck
    (bsc#1051510).

  - ALSA: usb-audio: Disable quirks for BOSS Katana
    amplifiers (bsc#1051510).

  - ALSA: usb-audio: Skip bSynchAddress endpoint check if it
    is invalid (bsc#1051510).

  - appletalk: enforce CAP_NET_RAW for raw sockets
    (bsc#1051510).

  - ASoC: Define a set of DAPM pre/post-up events
    (bsc#1051510).

  - ASoC: dmaengine: Make the pcm->name equal to pcm->id if
    the name is not set (bsc#1051510).

  - ASoC: Intel: Fix use of potentially uninitialized
    variable (bsc#1051510).

  - ASoC: Intel: NHLT: Fix debug print format (bsc#1051510).

  - ASoC: sgtl5000: Fix charge pump source assignment
    (bsc#1051510).

  - auxdisplay: panel: need to delete scan_timer when
    misc_register fails in panel_attach (bsc#1051510).

  - ax25: enforce CAP_NET_RAW for raw sockets (bsc#1051510).

  - blacklist 'signal: Correct namespace fixups of si_pid
    and si_uid' (bsc#1142667)

  - blk-wbt: abstract out end IO completion handler
    (bsc#1135873).

  - blk-wbt: fix has-sleeper queueing check (bsc#1135873).

  - blk-wbt: improve waking of tasks (bsc#1135873).

  - blk-wbt: move disable check into get_limit()
    (bsc#1135873).

  - blk-wbt: use wq_has_sleeper() for wq active check
    (bsc#1135873).

  - block: add io timeout to sysfs (bsc#1148410).

  - block: do not show io_timeout if driver has no timeout
    handler (bsc#1148410).

  - bluetooth: btrtl: Additional Realtek 8822CE Bluetooth
    devices (bsc#1051510).

  - bnx2x: Fix VF's VLAN reconfiguration in reload
    (bsc#1086323 ).

  - bridge/mdb: remove wrong use of NLM_F_MULTI
    (networking-stable-19_09_15).

  - btrfs: bail out gracefully rather than BUG_ON
    (bsc#1153646).

  - btrfs: check for the full sync flag while holding the
    inode lock during fsync (bsc#1153713).

  - btrfs: Ensure btrfs_init_dev_replace_tgtdev sees up to
    date values (bsc#1154651).

  - btrfs: Ensure replaced device does not have pending
    chunk allocation (bsc#1154607).

  - btrfs: remove wrong use of volume_mutex from
    btrfs_dev_replace_start (bsc#1154651).

  - can: mcp251x: mcp251x_hw_reset(): allow more time after
    a reset (bsc#1051510).

  - can: xilinx_can: xcan_probe(): skip error message on
    deferred probe (bsc#1051510).

  - cdc_ether: fix rndis support for Mediatek based
    smartphones (networking-stable-19_09_15).

  - cdc_ncm: fix divide-by-zero caused by invalid
    wMaxPacketSize (bsc#1051510).

  - ceph: fix directories inode i_blkbits initialization
    (bsc#1153717).

  - ceph: reconnect connection if session hang in opening
    state (bsc#1153718).

  - ceph: update the mtime when truncating up (bsc#1153719).

  - cfg80211: add and use strongly typed element iteration
    macros (bsc#1051510).

  - cfg80211: Purge frame registrations on iftype change
    (bsc#1051510).

  - clk: at91: select parent if main oscillator or bypass is
    enabled (bsc#1051510).

  - clk: qoriq: Fix -Wunused-const-variable (bsc#1051510).

  - clk: sirf: Do not reference clk_init_data after
    registration (bsc#1051510).

  - clk: zx296718: Do not reference clk_init_data after
    registration (bsc#1051510).

  - crypto: talitos - fix missing break in switch statement
    (bsc#1142635).

  - cxgb4: fix endianness for vlan value in cxgb4_tc_flower
    (bsc#1064802 bsc#1066129).

  - cxgb4: offload VLAN flows regardless of VLAN ethtype
    (bsc#1064802 bsc#1066129).

  - cxgb4: reduce kernel stack usage in
    cudbg_collect_mem_region() (bsc#1073513).

  - cxgb4: Signedness bug in init_one() (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: smt: Add lock for atomic_dec_and_test
    (bsc#1064802 bsc#1066129).

  - dasd_fba: Display '00000000' for zero page when dumping
    sense

  - /dev/mem: Bail out upon SIGKILL (git-fixes).

  - drm/amdgpu: Check for valid number of registers to read
    (bsc#1051510).

  - drm/amdgpu/si: fix ASIC tests (git-fixes).

  - drm/amd/powerplay/smu7: enforce minimal VBITimeout (v2)
    (bsc#1051510).

  - drm/ast: Fixed reboot test may cause system hanged
    (bsc#1051510).

  - drm/bridge: tc358767: Increase AUX transfer length limit
    (bsc#1051510).

  - drm: Flush output polling on shutdown (bsc#1051510).

  - drm/msm/dsi: Implement reset correctly (bsc#1051510).

  - drm/panel: simple: fix AUO g185han01 horizontal blanking
    (bsc#1051510).

  - drm/radeon: Fix EEH during kexec (bsc#1051510).

  - drm/tilcdc: Register cpufreq notifier after we have
    initialized crtc (bsc#1051510).

  - drm/vmwgfx: Fix double free in vmw_recv_msg()
    (bsc#1051510).

  - e1000e: add workaround for possible stalled packet
    (bsc#1051510).

  - firmware: dmi: Fix unlikely out-of-bounds read in
    save_mem_devices (git-fixes).

  - Fix AMD IOMMU kABI (bsc#1154610).

  - Fix KVM kABI after x86 mmu backports (bsc#1117665).

  - gpu: drm: radeon: Fix a possible NULL pointer
    dereference in radeon_connector_set_property()
    (bsc#1051510).

  - HID: apple: Fix stuck function keys when using FN
    (bsc#1051510).

  - HID: hidraw: Fix invalid read in hidraw_ioctl
    (bsc#1051510).

  - HID: logitech: Fix general protection fault caused by
    Logitech driver (bsc#1051510).

  - HID: prodikeys: Fix general protection fault during
    probe (bsc#1051510).

  - HID: sony: Fix memory corruption issue on cleanup
    (bsc#1051510).

  - hwmon: (acpi_power_meter) Change log level for 'unsafe
    software power cap' (bsc#1051510).

  - hwrng: core - do not wait on add_early_randomness()
    (git-fixes).

  - i2c: riic: Clear NACK in tend isr (bsc#1051510).

  - IB/core, ipoib: Do not overreact to SM LID change event
    (bsc#1154108)

  - IB/hfi1: Remove overly conservative VM_EXEC flag check
    (bsc#1144449).

  - IB/mlx5: Consolidate use_umr checks into single function
    (bsc#1093205).

  - IB/mlx5: Fix MR re-registration flow to use UMR properly
    (bsc#1093205).

  - IB/mlx5: Report correctly tag matching rendezvous
    capability (bsc#1046305).

  - ieee802154: atusb: fix use-after-free at disconnect
    (bsc#1051510).

  - ieee802154: enforce CAP_NET_RAW for raw sockets
    (bsc#1051510).

  - iio: adc: ad799x: fix probe error handling
    (bsc#1051510).

  - iio: light: opt3001: fix mutex unlock race
    (bsc#1051510).

  - ima: always return negative code for error
    (bsc#1051510).

  - Input: da9063 - fix capability and drop KEY_SLEEP
    (bsc#1051510).

  - iommu/amd: Apply the same IVRS IOAPIC workaround to Acer
    Aspire A315-41 (bsc#1137799).

  - iommu/amd: Check PM_LEVEL_SIZE() condition in locked
    section (bsc#1154608).

  - iommu/amd: Override wrong IVRS IOAPIC on Raven Ridge
    systems (bsc#1137799).

  - iommu/amd: Remove domain->updated (bsc#1154610).

  - iommu/amd: Wait for completion of IOTLB flush in
    attach_device (bsc#1154611).

  - ipmi_si: Only schedule continuously in the thread in
    maintenance mode (bsc#1051510).

  - ipv6: Fix the link time qualifier of
    'ping_v6_proc_exit_net()' (networking-stable-19_09_15).

  - ixgbe: Prevent u8 wrapping of ITR value to something
    less than 10us (bsc#1101674).

  - ixgbe: sync the first fragment unconditionally
    (bsc#1133140).

  - kabi: net: sched: act_sample: fix psample group handling
    on overwrite (networking-stable-19_09_05).

  - kabi/severities: Whitelist functions internal to radix
    mm. To call these functions you have to first detect if
    you are running in radix mm mode which can't be expected
    of OOT code.

  - kABI workaround for snd_hda_pick_pin_fixup() changes
    (bsc#1051510).

  - kernel-binary: Drop .kernel-binary.spec.buildenv
    (boo#1154578).

  - kernel-binary.spec.in: Fix build of non-modular kernels
    (boo#1154578).

  - kernel-subpackage-build: create zero size ghost for
    uncompressed vmlinux (bsc#1154354). It is not strictly
    necessary to uncompress it so maybe the ghost file can
    be 0 size in this case.

  - kernel/sysctl.c: do not override max_threads provided by
    userspace (bnc#1150875).

  - kvm: Convert kvm_lock to a mutex (bsc#1117665).

  - kvm: MMU: drop vcpu param in gpte_access (bsc#1117665).

  - kvm: PPC: Book3S HV: use smp_mb() when setting/clearing
    host_ipi flag (bsc#1061840).

  - kvm: x86: add tracepoints around __direct_map and
    FNAME(fetch) (bsc#1117665).

  - kvm: x86: adjust kvm_mmu_page member to save 8 bytes
    (bsc#1117665).

  - kvm: x86: change kvm_mmu_page_get_gfn BUG_ON to WARN_ON
    (bsc#1117665).

  - kvm: x86: Do not release the page inside mmu_set_spte()
    (bsc#1117665).

  - kvm: x86: make FNAME(fetch) and __direct_map more
    similar (bsc#1117665).

  - kvm: x86, powerpc: do not allow clearing largepages
    debugfs entry (bsc#1117665).

  - kvm: x86: remove now unneeded hugepage gfn adjustment
    (bsc#1117665).

  - libertas: Add missing sentinel at end of if_usb.c
    fw_table (bsc#1051510).

  - lib/mpi: Fix karactx leak in mpi_powm (bsc#1051510).

  - mac80211: accept deauth frames in IBSS mode
    (bsc#1051510).

  - macsec: drop skb sk before calling gro_cells_receive
    (bsc#1051510).

  - media: atmel: atmel-isc: fix asd memory allocation
    (bsc#1135642).

  - media: cpia2_usb: fix memory leaks (bsc#1051510).

  - media: dvb-core: fix a memory leak bug (bsc#1051510).

  - media: exynos4-is: fix leaked of_node references
    (bsc#1051510).

  - media: gspca: zero usb_buf on error (bsc#1051510).

  - media: hdpvr: Add device num check and handling
    (bsc#1051510).

  - media: hdpvr: add terminating 0 at end of string
    (bsc#1051510).

  - media: i2c: ov5645: Fix power sequence (bsc#1051510).

  - media: iguanair: add sanity checks (bsc#1051510).

  - media: omap3isp: Do not set streaming state on random
    subdevs (bsc#1051510).

  - media: omap3isp: Set device on omap3isp subdevs
    (bsc#1051510).

  - media: ov9650: add a sanity check (bsc#1051510).

  - media: radio/si470x: kill urb on error (bsc#1051510).

  - media: saa7134: fix terminology around
    saa7134_i2c_eeprom_md7134_gate() (bsc#1051510).

  - media: saa7146: add cleanup in hexium_attach()
    (bsc#1051510).

  - media: sn9c20x: Add MSI MS-1039 laptop to flip_dmi_table
    (bsc#1051510).

  - media: stkwebcam: fix runtime PM after driver unbind
    (bsc#1051510).

  - media: ttusb-dec: Fix info-leak in
    ttusb_dec_send_command() (bsc#1051510).

  - memstick: jmb38x_ms: Fix an error handling path in
    'jmb38x_ms_probe()' (bsc#1051510).

  - mfd: intel-lpss: Remove D3cold delay (bsc#1051510).

  - mISDN: enforce CAP_NET_RAW for raw sockets
    (bsc#1051510).

  - mld: fix memory leak in mld_del_delrec()
    (networking-stable-19_09_05).

  - mmc: sdhci: Fix incorrect switch to HS mode
    (bsc#1051510).

  - mmc: sdhci: improve ADMA error reporting (bsc#1051510).

  - mmc: sdhci-of-esdhc: set DMA snooping based on DMA
    coherence (bsc#1051510).

  - net: Fix null de-reference of device refcount
    (networking-stable-19_09_15).

  - net: fix skb use after free in netpoll
    (networking-stable-19_09_05).

  - net: gso: Fix skb_segment splat when splitting gso_size
    mangled skb having linear-headed frag_list
    (networking-stable-19_09_15).

  - net/ibmvnic: Fix EOI when running in XIVE mode
    (bsc#1089644, ltc#166495, ltc#165544, git-fixes).

  - net/mlx4_en: fix a memory leak bug (bsc#1046299).

  - net/mlx5: Add device ID of upcoming BlueField-2
    (bsc#1046303 ).

  - net/mlx5: Fix error handling in mlx5_load() (bsc#1046305
    ).

  - net: sched: act_sample: fix psample group handling on
    overwrite (networking-stable-19_09_05).

  - net: stmmac: dwmac-rk: Do not fail if phy regulator is
    absent (networking-stable-19_09_05).

  - nfc: fix attrs checks in netlink interface
    (bsc#1051510).

  - nfc: fix memory leak in llcp_sock_bind() (bsc#1051510).

  - nfc: pn533: fix use-after-free and memleaks
    (bsc#1051510).

  - objtool: Clobber user CFLAGS variable (bsc#1153236).

  - PCI: Correct pci=resource_alignment parameter example
    (bsc#1051510).

  - PCI: dra7xx: Fix legacy INTD IRQ handling (bsc#1087092).

  - PCI: hv: Use bytes 4 and 5 from instance ID as the PCI
    domain numbers (bsc#1153263).

  - PCI: PM: Fix pci_power_up() (bsc#1051510).

  - pinctrl: tegra: Fix write barrier placement in
    pmx_writel (bsc#1051510).

  - platform/x86: classmate-laptop: remove unused variable
    (bsc#1051510).

  - platform/x86: pmc_atom: Add Siemens SIMATIC IPC277E to
    critclk_systems DMI table (bsc#1051510).

  - powerpc/64s/pseries: radix flush translations before MMU
    is enabled at boot (bsc#1055186).

  - powerpc/64s/radix: keep kernel ERAT over local
    process/guest invalidates (bsc#1055186).

  - powerpc/64s/radix: tidy up TLB flushing code
    (bsc#1055186).

  - powerpc/64s: Rename PPC_INVALIDATE_ERAT to
    PPC_ISA_3_0_INVALIDATE_ERAT (bsc#1055186).

  - powerpc/mm/book3s64: Move book3s64 code to
    pgtable-book3s64 (bsc#1055186).

  - powerpc/mm: mark more tlb functions as __always_inline
    (bsc#1055186).

  - powerpc/mm: Properly invalidate when setting process
    table base (bsc#1055186).

  - powerpc/mm/radix: mark as __tlbie_pid() and friends
    as__always_inline (bsc#1055186).

  - powerpc/mm/radix: mark __radix__flush_tlb_range_psize()
    as __always_inline (bsc#1055186).

  - powerpc/pseries/mobility: use cond_resched when updating
    device tree (bsc#1153112 ltc#181778).

  - powerpc/pseries: Remove confusing warning message
    (bsc#1109158).

  - powerpc/rtas: allow rescheduling while changing cpu
    states (bsc#1153112 ltc#181778).

  - power: supply: sysfs: ratelimit property read error
    message (bsc#1051510).

  - Pull packaging cleanup from mkubecek.

  - qed: iWARP - Fix default window size to be based on chip
    (bsc#1050536 bsc#1050545).

  - qed: iWARP - Fix tc for MPA ll2 connection (bsc#1050536
    bsc#1050545).

  - qed: iWARP - fix uninitialized callback (bsc#1050536
    bsc#1050545).

  - qed: iWARP - Use READ_ONCE and smp_store_release to
    access ep->state (bsc#1050536 bsc#1050545).

  - RDMA/bnxt_re: Fix spelling mistake 'missin_resp' ->
    'missing_resp' (bsc#1050244).

  - RDMA: Fix goto target to release the allocated memory
    (bsc#1050244).

  - rtlwifi: rtl8192cu: Fix value set in descriptor
    (bsc#1142635).

  - sch_hhf: ensure quantum and hhf_non_hh_weight are
    non-zero (networking-stable-19_09_15).

  - scripts/arch-symbols: add missing link.

  - scsi: lpfc: Fix null ptr oops updating lpfc_devloss_tmo
    via sysfs attribute (bsc#1140845).

  - scsi: lpfc: Fix propagation of devloss_tmo setting to
    nvme transport (bsc#1140883).

  - scsi: lpfc: Remove bg debugfs buffers (bsc#1144375).

  - scsi: qedf: fc_rport_priv reference counting fixes
    (bsc#1098291).

  - scsi: qedf: Modify abort and tmf handler to handle edge
    condition and flush (bsc#1098291).

  - scsi: storvsc: setup 1:1 mapping between hardware queue
    and CPU queue (bsc#1140729).

  - sctp: Fix the link time qualifier of
    'sctp_ctrlsock_exit()' (networking-stable-19_09_15).

  - sctp: use transport pf_retrans in
    sctp_do_8_2_transport_strike
    (networking-stable-19_09_15).

  - Sign non-x86 kernels when possible (boo#1134303)

  - sock_diag: fix autoloading of the raw_diag module
    (bsc#1152791).

  - sock_diag: request _diag module only when the family or
    proto has been registered (bsc#1152791).

  - staging: vt6655: Fix memory leak in vt6655_probe
    (bsc#1051510).

  - tcp: Do not dequeue SYN/FIN-segments from write-queue
    (git-gixes).

  - tcp: fix tcp_ecn_withdraw_cwr() to clear
    TCP_ECN_QUEUE_CWR (networking-stable-19_09_15).

  - tcp: inherit timestamp on mtu probe
    (networking-stable-19_09_05).

  - tcp: remove empty skb from write queue in error cases
    (networking-stable-19_09_05).

  - thermal: Fix use-after-free when unregistering thermal
    zone device (bsc#1051510).

  - thermal_hwmon: Sanitize thermal_zone type (bsc#1051510).

  - tipc: add NULL pointer check before calling kfree_rcu
    (networking-stable-19_09_15).

  - tracing: Initialize iter->seq after zeroing in
    tracing_read_pipe() (bsc#1151508).

  - tun: fix use-after-free when register netdev failed
    (networking-stable-19_09_15).

  - tuntap: correctly set SOCKWQ_ASYNC_NOSPACE
    (bsc#1145099).

  - Update
    patches.suse/NFSv4-Check-the-return-value-of-update_open
    _stateid.patch (boo#1154189 bsc#1154747).

  - usb: adutux: fix NULL-derefs on disconnect
    (bsc#1142635).

  - usb: adutux: fix use-after-free on disconnect
    (bsc#1142635).

  - usb: adutux: fix use-after-free on release
    (bsc#1051510).

  - usb: chaoskey: fix use-after-free on release
    (bsc#1051510).

  - usb: dummy-hcd: fix power budget for SuperSpeed mode
    (bsc#1051510).

  - usb: iowarrior: fix use-after-free after driver unbind
    (bsc#1051510).

  - usb: iowarrior: fix use-after-free on disconnect
    (bsc#1051510).

  - usb: iowarrior: fix use-after-free on release
    (bsc#1051510).

  - usb: legousbtower: fix deadlock on disconnect
    (bsc#1142635).

  - usb: legousbtower: fix open after failed reset request
    (bsc#1142635).

  - usb: legousbtower: fix potential NULL-deref on
    disconnect (bsc#1142635).

  - usb: legousbtower: fix slab info leak at probe
    (bsc#1142635).

  - usb: legousbtower: fix use-after-free on release
    (bsc#1051510).

  - usb: microtek: fix info-leak at probe (bsc#1142635).

  - usbnet: ignore endpoints with invalid wMaxPacketSize
    (bsc#1051510).

  - usbnet: sanity checking of packet sizes and device mtu
    (bsc#1051510).

  - usb: serial: fix runtime PM after driver unbind
    (bsc#1051510).

  - usb: serial: ftdi_sio: add device IDs for Sienna and
    Echelon PL-20 (bsc#1051510).

  - usb: serial: keyspan: fix NULL-derefs on open() and
    write() (bsc#1051510).

  - usb: serial: option: add support for Cinterion CLS8
    devices (bsc#1051510).

  - usb: serial: option: add Telit FN980 compositions
    (bsc#1051510).

  - usb: usblcd: fix I/O after disconnect (bsc#1142635).

  - usb: usblp: fix runtime PM after driver unbind
    (bsc#1051510).

  - usb: usb-skeleton: fix NULL-deref on disconnect
    (bsc#1051510).

  - usb: usb-skeleton: fix runtime PM after driver unbind
    (bsc#1051510).

  - usb: usb-skeleton: fix use-after-free after driver
    unbind (bsc#1051510).

  - usb: xhci: wait for CNR controller not ready bit in xhci
    resume (bsc#1051510).

  - usb: yurex: Do not retry on unexpected errors
    (bsc#1051510).

  - usb: yurex: fix NULL-derefs on disconnect (bsc#1051510).

  - vfio_pci: Restore original state on release
    (bsc#1051510).

  - vhost_net: conditionally enable tx polling
    (bsc#1145099).

  - video: of: display_timing: Add of_node_put() in
    of_get_display_timing() (bsc#1051510).

  - watchdog: imx2_wdt: fix min() calculation in
    imx2_wdt_set_timeout (bsc#1051510).

  - x86/asm: Fix MWAITX C-state hint value (bsc#1114279).

  - x86/mm: Use WRITE_ONCE() when setting PTEs
    (bsc#1114279).

  - xen/netback: fix error path of xenvif_connect_data()
    (bsc#1065600).

  - xen/pv: Fix Xen PV guest int3 handling (bsc#1153811).

  - xhci: Check all endpoints for LPM timeout (bsc#1051510).

  - xhci: Fix false warning message about wrong bounce
    buffer write length (bsc#1051510).

  - xhci: Increase STS_SAVE timeout in xhci_suspend()
    (bsc#1051510).

  - xhci: Prevent device initiated U1/U2 link pm if exit
    latency is too long (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=118461_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=133135_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=135757_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=147830_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=147831_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=158172_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=165544_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=166495_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=172859_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=172860_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=181778_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229268_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229269_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229270_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229274_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229277_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229279_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229280_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229281_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229283_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229285_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229286_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=229297_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=296718_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=358767_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=359798_FIXME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=802154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=814594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998153"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/28");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.79.1") ) flag++;

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
