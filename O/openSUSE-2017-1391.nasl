#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1391.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105364);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000405", "CVE-2017-1000410", "CVE-2017-11600", "CVE-2017-12193", "CVE-2017-15115", "CVE-2017-16528", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16939", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-7482", "CVE-2017-8824");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1391) (Dirty COW)");
  script_summary(english:"Check for the openSUSE-2017-1391 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.103 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000405: A bug in the THP CoW support could be
    used by local attackers to corrupt memory of other
    processes and cause them to crash (bnc#1069496).

  - CVE-2017-1000410: The Linux kernel was affected by a
    vulnerability lies in the processing of incoming L2CAP
    commands - ConfigRequest, and ConfigResponse messages.
    This info leak is a result of uninitialized stack
    variables that may be returned to an attacker in their
    uninitialized state. (bnc#1070535).

  - CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux
    kernel did not ensure that the dir value of
    xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which
    allowed local users to cause a denial of service
    (out-of-bounds access) or possibly have unspecified
    other impact via an XFRM_MSG_MIGRATE xfrm Netlink
    message (bnc#1050231).

  - CVE-2017-12193: The
    assoc_array_insert_into_terminal_node function in
    lib/assoc_array.c in the Linux kernel mishandled node
    splitting, which allowed local users to cause a denial
    of service (NULL pointer dereference and panic) via a
    crafted application, as demonstrated by the keyring key
    type, and key addition and link creation operations
    (bnc#1066192).

  - CVE-2017-15115: The sctp_do_peeloff function in
    net/sctp/socket.c in the Linux kernel did not check
    whether the intended netns is used in a peel-off action,
    which allowed local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via crafted system calls
    (bnc#1068671).

  - CVE-2017-16528: sound/core/seq_device.c in the Linux
    kernel allowed local users to cause a denial of service
    (snd_rawmidi_dev_seq_free use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1066629).

  - CVE-2017-16536: The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel allowed local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB device
    (bnc#1066606).

  - CVE-2017-16537: The imon_probe function in
    drivers/media/rc/imon.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact via a crafted USB device
    (bnc#1066573).

  - CVE-2017-16645: The ims_pcu_get_cdc_union_desc function
    in drivers/input/misc/ims-pcu.c in the Linux kernel
    allowed local users to cause a denial of service
    (ims_pcu_parse_cdc_data out-of-bounds read and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1067132).

  - CVE-2017-16646:
    drivers/media/usb/dvb-usb/dib0700_devices.c in the Linux
    kernel allowed local users to cause a denial of service
    (BUG and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1067105).

  - CVE-2017-16939: The XFRM dump policy implementation in
    net/xfrm/xfrm_user.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) via a crafted SO_RCVBUF setsockopt
    system call in conjunction with XFRM_MSG_GETPOLICY
    Netlink messages (bnc#1069702).

  - CVE-2017-16994: The walk_hugetlb_range function in
    mm/pagewalk.c in the Linux kernel mishandled holes in
    hugetlb ranges, which allowed local users to obtain
    sensitive information from uninitialized kernel memory
    via crafted use of the mincore() system call
    (bnc#1069996).

  - CVE-2017-17448: net/netfilter/nfnetlink_cthelper.c in
    the Linux kernel did not require the CAP_NET_ADMIN
    capability for new, get, and del operations, which
    allowed local users to bypass intended access
    restrictions because the nfnl_cthelper_list data
    structure is shared across all net namespaces
    (bnc#1071693).

  - CVE-2017-17449: The __netlink_deliver_tap_skb function
    in net/netlink/af_netlink.c in the Linux kernel did not
    restrict observations of Netlink messages to a single
    net namespace, which allowed local users to obtain
    sensitive information by leveraging the CAP_NET_ADMIN
    capability to sniff an nlmon interface for all Netlink
    activity on the system (bnc#1071694).

  - CVE-2017-17450: net/netfilter/xt_osf.c in the Linux
    kernel did not require the CAP_NET_ADMIN capability for
    add_callback and remove_callback operations, which
    allowed local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all net namespaces (bnc#1071695).

  - CVE-2017-7482: Fixed an overflow when decoding a krb5
    principal. (bnc#1046107).

  - CVE-2017-8824: The dccp_disconnect function in
    net/dccp/proto.c in the Linux kernel allowed local users
    to gain privileges or cause a denial of service
    (use-after-free) via an AF_UNSPEC connect system call
    during the DCCP_LISTEN state (bnc#1070771).

The following non-security bugs were fixed :

  - acpi / apd: Add clock frequency for ThunderX2 I2C
    controller (bsc#1067225).

  - Add references (bsc#1062941, bsc#1037404, bsc#1012523,
    bsc#1038299) The scsi_devinfo patches are relevant for
    all bugs related to HITACHI OPEN-V.

  - adm80211: return an error if adm8211_alloc_rings() fails
    (bsc#1031717).

  - adv7604: Initialize drive strength to default when using
    DT (bnc#1012382).

  - af_netlink: ensure that NLMSG_DONE never fails in dumps
    (bnc#1012382).

  - alsa: caiaq: Fix stray URB at probe error path
    (bnc#1012382).

  - alsa: hda: Abort capability probe at invalid register
    read (bsc#1048356).

  - alsa: hda: Add Raven PCI ID (bnc#1012382).

  - alsa: hda - Apply ALC269_FIXUP_NO_SHUTUP on
    HDA_FIXUP_ACT_PROBE (bnc#1012382).

  - alsa: hda/ca0132 - Fix memory leak at error path
    (bsc#1031717).

  - alsa: hda - fix headset mic problem for Dell machines
    with alc236 (bnc#1012382).

  - alsa: hda - No loopback on ALC299 codec (git-fixes).

  - alsa: hda/realtek: Add headset mic support for Intel NUC
    Skull Canyon (bsc#1031717).

  - alsa: hda/realtek - Add new codec ID ALC299
    (bnc#1012382).

  - alsa: hda/realtek - Add support for ALC236/ALC3204
    (bnc#1012382).

  - alsa: hda/realtek - Fix ALC700 family no sound issue
    (bsc#1031717).

  - alsa: hda: Remove superfluous '-' added by printk
    conversion (bnc#1012382).

  - alsa: hda: Workaround for KBL codec power control
    (bsc#1048356,bsc#1047989,bsc#1055272,bsc#1058413).

  - alsa: line6: Fix leftover URB at error-path during probe
    (bnc#1012382).

  - alsa: pcm: update tstamp only if audio_tstamp changed
    (bsc#1031717).

  - alsa: seq: Avoid invalid lockdep class warning
    (bsc#1031717).

  - alsa: seq: Enable 'use' locking in all configurations
    (bnc#1012382).

  - alsa: seq: Fix copy_from_user() call inside lock
    (bnc#1012382).

  - alsa: seq: Fix nested rwsem annotation for lockdep splat
    (bnc#1012382).

  - alsa: seq: Fix OSS sysex delivery in OSS emulation
    (bnc#1012382).

  - alsa: timer: Add missing mutex lock for compat ioctls
    (bnc#1012382).

  - alsa: timer: Remove kernel warning at compat ioctl error
    paths (bsc#1031717).

  - alsa: usb-audio: Add native DSD support for Pro-Ject Pre
    Box S2 Digital (bnc#1012382).

  - alsa: usb-audio: Add sanity checks in v2 clock parsers
    (bsc#1031717).

  - alsa: usb-audio: Add sanity checks to FE parser
    (bsc#1031717).

  - alsa: usb-audio: Fix potential out-of-bound access at
    parsing SU (bsc#1031717).

  - alsa: usb-audio: Kill stray URB at exiting
    (bnc#1012382).

  - alsa: usb-audio: uac1: Invalidate ctl on interrupt
    (bsc#1031717).

  - alsa: vx: Do not try to update capture stream before
    running (bnc#1012382).

  - alsa: vx: Fix possible transfer overflow (bnc#1012382).

  - Apply generic ppc build fixes to vanilla (bsc#1070805)

  - arm64: dts: NS2: reserve memory for Nitro firmware
    (bnc#1012382).

  - arm64: ensure __dump_instr() checks addr_limit
    (bnc#1012382).

  - arm: 8715/1: add a private asm/unaligned.h
    (bnc#1012382).

  - arm: 8720/1: ensure dump_instr() checks addr_limit
    (bnc#1012382).

  - arm: 8721/1: mm: dump: check hardware RO bit for LPAE
    (bnc#1012382).

  - arm: 8722/1: mm: make STRICT_KERNEL_RWX effective for
    LPAE (bnc#1012382).

  - arm: crypto: reduce priority of bit-sliced AES cipher
    (bnc#1012382).

  - arm: dts: Fix am335x and dm814x scm syscon to probe
    children (bnc#1012382).

  - arm: dts: Fix compatible for ti81xx uarts for 8250
    (bnc#1012382).

  - arm: dts: Fix omap3 off mode pull defines (bnc#1012382).

  - arm: dts: mvebu: pl310-cache disable double-linefill
    (bnc#1012382).

  - arm: OMAP2+: Fix init for multiple quirks for the same
    SoC (bnc#1012382).

  - arm: omap2plus_defconfig: Fix probe errors on UARTs 5
    and 6 (bnc#1012382).

  - arm: pxa: Do not rely on public mmc header to include
    leds.h (bnc#1012382).

  - asm/sections: add helpers to check for section data
    (bsc#1063026).

  - asoc: adau17x1: Workaround for noise bug in ADC
    (bnc#1012382).

  - asoc: cs42l56: Fix reset GPIO name in example DT binding
    (bsc#1031717).

  - asoc: davinci-mcasp: Fix an error handling path in
    'davinci_mcasp_probe()' (bsc#1031717).

  - ASoC: rsnd: do not double free kctrl (bnc#1012382).

  - asoc: samsung: Fix possible double iounmap on s3c24xx
    driver probe failure (bsc#1031717).

  - ASoC: wm_adsp: Do not overrun firmware file buffer when
    reading region data (bnc#1012382).

  - ata: ATA_BMDMA should depend on HAS_DMA (bnc#1012382).

  - ata: fixes kernel crash while tracing
    ata_eh_link_autopsy event (bnc#1012382).

  - ata: SATA_HIGHBANK should depend on HAS_DMA
    (bnc#1012382).

  - ata: SATA_MV should depend on HAS_DMA (bnc#1012382).

  - ath10k: convert warning about non-existent OTP board id
    to debug message (git-fixes).

  - ath10k: fix a warning during channel switch with
    multiple vaps (bsc#1031717).

  - ath10k: fix board data fetch error message
    (bsc#1031717).

  - ath10k: fix diag_read to collect data for larger memory
    (bsc#1031717).

  - ath10k: fix incorrect txpower set by P2P_DEVICE
    interface (bnc#1012382).

  - ath10k: fix potential memory leak in
    ath10k_wmi_tlv_op_pull_fw_stats() (bnc#1012382).

  - ath10k: free cached fw bin contents when get board id
    fails (bsc#1031717).

  - ath10k: ignore configuring the incorrect board_id
    (bnc#1012382).

  - ath10k: set CTS protection VDEV param only if VDEV is up
    (bnc#1012382).

  - ath9k_htc: check for underflow in ath9k_htc_rx_msg()
    (bsc#1031717).

  - ath9k: off by one in ath9k_hw_nvram_read_array()
    (bsc#1031717).

  - autofs: do not fail mount for transient error
    (bsc#1065180).

  - backlight: adp5520: Fix error handling in
    adp5520_bl_probe() (bnc#1012382).

  - backlight: lcd: Fix race condition during register
    (bnc#1012382).

  - bcache: check ca->alloc_thread initialized before wake
    up it (bnc#1012382).

  - bio-integrity: bio_integrity_advance must update
    integrity seed (bsc#1046054).

  - bio-integrity: bio_trim should truncate integrity vector
    accordingly (bsc#1046054).

  - bio-integrity: Do not allocate integrity context for bio
    w/o data (bsc#1046054).

  - bio-integrity: fix interface for bio_integrity_trim
    (bsc#1046054).

  - bio: partially revert 'fix interface for
    bio_integrity_trim' (bsc#1046054).

  - blacklist 85e3f1adcb9d powerpc/64s/radix: Fix
    128TB-512TB virtual address boundary case allocation

  - blacklist arm64 kaslr fix for 16KB pages

  - blacklist.conf

  - blacklist.conf: add
    79b63f12abcbbd2caf7064b294af648a87de07ff # bsc#1061756
    may break existing setups

  - blacklist.conf: Add ath10k, mmc and rtl8192u commits
    (bsc#1031717)

  - blacklist.conf: Add drm/i915 blacklist (bsc#1031717)

  - blacklist.conf: added misc commits (bsc#1031717)

  - blacklist.conf: Add misc entries (bsc#1031717)

  - blacklist.conf: Add non-applicable commit ID
    (bsc#1066812)

  - blacklist.conf: Add non-applicable commits (bsc#1066812)

  - blacklist.conf: add test_kmod blacklist
    CONFIG_TEST_KMOD=n is currently set. When and if we
    enable it then we will need it, otherwise we do not.

  - blacklist.conf: add two more

  - blacklist.conf: blacklist 0fafdc9f888b

  - blacklist.conf: blacklist 4c578dce5803

  - blacklist.conf: blacklisted 16af97dc5a89 (bnc#1053919)

  - blacklist.conf: Blacklist two commits (bbb3be170ac2 and
    ccf1e0045eea).

  - blacklist.conf: commit fe22cd9b7c980b8b948 ('printk:
    help pr_debug and pr_devel to optimize out arguments')
    is just a cosmetic change.

  - blacklist.conf: ignore a broken USB-audio patch

  - blacklist.conf: Update blacklist (bsc#1031717)

  - blacklist.conf: Update iwlwifi blacklist (bsc#1031717)

  - blacklist.conf: yet another serial entry (bsc#1031717)

  - blacklist irrelevant powerpc fixes 6b8cb66a6a7c powerpc:
    Fix usage of _PAGE_RO in hugepage Only relevant on ppc
    CPUs that have non-zero _PAGE_RO a050d20d024d
    powerpc/64s: Use relon prolog for
    EXC_VIRT_OOL_MASKABLE_HV handlers IPI optimization, hard
    to backport fb479e44a9e2 powerpc/64s: relocation,
    register save fixes for system reset interrupt Fixes
    PowerNV running relocated. Nobody missed it so far.
    e76ca27790a5 powerpc/sysfs: Fix reference leak of cpu
    device_nodes present at boot Fixes leak of few kobjects
    created at boot but high risk of regression

  - blacklist tpm endian annotation patches.

  - block: Fix a race between blk_cleanup_queue() and
    timeout handling (FATE#319965, bsc#964944).

  - block: Make q_usage_counter also track legacy requests
    (bsc#1057820).

  - bluetooth: btusb: fix QCA Rome suspend/resume
    (bnc#1012382).

  - bnxt_en: Do not use rtnl lock to protect link change
    logic in workqueue (bsc#1020412 FATE#321671).

  - bnxt_en: Fix a variable scoping in
    bnxt_hwrm_do_send_msg() (bsc#1053309).

  - bnxt_en: Fix possible corrupted NVRAM parameters from
    firmware response (bsc#1020412 FATE#321671).

  - bnxt_en: Fix possible corruption in DCB parameters from
    firmware (bsc#1020412 FATE#321671).

  - bnxt_en: Fix VF PCIe link speed and width logic
    (bsc#1020412 FATE#321671).

  - bnxt_en: Need to unconditionally shut down RoCE in
    bnxt_shutdown (bsc#1053309).

  - bnxt_re: Make room for mapping beyond 32 entries
    (bsc#1056596).

  - bonding: discard lowest hash bit for 802.3ad layer3+4
    (bnc#1012382).

  - bpf: one perf event close won't free bpf program
    attached by another perf event (bnc#1012382).

  - bpf/verifier: reject BPF_ALU64|BPF_END (bnc#1012382).

  - brcmfmac: add length check in
    brcmf_cfg80211_escan_handler() (bnc#1012382).

  - brcmfmac: remove setting IBSS mode when stopping AP
    (bnc#1012382).

  - brcmsmac: make some local variables 'static const' to
    reduce stack size (bnc#1012382).

  - bt8xx: fix memory leak (bnc#1012382).

  - btrfs: return the actual error value from from
    btrfs_uuid_tree_iterate (bnc#1012382).

  - bus: mbus: fix window size calculation for 4GB windows
    (bnc#1012382).

  - can: c_can: do not indicate triple sampling support for
    D_CAN (bnc#1012382).

  - can: esd_usb2: Fix can_dlc value for received RTR,
    frames (bnc#1012382).

  - can: gs_usb: fix busy loop if no more TX context is
    available (bnc#1012382).

  - can: kvaser_usb: Correct return value in printout
    (bnc#1012382).

  - can: kvaser_usb: Ignore CMD_FLUSH_QUEUE_REPLY messages
    (bnc#1012382).

  - can: sun4i: fix loopback mode (bnc#1012382).

  - can: sun4i: handle overrun in RX FIFO (bnc#1012382).

  - cdc_ncm: Set NTB format again after altsetting switch
    for Huawei devices (bnc#1012382).

  - ceph: clean up unsafe d_parent accesses in
    build_dentry_path (FATE#322288 bnc#1012382).

  - ceph: disable cached readdir after dropping positive
    dentry (bsc#1069277).

  - ceph: -EINVAL on decoding failure in
    ceph_mdsc_handle_fsmap() (bsc#1069277).

  - ceph: present consistent fsid, regardless of arch
    endianness (bsc#1069277).

  - ceph: unlock dangling spinlock in try_flush_caps()
    (bsc#1065639).

  - cgroup, net_cls: iterate the fds of only the tasks which
    are being migrated (bnc#1064926).

  - cifs: check MaxPathNameComponentLength != 0 before using
    it (bnc#1012382).

  - cifs: fix circular locking dependency (bsc#1064701).

  - cifs: Reconnect expired SMB sessions (bnc#1012382).

  - clk: ti: dra7-atl-clock: fix child-node lookups
    (bnc#1012382).

  - clk: ti: dra7-atl-clock: Fix of_node reference counting
    (bnc#1012382).

  - clockevents/drivers/cs5535: Improve resilience to
    spurious interrupts (bnc#1012382).

  - cma: fix calculation of aligned offset (VM
    Functionality, bsc#1050060).

  - coda: fix 'kernel memory exposure attempt' in fsync
    (bnc#1012382).

  - cpufreq: CPPC: add ACPI_PROCESSOR dependency
    (bnc#1012382).

  - crypto: dh - Do not permit 'key' or 'g' size longer than
    'p' (bsc#1048317).

  - crypto: dh - Do not permit 'p' to be 0 (bsc#1048317).

  - crypto: dh - Fix double free of ctx->p (bsc#1048317).

  - crypto: dh - fix memleak in setkey (bsc#1048317).

  - crypto: rsa - fix buffer overread when stripping leading
    zeroes (bsc#1048317).

  - crypto: shash - Fix zero-length shash ahash digest crash
    (bnc#1012382).

  - crypto: vmx - disable preemption to enable vsx in
    aes_ctr.c (bnc#1012382).

  - crypto: x86/sha1-mb - fix panic due to unaligned access
    (bnc#1012382).

  - crypto: xts - Add ECB dependency (bnc#1012382).

  - cx231xx: Fix I2C on Internal Master 3 Bus (bnc#1012382).

  - cxgb4: Fix error codes in c4iw_create_cq()
    (bsc#1048327).

  - cxl: Fix DAR check & use REGION_ID instead of opencoding
    (bsc#1066223).

  - cxl: Fix leaking pid refs in some error paths
    (bsc#1066223).

  - cxl: Force context lock during EEH flow (bsc#1066223).

  - cxl: Prevent adapter reset if an active context exists
    (bsc#1066223).

  - cxl: Route eeh events to all drivers in
    cxl_pci_error_detected() (bsc#1066223).

  - direct-io: Prevent NULL pointer access in
    submit_page_section (bnc#1012382).

  - Disable
    patches.kernel.org/4.4.93-022-fix-unbalanced-page-refcou
    nting-in-bio_map_use.patch (bsc#1070767)

  - dmaengine: dmatest: warn user when dma test times out
    (bnc#1012382).

  - dmaengine: edma: Align the memcpy acnt array size with
    the transfer (bnc#1012382).

  - dmaengine: zx: set DMA_CYCLIC cap_mask bit
    (bnc#1012382).

  - dm bufio: fix integer overflow when limiting maximum
    cache size (bnc#1012382).

  - dm: fix race between dm_get_from_kobject() and
    __dm_destroy() (bnc#1012382).

  - dm mpath: remove annoying message of 'blk_get_request()
    returned -11' (bsc#1066812).

  - dm raid: fix NULL pointer dereference for raid1 without
    bitmap (bsc#1042957, FATE#321488).

  - dm rq: Avoid that request processing stalls sporadically
    (bsc#1042978).

  - drivers: base: cacheinfo: fix x86 with CONFIG_OF enabled
    (bsc#1070001).

  - drivers: dma-mapping: Do not leave an invalid
    area->pages pointer in dma_common_contiguous_remap()
    (Git-fixes, bsc#1065692).

  - drivers/fbdev/efifb: Allow BAR to be moved instead of
    claiming it (bsc#1051987).

  - drivers: of: Fix of_pci.h header guard (bsc#1065959).

  - drm/amdgpu: when dpm disabled, also need to stop/start
    vce (bnc#1012382).

  - drm/amdkfd: NULL dereference involving create_process()
    (bsc#1031717).

  - drm: Apply range restriction after color adjustment when
    allocation (bnc#1012382).

  - drm/armada: Fix compile fail (bnc#1012382).

  - drm: drm_minor_register(): Clean up debugfs on failure
    (bnc#1012382).

  - drm: gma500: fix logic error (bsc#1031717).

  - drm/i915/bxt: set min brightness from VBT (bsc#1031717).

  - drm/i915: Do not try indexed reads to alternate slave
    addresses (bsc#1031717).

  - drm/i915: fix backlight invert for non-zero minimum
    brightness (bsc#1031717).

  - drm/i915: Prevent zero length 'index' write
    (bsc#1031717).

  - drm/i915: Read timings from the correct transcoder in
    intel_crtc_mode_get() (bsc#1031717).

  - drm/msm: fix an integer overflow test (bnc#1012382).

  - drm/msm: Fix potential buffer overflow issue
    (bnc#1012382).

  - drm/nouveau/bsp/g92: disable by default (bnc#1012382).

  - drm/nouveau/gr: fallback to legacy paths during firmware
    lookup (bsc#1031717).

  - drm/nouveau/mmu: flush tlbs before deleting page tables
    (bnc#1012382).

  - drm/omap: Fix error handling path in 'omap_dmm_probe()'
    (bsc#1031717).

  - drm/panel: simple: Add missing panel_simple_unprepare()
    calls (bsc#1031717).

  - drm/radeon: Avoid double gpu reset by adding a timeout
    on IB ring tests (bsc#1066175).

  - drm/sti: sti_vtg: Handle return NULL error from
    devm_ioremap_nocache (bnc#1012382).

  - drm/vc4: Fix leak of HDMI EDID (bsc#1031717).

  - drm/vmwgfx: Fix Ubuntu 17.10 Wayland black screen issue
    (bnc#1012382).

  - e1000e: Avoid receiver overrun interrupt bursts
    (bsc#969470 FATE#319819).

  - e1000e: Fix error path in link detection (bnc#1012382).

  - e1000e: Fix return value test (bnc#1012382).

  - e1000e: Separate signaling for link check/link up
    (bnc#1012382).

  - ecryptfs: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - eCryptfs: use after free in ecryptfs_release_messaging()
    (bsc#1070404).

  - epoll: avoid calling ep_call_nested() from
    ep_poll_safewake() (bsc#1056427).

  - epoll: remove ep_call_nested() from ep_eventpoll_poll()
    (bsc#1056427).

  - ext4: cleanup goto next group (bsc#1066285).

  - ext4: do not use stripe_width if it is not set
    (bnc#1012382).

  - ext4: fix fault handling when mounted with -o dax,ro
    (bsc#1069484).

  - ext4: fix interaction between i_size, fallocate, and
    delalloc after a crash (bnc#1012382).

  - ext4: fix stripe-unaligned allocations (bnc#1012382).

  - ext4: in ext4_seek_(hole,data), return -ENXIO for
    negative offsets (bnc#1012382).

  - ext4: prevent data corruption with inline data + DAX
    (bsc#1064591).

  - ext4: prevent data corruption with journaling + DAX
    (bsc#1064591).

  - ext4: reduce lock contention in __ext4_new_inode
    (bsc#1066285).

  - extcon: palmas: Check the parent instance to prevent the
    NULL (bnc#1012382).

  - exynos4-is: fimc-is: Unmap region obtained by of_iomap()
    (bnc#1012382).

  - f2fs crypto: add missing locking for keyring_key access
    (bnc#1012382).

  - f2fs crypto: replace some BUG_ON()'s with error checks
    (bnc#1012382).

  - f2fs: do not wait for writeback in write_begin
    (bnc#1012382).

  - fealnx: Fix building error on MIPS (bnc#1012382).

  - fix a page leak in vhost_scsi_iov_to_sgl() error
    recovery (bnc#1012382).

  - fix unbalanced page refcounting in bio_map_user_iov
    (bnc#1012382).

  - fm10k: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - fs/9p: Compare qid.path in v9fs_test_inode
    (bsc#1070404).

  - FS-Cache: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - fscrypt: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - fscrypt: lock mutex before checking for bounce page pool
    (bnc#1012382).

  - fscrypto: require write access to mount to set
    encryption policy (bnc#1012382).

  - fuse: fix READDIRPLUS skipping an entry (bnc#1012382).

  - gpu: drm: mgag200: mgag200_main:- Handle error from
    pci_iomap (bnc#1012382).

  - hid: elo: clear BTN_LEFT mapping (bsc#1065866).

  - hid: usbhid: fix out-of-bounds bug (bnc#1012382).

  - hsi: ssi_protocol: double free in ssip_pn_xmit()
    (bsc#1031717).

  - hwmon: (xgene) Fix up error handling path mixup in
    'xgene_hwmon_probe()' (bsc#).

  - i2c: at91: ensure state is restored after suspending
    (bnc#1012382).

  - i2c: bcm2835: Add support for dynamic clock
    (bsc#1066660).

  - i2c: bcm2835: Add support for Repeated Start Condition
    (bsc#1066660).

  - i2c: bcm2835: Avoid possible NULL ptr dereference
    (bsc#1066660).

  - i2c: bcm2835: Can't support I2C_M_IGNORE_NAK
    (bsc#1066660).

  - i2c: bcm2835: Do not complain on -EPROBE_DEFER from
    getting our clock (bsc#1066660).

  - i2c: bcm2835: Fix hang for writing messages larger than
    16 bytes (bsc#1066660).

  - i2c: bcm2835: Protect against unexpected TXW/RXR
    interrupts (bsc#1066660).

  - i2c: bcm2835: Support i2c-dev ioctl I2C_TIMEOUT
    (bsc#1066660).

  - i2c: bcm2835: Use dev_dbg logging on transfer errors
    (bsc#1066660).

  - i2c: cadance: fix ctrl/addr reg write order
    (bsc#1031717).

  - i2c: imx: Use correct function to write to register
    (bsc#1031717).

  - i2c: ismt: Separate I2C block read from SMBus block read
    (bnc#1012382).

  - i2c: riic: correctly finish transfers (bnc#1012382).

  - i2c: riic: fix restart condition (git-fixes).

  - i2c: xlp9xx: Enable HWMON class probing for xlp9xx
    (bsc#1067225).

  - i2c: xlp9xx: Get clock frequency with clk API
    (bsc#1067225).

  - i2c: xlp9xx: Handle I2C_M_RECV_LEN in msg->flags
    (bsc#1067225).

  - i40e: Fix incorrect use of tx_itr_setting when checking
    for Rx ITR setup (bsc#1024346 FATE#321239 bsc#1024373
    FATE#321247).

  - i40e: fix the calculation of VFs mac addresses
    (bsc#1024346 FATE#321239 bsc#1024373 FATE#321247).

  - i40e: only redistribute MSI-X vectors when needed
    (bsc#1024346 FATE#321239 bsc#1024373 FATE#321247).

  - i40e: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - i40evf: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - i40iw: Remove UDA QP from QoS list if creation fails
    (bsc#1024376 FATE#321249).

  - ib/core: Fix calculation of maximum RoCE MTU
    (bsc#1022595 FATE#322350).

  - ib/core: Fix unable to change lifespan entry for
    hw_counters (FATE#321231 FATE#321473).

  - ib/core: Namespace is mandatory input for address
    resolution (bsc#1022595 FATE#322350).

  - ib/hfi1: Add MODULE_FIRMWARE statements (bsc#1036800).

  - ib/ipoib: Clean error paths in add port (bsc#1022595
    FATE#322350).

  - ib/ipoib: Prevent setting negative values to
    max_nonsrq_conn_qp (bsc#1022595 FATE#322350).

  - ib/ipoib: Remove double pointer assigning (bsc#1022595
    FATE#322350).

  - ib/ipoib: Set IPOIB_NEIGH_TBL_FLUSH after flushed
    completion initialization (bsc#1022595 FATE#322350).

  - ib/mlx5: Fix RoCE Address Path fields (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - ibmvnic: Add netdev_dbg output for debugging
    (fate#323285).

  - ibmvnic: Add vnic client data to login buffer
    (bsc#1069942).

  - ibmvnic: Convert vnic server reported statistics to cpu
    endian (fate#323285).

  - ibmvnic: Enable scatter-gather support (bsc#1066382).

  - ibmvnic: Enable TSO support (bsc#1066382).

  - ibmvnic: Feature implementation of Vital Product Data
    (VPD) for the ibmvnic driver (bsc#1069942).

  - ibmvnic: Fix calculation of number of TX header
    descriptors (bsc#1066382).

  - ibmvnic: fix dma_mapping_error call (bsc#1069942).

  - ibmvnic: Fix failover error path for non-fatal resets
    (bsc#1066382).

  - ibmvnic: Implement .get_channels (fate#323285).

  - ibmvnic: Implement .get_ringparam (fate#323285).

  - ibmvnic: Implement per-queue statistics reporting
    (fate#323285).

  - ibmvnic: Let users change net device features
    (bsc#1066382).

  - ibmvnic: Update reset infrastructure to support tunable
    parameters (bsc#1066382).

  - ib/rxe: check for allocation failure on elem
    (FATE#322149).

  - ib/rxe: do not crash, if allocation of crc algorithm
    failed (bsc#1051635).

  - ib/rxe: put the pool on allocation failure
    (FATE#322149).

  - ib/srp: Avoid that a cable pull can trigger a kernel
    crash (bsc#1022595 FATE#322350).

  - ib/srpt: Do not accept invalid initiator port names
    (bnc#1012382).

  - ib/uverbs: Fix device cleanup (bsc#1022595 FATE#322350).

  - ib/uverbs: Fix NULL pointer dereference during device
    removal (bsc#1022595 FATE#322350).

  - igb: close/suspend race in netif_device_detach
    (bnc#1012382).

  - igb: Fix hw_dbg logging in igb_update_flash_i210
    (bnc#1012382).

  - igb: reset the PHY before reading the PHY ID
    (bnc#1012382).

  - igb: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - igbvf: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - iio: adc: xilinx: Fix error handling (bnc#1012382).

  - iio: dummy: events: Add missing break (bsc#1031717).

  - iio: light: fix improper return value (bnc#1012382).

  - iio: trigger: free trigger resource correctly
    (bnc#1012382).

  - ima: do not update security.ima if appraisal status is
    not INTEGRITY_PASS (bnc#1012382).

  - input: ar1021_i2c - fix too long name in driver's device
    table (bsc#1031717).

  - input: edt-ft5x06 - fix setting gain, offset, and
    threshold via device tree (bsc#1031717).

  - input: elan_i2c - add ELAN060C to the ACPI table
    (bnc#1012382).

  - input: elan_i2c - add ELAN0611 to the ACPI table
    (bnc#1012382).

  - input: gtco - fix potential out-of-bound access
    (bnc#1012382).

  - input: mpr121 - handle multiple bits change of status
    register (bnc#1012382).

  - input: mpr121 - set missing event capability
    (bnc#1012382).

  - input: ti_am335x_tsc - fix incorrect step config for 5
    wire touchscreen (bsc#1031717).

  - input: twl4030-pwrbutton - use correct device for irq
    request (bsc#1031717).

  - input: ucb1400_ts - fix suspend and resume handling
    (bsc#1031717).

  - input: uinput - avoid crash when sending FF request to
    device going away (bsc#1031717).

  - iommu/amd: Finish TLB flush in amd_iommu_unmap()
    (bnc#1012382).

  - iommu/vt-d: Do not register bus-notifier under
    dmar_global_lock (bsc#1069793).

  - ip6_gre: only increase err_count for some certain type
    icmpv6 in ip6gre_err (bnc#1012382).

  - ip6_gre: skb_push ipv6hdr before packing the header in
    ip6gre_header (bnc#1012382).

  - ipip: only increase err_count for some certain type icmp
    in ipip_err (bnc#1012382).

  - ipmi: fix unsigned long underflow (bnc#1012382).

  - ipmi: Pick up slave address from SMBIOS on an ACPI
    device (bsc#1070006).

  - ipmi: Prefer ACPI system interfaces over SMBIOS ones
    (bsc#1070006).

  - ipmi_si: Clean up printks (bsc#1070006).

  - ipmi_si: fix memory leak on new_smi (bsc#1070006).

  - ipsec: do not ignore crypto err in ah4 input
    (bnc#1012382).

  - ipv6: flowlabel: do not leave opt->tot_len with garbage
    (bnc#1012382).

  - ipv6: only call ip6_route_dev_notify() once for
    NETDEV_UNREGISTER (bnc#1012382).

  - ipvs: make drop_entry protection effective for SIP-pe
    (bsc#1056365).

  - irqchip/crossbar: Fix incorrect type of local variables
    (bnc#1012382).

  - isa: Prevent NULL dereference in isa_bus driver
    callbacks (bsc#1031717).

  - iscsi-target: Fix non-immediate TMR reference leak
    (bnc#1012382).

  - isdn/i4l: fetch the ppp_write buffer in one shot
    (bnc#1012382).

  - isofs: fix timestamps beyond 2027 (bnc#1012382).

  - iwlwifi: mvm: fix the coex firmware API (bsc#1031717).

  - iwlwifi: mvm: return -ENODATA when reading the
    temperature with the FW down (bsc#1031717).

  - iwlwifi: mvm: set the RTS_MIMO_PROT bit in flag mask
    when sending sta to fw (bsc#1031717).

  - iwlwifi: mvm: use IWL_HCMD_NOCOPY for MCAST_FILTER_CMD
    (bnc#1012382).

  - iwlwifi: split the regulatory rules when the bandwidth
    flags require it (bsc#1031717).

  - ixgbe: add mask for 64 RSS queues (bnc#1012382).

  - ixgbe: do not disable FEC from the driver (bnc#1012382).

  - ixgbe: fix AER error handling (bnc#1012382).

  - ixgbe: Fix skb list corruption on Power systems
    (bnc#1012382).

  - ixgbe: handle close/suspend race with
    netif_device_detach/present (bnc#1012382).

  - ixgbe: Reduce I2C retry count on X550 devices
    (bnc#1012382).

  - ixgbevf: Use smp_rmb rather than read_barrier_depends
    (bnc#1012382).

  - kABI fix for 4.4.99 net changes (stable-4.4.99).

  - kABI: protect struct l2tp_tunnel (kabi).

  - kABI: protect struct regulator_dev (kabi).

  - kABI: protect structs rt_rq+root_domain (kabi).

  - kABI: protect typedef rds_rdma_cookie_t (kabi).

  - kabi/severities: Ignore drivers/nvme/target
    (bsc#1063349)

  - kabi/severities: Ignore kABI changes for qla2xxx
    (bsc#1043017)

  - kernel-docs: unpack the source instead of using
    kernel-source (bsc#1057199).

  - kernel/sysctl_binary.c: check name array length in
    deprecated_sysctl_warning() (FATE#323821).

  - kernel/sysctl.c: remove duplicate UINT_MAX check on
    do_proc_douintvec_conv() (bsc#1066470).

  - kernel/watchdog: Prevent false positives with turbo
    modes (bnc#1063516).

  - keys: do not let add_key() update an uninstantiated key
    (bnc#1012382).

  - keys: do not revoke uninstantiated key in
    request_key_auth_new() (bsc#1031717).

  - keys: encrypted: fix dereference of NULL
    user_key_payload (bnc#1012382).

  - keys: fix cred refcount leak in request_key_auth_new()
    (bsc#1031717).

  - keys: fix key refcount leak in keyctl_assume_authority()
    (bsc#1031717).

  - keys: fix key refcount leak in keyctl_read_key()
    (bsc#1031717).

  - keys: fix NULL pointer dereference during ASN.1 parsing
    [ver #2] (bnc#1012382).

  - keys: fix out-of-bounds read during ASN.1 parsing
    (bnc#1012382).

  - keys: Fix race between updating and finding a negative
    key (bnc#1012382).

  - keys: return full count in keyring_read() if buffer is
    too small (bnc#1012382).

  - keys: trusted: fix writing past end of buffer in
    trusted_read() (bnc#1012382).

  - keys: trusted: sanitize all key material (bnc#1012382).

  - KVM: nVMX: fix guest CR4 loading when emulating L2 to L1
    exit (bnc#1012382).

  - kvm: nVMX: set IDTR and GDTR limits when loading L1 host
    state (bnc#1012382).

  - KVM: PPC: Book 3S: XICS: correct the real mode ICP
    rejecting counter (bnc#1012382).

  - kvm: SVM: obey guest PAT (bnc#1012382).

  - l2tp: Avoid schedule while atomic in exit_net
    (bnc#1012382).

  - l2tp: check ps->sock before running
    pppol2tp_session_ioctl() (bnc#1012382).

  - l2tp: fix race condition in l2tp_tunnel_delete
    (bnc#1012382).

  - libceph: do not WARN() if user tries to add invalid key
    (bsc#1069277).

  - lib/digsig: fix dereference of NULL user_key_payload
    (bnc#1012382).

  - libertas: Fix lbs_prb_rsp_limit_set() (bsc#1031717).

  - lib/mpi: call cond_resched() from mpi_powm() loop
    (bnc#1012382).

  - libnvdimm, namespace: fix label initialization to use
    valid seq numbers (bnc#1012382).

  - libnvdimm, namespace: make 'resource' attribute only
    readable by root (bnc#1012382).

  - libnvdimm, pfn: make 'resource' attribute only readable
    by root (FATE#319858).

  - lib/ratelimit.c: use deferred printk() version
    (bsc#979928).

  - locking/lockdep: Add nest_lock integrity test
    (bnc#1012382).

  - lpfc: tie in to new dev_loss_tmo interface in nvme
    transport (bsc#1041873).

  - mac80211: agg-tx: call drv_wake_tx_queue in proper
    context (bsc#1031717).

  - mac80211: do not compare TKIP TX MIC key in reinstall
    prevention (bsc#1066472).

  - mac80211: do not send SMPS action frame in AP mode when
    not needed (bsc#1031717).

  - mac80211: Fix addition of mesh configuration element
    (git-fixes).

  - mac80211: Fix BW upgrade for TDLS peers (bsc#1031717).

  - mac80211: fix mgmt-tx abort cookie and leak
    (bsc#1031717).

  - mac80211: fix power saving clients handling in iwlwifi
    (bnc#1012382).

  - mac80211_hwsim: check HWSIM_ATTR_RADIO_NAME length
    (bnc#1012382).

  - mac80211_hwsim: Fix memory leak in hwsim_new_radio_nl()
    (bsc#1031717).

  - mac80211: Remove invalid flag operations in mesh TSF
    synchronization (bnc#1012382).

  - mac80211: Remove unused 'beaconint_us' variable
    (bsc#1031717).

  - mac80211: Remove unused 'i' variable (bsc#1031717).

  - mac80211: Remove unused 'len' variable (bsc#1031717).

  - mac80211: Remove unused 'rates_idx' variable
    (bsc#1031717).

  - mac80211: Remove unused 'sband' and 'local' variables
    (bsc#1031717).

  - mac80211: Remove unused 'struct ieee80211_rx_status' ptr
    (bsc#1031717).

  - mac80211: Suppress NEW_PEER_CANDIDATE event if no room
    (bnc#1012382).

  - mac80211: TDLS: always downgrade invalid chandefs
    (bsc#1031717).

  - mac80211: TDLS: change BW calculation for WIDER_BW peers
    (bsc#1031717).

  - mac80211: use constant time comparison with keys
    (bsc#1066471).

  - md/linear: shutup lockdep warnning (FATE#321488
    bnc#1012382 bsc#1042977).

  - media: au0828: fix RC_CORE dependency (bsc#1031717).

  - media: Do not do DMA on stack for firmware upload in the
    AS102 driver (bnc#1012382).

  - media: em28xx: calculate left volume level correctly
    (bsc#1031717).

  - media: mceusb: fix memory leaks in error path
    (bsc#1031717).

  - media: rc: check for integer overflow (bnc#1012382).

  - media: v4l2-ctrl: Fix flags field on Control events
    (bnc#1012382).

  - mei: return error on notification request to a
    disconnected client (bnc#1012382).

  - memremap: add scheduling point to devm_memremap_pages
    (bnc#1057079).

  - mfd: ab8500-sysctrl: Handle probe deferral
    (bnc#1012382).

  - mfd: axp20x: Fix axp288 PEK_DBR and PEK_DBF irqs being
    swapped (bnc#1012382).

  - mips: AR7: Defer registration of GPIO (bnc#1012382).

  - mips: AR7: Ensure that serial ports are properly set up
    (bnc#1012382).

  - mips: BCM47XX: Fix LED inversion for WRT54GSv1
    (bnc#1012382).

  - mips: End asm function prologue macros with .insn
    (bnc#1012382).

  - mips: Fix an n32 core file generation regset support
    regression (bnc#1012382).

  - mips: Fix CM region target definitions (bnc#1012382).

  - mips: Fix race on setting and getting cpu_online_mask
    (bnc#1012382).

  - mips: init: Ensure bootmem does not corrupt reserved
    memory (bnc#1012382).

  - mips: init: Ensure reserved memory regions are not added
    to bootmem (bnc#1012382).

  - mips: math-emu: Remove pr_err() calls from fpu_emu()
    (bnc#1012382).

  - mips: microMIPS: Fix incorrect mask in insn_table_MM
    (bnc#1012382).

  - mips: Netlogic: Exclude netlogic,xlp-pic code from XLR
    builds (bnc#1012382).

  - mips: ralink: Fix MT7628 pinmux (bnc#1012382).

  - mips: ralink: Fix typo in mt7628 pinmux function
    (bnc#1012382).

  - mips: SMP: Fix deadlock & online race (bnc#1012382).

  - mips: SMP: Use a completion event to signal CPU up
    (bnc#1012382).

  - misc: panel: properly restore atomic counter on error
    path (bnc#1012382).

  - mmc: block: return error on failed mmc_blk_get()
    (bsc#1031717).

  - mmc: core: add driver strength selection when selecting
    hs400es (bsc#1069721).

  - mmc: core: Fix access to HS400-ES devices (bsc#1031717).

  - mmc: core/mmci: restore pre/post_req behaviour
    (bsc#1031717).

  - mmc: dw_mmc: Fix the DTO timeout calculation
    (bsc#1069721).

  - mm: check the return value of lookup_page_ext for all
    call sites (bnc#1068982).

  - mmc: host: omap_hsmmc: avoid possible overflow of
    timeout value (bsc#1031717).

  - mmc: host: omap_hsmmc: checking for NULL instead of
    IS_ERR() (bsc#1031717).

  - mmc: mediatek: Fixed size in dma_free_coherent
    (bsc#1031717).

  - mmc: s3cmci: include linux/interrupt.h for
    tasklet_struct (bnc#1012382).

  - mmc: sd: limit SD card power limit according to cards
    capabilities (bsc#1031717).

  - mm: distinguish CMA and MOVABLE isolation in
    has_unmovable_pages (bnc#1051406).

  - mm: drop migrate type checks from has_unmovable_pages
    (bnc#1051406).

  - mm, hwpoison: fixup 'mm: check the return value of
    lookup_page_ext for all call sites' (bnc#1012382).

  - mm/madvise.c: fix freeing of locked page with MADV_FREE
    (bnc#1069152).

  - mm/madvise.c: fix madvise() infinite loop under special
    circumstances (bnc#1070964).

  - mm, memory_hotplug: add scheduling point to __add_pages
    (bnc#1057079).

  - mm, memory_hotplug: do not fail offlining too early
    (bnc#1051406).

  - mm, memory_hotplug: remove timeout from __offline_memory
    (bnc#1051406).

  - mm, page_alloc: add scheduling point to memmap_init_zone
    (bnc#1057079).

  - mm/page_alloc.c: broken deferred calculation
    (bnc#1068980).

  - mm, page_alloc: fix potential false positive in
    __zone_watermark_ok (Git-fixes, bsc#1068978).

  - mm/page_ext.c: check if page_ext is not prepared
    (bnc#1068982).

  - mm/page_owner: avoid NULL pointer dereference
    (bnc#1068982).

  - mm/pagewalk.c: report holes in hugetlb ranges
    (bnc#1012382).

  - mm, sparse: do not swamp log with huge vmemmap
    allocation failures (bnc#1047901).

  - net: 3com: typhoon: typhoon_init_one: fix incorrect
    return values (bnc#1012382).

  - net: 3com: typhoon: typhoon_init_one: make return values
    more specific (bnc#1012382).

  - net/9p: Switch to wait_event_killable() (bnc#1012382).

  - net: Allow IP_MULTICAST_IF to set index to L3 slave
    (bnc#1012382).

  - net: cdc_ether: fix divide by 0 on bad descriptors
    (bnc#1012382).

  - net: cdc_ncm: GetNtbFormat endian fix (git-fixes).

  - net: dsa: select NET_SWITCHDEV (bnc#1012382).

  - net: emac: Fix napi poll list corruption (bnc#1012382).

  - netfilter/ipvs: clear ipvs_property flag when SKB net
    namespace changed (bnc#1012382).

  - netfilter: nf_ct_expect: Change __nf_ct_expect_check()
    return value (bnc#1012382).

  - netfilter: nf_tables: fix oob access (bnc#1012382).

  - netfilter: nft_meta: deal with PACKET_LOOPBACK in netdev
    family (bnc#1012382).

  - netfilter: nft_queue: use raw_smp_processor_id()
    (bnc#1012382).

  - net: ibm: ibmvnic: constify vio_device_id (fate#323285).

  - net: ixgbe: Use new IXGBE_FLAG2_ROOT_RELAXED_ORDERING
    flag (bsc#1056652).

  - net/mlx4_core: Fix VF overwrite of module param which
    disables DMFS on new probed PFs (FATE#321685 FATE#321686
    FATE#321687 bnc#1012382 bsc#1015336 bsc#1015337
    bsc#1015340).

  - net/mlx4_en: fix overflow in mlx4_en_init_timestamp()
    (FATE#321685 FATE#321686 FATE#321687 bnc#1012382
    bsc#1015336 bsc#1015337 bsc#1015340).

  - net/mlx5: Delay events till mlx5 interface's add
    complete for pci resume (bsc#1015342 FATE#321688
    bsc#1015343 FATE#321689).

  - net/mlx5e: Increase Striding RQ minimum size limit to 4
    multi-packet WQEs (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5: Fix health work queue spin lock to IRQ safe
    (bsc#1015342).

  - net/mlx5: Loop over temp list to release delay events
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net: mvneta: fix handling of the Tx descriptor counter
    (fate#319899).

  - net: mvpp2: release reference to txq_cpu[] entry after
    unmapping (bnc#1012382 bsc#1032150).

  - net: qmi_wwan: fix divide by 0 on bad descriptors
    (bnc#1012382).

  - net/sctp: Always set scope_id in sctp_inet6_skb_msgname
    (bnc#1012382).

  - net: Set sk_prot_creator when cloning sockets to the
    right proto (bnc#1012382).

  - net/smc: dev_put for netdev after usage of
    ib_query_gid() (bsc#1066812).

  - net: thunderx: Fix TCP/UDP checksum offload for IPv4
    pkts (bsc#1069583).

  - net: thunderx: Fix TCP/UDP checksum offload for IPv6
    pkts (bsc#1069583).

  - net/unix: do not show information about sockets from
    other namespaces (bnc#1012382).

  - netvsc: use refcount_t for keeping track of sub channels
    (bsc#1062835).

  - nfc: fix device-allocation error return (bnc#1012382).

  - nfsd/callback: Cleanup callback cred on shutdown
    (bnc#1012382).

  - nfsd: deal with revoked delegations appropriately
    (bnc#1012382).

  - nfs: Do not disconnect open-owner on NFS4ERR_BAD_SEQID
    (bsc#989261).

  - nfs: Fix typo in nomigration mount option (bnc#1012382).

  - nfs: Fix ugly referral attributes (bnc#1012382).

  - nilfs2: fix race condition that causes file system
    corruption (bnc#1012382).

  - nl80211: Define policy for packet pattern attributes
    (bnc#1012382).

  - nvme: add duplicate_connect option (bsc#1067734).

  - nvme: add helper to compare options to controller
    (bsc#1067734).

  - nvme: add transport SGL definitions (bsc#1057820).

  - nvme: allow controller RESETTING to RECONNECTING
    transition (bsc#1037838).

  - nvme-fabrics: Allow 0 as KATO value (bsc#1067734).

  - nvme-fabrics: kABI fix for duplicate_connect option
    (bsc#1067734).

  - nvme-fc: add a dev_loss_tmo field to the remoteport
    (bsc#1037838).

  - nvme-fc: add dev_loss_tmo timeout and remoteport resume
    support (bsc#1037838).

  - nvme-fc: add support for duplicate_connect option
    (bsc#1067734).

  - nvme-fc: add uevent for auto-connect (bsc#1037838).

  - nvme-fc: change ctlr state assignments during
    reset/reconnect (bsc#1037838).

  - nvme-fc: check connectivity before initiating reconnects
    (bsc#1037838).

  - nvme-fc: correct io termination handling (bsc#1067734).

  - nvme-fc: correct io timeout behavior (bsc#1067734).

  - nvme-fc: create fc class and transport device
    (bsc#1037838).

  - nvme-fc: decouple ns references from lldd references
    (bsc#1067734).

  - nvme-fc: fix iowait hang (bsc#1052384).

  - nvme-fc: fix localport resume using stale values
    (bsc#1067734).

  - nvme-fcloop: fix port deletes and callbacks
    (bsc#1037838).

  - nvme-fc: move remote port get/put/free location
    (bsc#1037838).

  - nvme-fc: on lldd/transport io error, terminate
    association (bsc#1042268).

  - nvme-fc: Reattach to localports on re-registration
    (bsc#1052384).

  - nvme-fc: remove NVME_FC_MAX_SEGMENTS (bsc#1067734).

  - nvme-fc: remove unused 'queue_size' field (bsc#1042268).

  - nvme-fc: retry initial controller connections 3 times
    (bsc#1067734).

  - nvme-fc: use transport-specific sgl format
    (bsc#1057820).

  - nvme: Fix memory order on async queue deletion
    (bnc#1012382).

  - nvme: fix the definition of the doorbell buffer config
    support bit (bsc#1066812).

  - nvme-rdma: add support for duplicate_connect option
    (bsc#1067734).

  - nvme/rdma: Kick admin queue when a connection is going
    down (bsc#1059639).

  - nvmet-fc: correct ref counting error when deferred rcv
    used (bsc#1067734).

  - nvmet-fc: fix failing max io queue connections
    (bsc#1067734).

  - nvmet-fc: on port remove call put outside lock
    (bsc#1067734).

  - nvmet-fc: simplify sg list handling (bsc#1052384).

  - nvmet: Fix fatal_err_work deadlock (bsc#1063349).

  - ocfs2: fstrim: Fix start offset of first cluster group
    during fstrim (bnc#1012382).

  - ocfs2: should wait dio before inode lock in
    ocfs2_setattr() (bnc#1012382).

  - packet: avoid panic in packet_getsockopt()
    (bnc#1012382).

  - packet: only test po->has_vnet_hdr once in packet_snd
    (bnc#1012382).

  - parisc: Avoid trashing sr2 and sr3 in LWS code
    (bnc#1012382).

  - parisc: Fix double-word compare and exchange in LWS code
    on 32-bit kernels (bnc#1012382).

  - parisc: Fix validity check of pointer size argument in
    new CAS implementation (bnc#1012382).

  - pci: Apply Cavium ThunderX ACS quirk to more Root Ports
    (bsc#1069250).

  - pci: Apply _HPX settings only to relevant devices
    (bnc#1012382).

  - pci: Enable Relaxed Ordering for Hisilicon Hip07 chip
    (bsc#1056652).

  - pci: Mark Cavium CN8xxx to avoid bus reset
    (bsc#1069250).

  - pci: Set Cavium ACS capability quirk flags to assert
    RR/CR/SV/UF (bsc#1069250).

  - percpu: make this_cpu_generic_read() atomic w.r.t.
    interrupts (bnc#1012382).

  - perf tools: Fix build failure on perl script context
    (bnc#1012382).

  - perf tools: Only increase index if perf_evsel__new_idx()
    succeeds (bnc#1012382).

  - perf/x86/intel/bts: Fix exclusive event reference leak
    (git-fixes d2878d642a4ed).

  - phy: increase size of MII_BUS_ID_SIZE and bus_id
    (bnc#1012382).

  - pkcs#7: fix uninitialized boolean 'want' (bnc#1012382).

  - pkcs7: Prevent NULL pointer dereference, since sinfo is
    not always set (bnc#1012382).

  - platform/x86: acer-wmi: setup accelerometer when ACPI
    device was found (bsc#1031717).

  - platform/x86: hp-wmi: Do not shadow error values
    (bnc#1012382).

  - platform/x86: hp-wmi: Fix detection for dock and tablet
    mode (bnc#1012382).

  - platform/x86: hp-wmi: Fix error value for
    hp_wmi_tablet_state (bnc#1012382).

  - platform/x86: intel_mid_thermal: Fix module autoload
    (bnc#1012382).

  - platform/x86: sony-laptop: Fix error handling in
    sony_nc_setup_rfkill() (bsc#1031717).

  - pm / OPP: Add missing of_node_put(np) (bnc#1012382).

  - power: bq27xxx_battery: Fix bq27541 AveragePower
    register address (bsc#1031717).

  - power: bq27xxx: fix reading for bq27000 and bq27010
    (bsc#1031717).

  - powercap: Fix an error code in powercap_register_zone()
    (bsc#1031717).

  - power: ipaq-micro-battery: freeing the wrong variable
    (bsc#1031717).

  - powerpc/64: Fix race condition in setting lock bit in
    idle/wakeup code (bsc#1066223).

  - powerpc/64s/hash: Allow MAP_FIXED allocations to cross
    128TB boundary (bsc#1070169).

  - powerpc/64s/hash: Fix 128TB-512TB virtual address
    boundary case allocation (bsc#1070169).

  - powerpc/64s/hash: Fix 512T hint detection to use >= 128T
    (bsc#1070169).

  - powerpc/64s/hash: Fix fork() with 512TB process address
    space (bsc#1070169).

  - powerpc/64s/slice: Use addr limit when computing slice
    mask (bsc#1070169).

  - powerpc/bpf/jit: Disable classic BPF JIT on ppc64le
    (bsc#1066223).

  - powerpc/corenet: explicitly disable the SDHC controller
    on kmcoge4 (bnc#1012382).

  - powerpc: Correct instruction code for xxlor instruction
    (bsc#1066223).

  - powerpc: Fix VSX enabling/flushing to also test MSR_FP
    and MSR_VEC (bsc#1066223).

  - powerpc/hotplug: Improve responsiveness of hotplug
    change (FATE#322022, bsc#1067906).

  - powerpc/mm: Fix check of multiple 16G pages from device
    tree (bsc#1066223).

  - powerpc/mm: Fix virt_addr_valid() etc. on 64-bit hash
    (bsc#1066223).

  - powerpc/mm/hash64: Fix subpage protection with 4K HPTE
    config (bsc#1010201, bsc#1066223).

  - powerpc/mm/hash: Free the subpage_prot_table correctly
    (bsc#1066223).

  - powerpc/numa: Fix multiple bugs in memory_hotplug_max()
    (bsc#1066223).

  - powerpc/numa: Fix whitespace in
    hot_add_drconf_memory_max() (bsc#1066223).

  - powerpc/opal: Fix EBUSY bug in acquiring tokens
    (bsc#1066223).

  - powerpc/powernv/ioda: Fix endianness when reading TCEs
    (bsc#1066223).

  - powerpc/powernv: Make opal_event_shutdown() callable
    from IRQ context (bsc#1066223).

  - powerpc/pseries/vio: Dispose of virq mapping on vdevice
    unregister (bsc#1067888).

  - powerpc/signal: Properly handle return value from
    uprobe_deny_signal() (bsc#1066223).

  - powerpc/sysrq: Fix oops whem ppmu is not registered
    (bsc#1066223).

  - powerpc/vphn: Fix numa update end-loop bug (FATE#322022,
    bsc#1067906).

  - powerpc/vphn: Improve recognition of PRRN/VPHN
    (FATE#322022, bsc#1067906).

  - powerpc/vphn: Update CPU topology when VPHN enabled
    (FATE#322022, bsc#1067906).

  - power: supply: bq27xxx_battery: Fix register map for
    BQ27510 and BQ27520 ('bsc#1069270').

  - power: supply: isp1704: Fix unchecked return value of
    devm_kzalloc (bsc#1031717).

  - power: supply: lp8788: prevent out of bounds array
    access (bsc#1031717).

  - power_supply: tps65217-charger: Fix NULL deref during
    property export (bsc#1031717).

  - ppp: fix race in ppp device destruction (bnc#1012382).

  - printk/console: Always disable boot consoles that use
    init memory before it is freed (bsc#1063026).

  - printk/console: Enhance the check for consoles using
    init memory (bsc#1063026).

  - printk: include <asm/sections.h> instead of
    <asm-generic/sections.h> (bsc#1063026).

  - printk: Make sure to wake up printk kthread from irq
    work for pending output (bnc#744692, bnc#789311).

  - printk: only unregister boot consoles when necessary
    (bsc#1063026).

  - qla2xxx: Fix cable swap (bsc#1043017).

  - qla2xxx: Fix notify ack without timeout handling
    (bsc#1043017).

  - qla2xxx: Fix re-login for Nport Handle in use
    (bsc#1043017).

  - qla2xxx: fix stale memory access (bsc#1043017).

  - qla2xxx: Login state machine stuck at GPDB
    (bsc#1043017).

  - qla2xxx: Recheck session state after RSCN (bsc#1043017).

  - qla2xxx: relogin is being triggered too fast
    (bsc#1043017).

  - qla2xxx: Retry switch command on timed out
    (bsc#1043017).

  - qla2xxx: Serialize gpnid (bsc#1043017).

  - quota: Check for register_shrinker() failure
    (bsc#1070404).

  - r8169: Do not increment tx_dropped in TX ring cleaning
    (bsc#1031717).

  - rbd: set discard_alignment to zero (bsc#1064320).

  - rbd: use GFP_NOIO for parent stat and data requests
    (bnc#1012382).

  - rcu: Allow for page faults in NMI handlers
    (bnc#1012382).

  - rdma/uverbs: Prevent leak of reserved field (bsc#1022595
    FATE#322350).

  - rds: rdma: return appropriate error on rdma map failures
    (bnc#1012382).

  - regulator: core: Limit propagation of parent voltage
    count and list (bsc#1070145).

  - regulator: fan53555: fix I2C device ids (bnc#1012382).

  - Revert 'bpf: one perf event close won't free bpf program
    attached by another perf event' (kabi).

  - Revert 'bsg-lib: do not free job in bsg_prepare_job'
    (bnc#1012382).

  - Revert 'crypto: xts - Add ECB dependency' (bnc#1012382).

  - Revert 'drm: bridge: add DT bindings for TI ths8135'
    (bnc#1012382).

  - Revert 'keys: Fix race between updating and finding a
    negative key' (kabi).

  - Revert 'phy: increase size of MII_BUS_ID_SIZE and
    bus_id' (kabi).

  - Revert 'sctp: do not peel off an assoc from one netns to
    another one' (bnc#1012382).

  - Revert 'tty: goldfish: Fix a parameter of a call to
    free_irq' (bnc#1012382).

  - Revert 'uapi: fix linux/rds.h userspace compilation
    errors' (bnc#1012382).

  - rpm/kernel-binary.spec.in: add the kernel-binary
    dependencies to kernel-binary-base (bsc#1060333).

  - rpm/kernel-binary.spec.in: Correct supplements for
    recent SLE products (bsc#1067494)

  - rpm/kernel-binary.spec.in: only rewrite modules.dep if
    non-zero in size (bsc#1056979).

  - rpm/package-descriptions :

  - rtc: ds1307: Fix relying on reset value for weekday
    (bsc#1031717).

  - rtc: ds1374: wdt: Fix issue with timeout scaling from
    secs to wdt ticks (bsc#1031717).

  - rtc: ds1374: wdt: Fix stop/start ioctl always returning
    -EINVAL (bsc#1031717).

  - rtc: rtc-nuc900: fix loop timeout test (bsc#1031717).

  - rtc: sa1100: fix unbalanced
    clk_prepare_enable/clk_disable_unprepare (bsc#1031717).

  - rtlwifi: fix uninitialized rtlhal->last_suspend_sec time
    (bnc#1012382).

  - rtlwifi: rtl8192ee: Fix memory leak when loading
    firmware (bnc#1012382).

  - rtlwifi: rtl8821ae: Fix connection lost problem
    (bnc#1012382).

  - rtlwifi: rtl8821ae: Fix HW_VAR_NAV_UPPER operation
    (bsc#1031717).

  - s390/dasd: check for device error pointer within state
    change interrupts (bnc#1012382).

  - s390/disassembler: add missing end marker for e7 table
    (bnc#1012382).

  - s390/disassembler: correct disassembly lines alignment
    (bsc#1070825).

  - s390/disassembler: increase show_code buffer size
    (bnc#1070825, LTC#161577).

  - s390/disassembler: increase show_code buffer size
    (LTC#161577 bnc#1012382 bnc#1070825).

  - s390: fix transactional execution control register
    handling (bnc#1012382).

  - s390/kbuild: enable modversions for symbols exported
    from asm (bnc#1012382).

  - s390/mm: fix write access check in gup_huge_pmd()
    (bnc#1066974, LTC#160551).

  - s390/qeth: allow hsuid configuration in DOWN state
    (bnc#1070825, LTC#161871).

  - s390/qeth: issue STARTLAN as first IPA command
    (bnc#1012382).

  - s390/qeth: use ip_lock for hsuid configuration
    (bnc#1070825, LTC#161871).

  - s390/runtime instrumention: fix possible memory
    corruption (bnc#1012382).

  - sched/autogroup: Fix autogroup_move_group() to never
    skip sched_move_task() (bnc#1012382).

  - sched: Make resched_cpu() unconditional (bnc#1012382).

  - sched/rt: Simplify the IPI based RT balancing logic
    (bnc#1012382).

  - scsi: aacraid: Check for PCI state of device in a
    generic way (bsc#1022607, FATE#321673).

  - scsi: aacraid: Fix controller initialization failure
    (FATE#320140).

  - scsi: bfa: fix access to bfad_im_port_s (bsc#1065101).

  - scsi: check for device state in __scsi_remove_target()
    (bsc#1072589).

  - scsi_devinfo: cleanly zero-pad devinfo strings
    (bsc#1062941).

  - scsi: fcoe: move fcoe_interface_remove() out of
    fcoe_interface_cleanup() (bsc#1039542).

  - scsi: fcoe: open-code fcoe_destroy_work() for
    NETDEV_UNREGISTER (bsc#1039542).

  - scsi: fcoe: separate out fcoe_vport_remove()
    (bsc#1039542).

  - scsi: ipr: Fix scsi-mq lockdep issue (bsc#1066213).

  - scsi: ipr: Set no_report_opcodes for RAID arrays
    (bsc#1066213).

  - scsi: libiscsi: fix shifting of DID_REQUEUE host byte
    (bsc#1056003).

  - scsi: lpfc: Add Buffer to Buffer credit recovery support
    (bsc#1052384).

  - scsi: lpfc: Add changes to assist in NVMET debugging
    (bsc#1041873).

  - scsi: lpfc: Add nvme initiator devloss support
    (bsc#1041873).

  - scsi: lpfc: Adjust default value of lpfc_nvmet_mrq
    (bsc#1067735).

  - scsi: lpfc: Break up IO ctx list into a separate get and
    put list (bsc#1045404).

  - scsi: lpfc: change version to 11.4.0.4 (bsc#1067735).

  - scsi: lpfc: convert info messages to standard messages
    (bsc#1052384).

  - scsi: lpfc: Correct driver deregistrations with host
    nvme transport (bsc#1067735).

  - scsi: lpfc: Correct issues with FAWWN and FDISCs
    (bsc#1052384).

  - scsi: lpfc: correct nvme sg segment count check
    (bsc#1067735).

  - scsi: lpfc: correct port registrations with nvme_fc
    (bsc#1067735).

  - scsi: lpfc: Correct return error codes to align with
    nvme_fc transport (bsc#1052384).

  - scsi: lpfc: Disable NPIV support if NVME is enabled
    (bsc#1067735).

  - scsi: lpfc: Driver fails to detect direct attach storage
    array (bsc#1067735).

  - scsi: lpfc: Expand WQE capability of every NVME hardware
    queue (bsc#1067735).

  - scsi: lpfc: Extend RDP support (bsc#1067735).

  - scsi: lpfc: Fix a precedence bug in
    lpfc_nvme_io_cmd_wqe_cmpl() (bsc#1056587).

  - scsi: lpfc: Fix bad sgl reposting after 2nd adapter
    reset (bsc#1052384).

  - scsi: lpfc: fix build issue if NVME_FC_TARGET is not
    defined (bsc#1040073).

  - scsi: lpfc: Fix counters so outstandng NVME IO count is
    accurate (bsc#1041873).

  - scsi: lpfc: Fix crash after bad bar setup on driver
    attachment (bsc#1067735).

  - scsi: lpfc: Fix crash during driver unload with running
    nvme traffic (bsc#1067735).

  - scsi: lpfc: Fix crash in lpfc_nvme_fcp_io_submit during
    LIP (bsc#1067735).

  - scsi: lpfc: Fix crash in lpfc nvmet when fc port is
    reset (bsc#1052384).

  - scsi: lpfc: Fix crash receiving ELS while detaching
    driver (bsc#1067735).

  - scsi: lpfc: Fix display for debugfs queInfo
    (bsc#1067735).

  - scsi: lpfc: Fix driver handling of nvme resources during
    unload (bsc#1067735).

  - scsi: lpfc: Fix duplicate NVME rport entries and
    namespaces (bsc#1052384).

  - scsi: lpfc: Fix FCP hba_wqidx assignment (bsc#1067735).

  - scsi: lpfc: Fix handling of FCP and NVME FC4 types in
    Pt2Pt topology (bsc#1052384).

  - scsi: lpfc: Fix hard lock up NMI in els timeout handling
    (bsc#1067735).

  - scsi: lpfc: fix 'integer constant too large' error on
    32bit archs (bsc#1052384).

  - scsi: lpfc: Fix loop mode target discovery
    (bsc#1052384).

  - scsi: lpfc: Fix lpfc nvme host rejecting IO with Not
    Ready message (bsc#1067735).

  - scsi: lpfc: Fix Lun Priority level shown as NA
    (bsc#1041873).

  - scsi: lpfc: Fix ndlp ref count for pt2pt mode issue RSCN
    (bsc#1067735).

  - scsi: lpfc: Fix NVME LS abort_xri (bsc#1067735).

  - scsi: lpfc: Fix nvme port role handling in sysfs and
    debugfs handlers (bsc#1041873).

  - scsi: lpfc: Fix NVME PRLI handling during RSCN
    (bsc#1052384).

  - scsi: lpfc: Fix nvme target failure after 2nd adapter
    reset (bsc#1052384).

  - scsi: lpfc: Fix nvmet node ref count handling
    (bsc#1041873).

  - scsi: lpfc: Fix oops if nvmet_fc_register_targetport
    fails (bsc#1067735).

  - scsi: lpfc: Fix oops of nvme host during driver unload
    (bsc#1067735).

  - scsi: lpfc: Fix oops when NVME Target is discovered in a
    nonNVME environment.

  - scsi: lpfc: fix pci hot plug crash in list_add call
    (bsc#1067735).

  - scsi: lpfc: fix pci hot plug crash in timer management
    routines (bsc#1067735).

  - scsi: lpfc: Fix plogi collision that causes illegal
    state transition (bsc#1052384).

  - scsi: lpfc: Fix Port going offline after multiple resets
    (bsc#1041873).

  - scsi: lpfc: Fix PRLI retry handling when target rejects
    it (bsc#1041873).

  - scsi: lpfc: Fix rediscovery on switch blade pull
    (bsc#1052384).

  - scsi: lpfc: Fix relative offset error on large nvmet
    target ios (bsc#1052384).

  - scsi: lpfc: Fix return value of board_mode store routine
    in case of online failure (bsc#1041873).

  - scsi: lpfc: Fix secure firmware updates (bsc#1067735).

  - scsi: lpfc: Fix System panic after loading the driver
    (bsc#1041873).

  - scsi: lpfc: Fix transition nvme-i rport handling to
    nport only (bsc#1041873).

  - scsi: lpfc: Fix vports not logging into target
    (bsc#1041873).

  - scsi: lpfc: Fix warning messages when NVME_TARGET_FC not
    defined (bsc#1067735).

  - scsi: lpfc: FLOGI failures are reported when connected
    to a private loop (bsc#1067735).

  - scsi: lpfc: Handle XRI_ABORTED_CQE in soft IRQ
    (bsc#1067735).

  - scsi: lpfc: Limit amount of work processed in IRQ
    (bsc#1052384).

  - scsi: lpfc: Linux LPFC driver does not process all RSCNs
    (bsc#1067735).

  - scsi: lpfc: lpfc version bump 11.4.0.3 (bsc#1052384).

  - scsi: lpfc: Make ktime sampling more accurate
    (bsc#1067735).

  - scsi: lpfc: Move CQ processing to a soft IRQ
    (bsc#1067735).

  - scsi: lpfc: NULL pointer dereference when log_verbose is
    set to 0xffffffff (bsc#1041873).

  - scsi: lpfc: PLOGI failures during NPIV testing
    (bsc#1067735).

  - scsi: lpfc: Raise maximum NVME sg list size for 256
    elements (bsc#1067735).

  - scsi: lpfc: Reduce log spew on controller reconnects
    (bsc#1067735).

  - scsi: lpfc: remove console log clutter (bsc#1052384).

  - scsi: lpfc: Revise NVME module parameter descriptions
    for better clarity (bsc#1067735).

  - scsi: lpfc: Set missing abort context (bsc#1067735).

  - scsi: lpfc: small sg cnt cleanup (bsc#1067735).

  - scsi: lpfc: spin_lock_irq() is not nestable
    (bsc#1045404).

  - scsi: lpfc: update driver version to 11.4.0.5
    (bsc#1067735).

  - scsi: lpfc: update to revision to 11.4.0.0
    (bsc#1041873).

  - scsi: megaraid_sas: mismatch of allocated MFI frame size
    and length exposed in MFI MPT pass through command
    (bsc#1066767).

  - scsi: qla2xxx: Cleanup debug message IDs (bsc#1043017).

  - scsi: qla2xxx: Correction to vha->vref_count timeout
    (bsc#1066812).

  - scsi: qla2xxx: Fix name server relogin (bsc#1043017).

  - scsi: qla2xxx: Fix path recovery (bsc#1043017).

  - scsi: qla2xxx: Initialize Work element before requesting
    IRQs (bsc#1019675,FATE#321701).

  - scsi: qla2xxx: Replace usage of spin_lock with
    spin_lock_irqsave (bsc#1043017).

  - scsi: qla2xxx: Retain loop test for fwdump length
    exceeding buffer length (bsc#1043017).

  - scsi: qla2xxx: Turn on FW option for exchange check
    (bsc#1043017).

  - scsi: qla2xxx: Use BIT_6 to acquire FAWWPN from switch
    (bsc#1066812).

  - scsi: qla2xxx: Use fabric name for Get Port Speed
    command (bsc#1066812).

  - scsi: qla2xxx: Use flag PFLG_DISCONNECTED (bsc#1043017).

  - scsi: reset wait for IO completion (bsc#996376).

  - scsi: scsi_devinfo: fixup string compare (bsc#1062941).
    updated
    patches.fixes/scsi_devinfo-fixup-string-compare.patch to
    the version merged upstream.

  - scsi: scsi_devinfo: handle non-terminated strings
    (bsc#1062941).

  - scsi: scsi_dh_emc: return success in
    clariion_std_inquiry() (bnc#1012382).

  - scsi: sd_zbc: Fix sd_zbc_read_zoned_characteristics()
    (bsc#1066812).

  - scsi: sg: close race condition in
    sg_remove_sfp_usercontext() (bsc#1064206).

  - scsi: sg: do not return bogus Sg_requests (bsc#1064206).

  - scsi: sg: only check for dxfer_len greater than 256M
    (bsc#1064206).

  - scsi: sg: Re-fix off by one in sg_fill_request_table()
    (bnc#1012382).

  - scsi: ufs: add capability to keep auto bkops always
    enabled (bnc#1012382).

  - scsi: ufs-qcom: Fix module autoload (bnc#1012382).

  - scsi: zfcp: fix erp_action use-before-initialize in REC
    action trace (bnc#1012382).

  - sctp: add the missing sock_owned_by_user check in
    sctp_icmp_redirect (bnc#1012382).

  - sctp: do not peel off an assoc from one netns to another
    one (bnc#1012382).

  - sctp: potential read out of bounds in
    sctp_ulpevent_type_enabled() (bnc#1012382).

  - sctp: reset owner sk for data chunks on out queues when
    migrating a sock (bnc#1012382).

  - security/keys: add CONFIG_KEYS_COMPAT to Kconfig
    (bnc#1012382).

  - selftests: firmware: add empty string and async tests
    (bnc#1012382).

  - selftests: firmware: send expected errors to /dev/null
    (bnc#1012382).

  - serial: 8250_fintek: Fix rs485 disablement on invalid
    ioctl() (bsc#1031717).

  - serial: 8250_uniphier: fix serial port index in private
    data (bsc#1031717).

  - serial: Fix serial console on SNI RM400 machines
    (bsc#1031717).

  - serial: omap: Fix EFR write on RTS deassertion
    (bnc#1012382).

  - serial: Remove unused port type (bsc#1066045).

  - serial: sh-sci: Fix register offsets for the IRDA serial
    port (bnc#1012382).

  - slub: do not merge cache if slub_debug contains a
    never-merge flag (bnc#1012382).

  - smb3: Validate negotiate request must always be signed
    (bsc#1064597).

  - smb: fix leak of validate negotiate info response buffer
    (bsc#1064597).

  - smb: fix validate negotiate info uninitialised memory
    use (bsc#1064597).

  - sparc64: Migrate hvcons irq to panicked cpu
    (bnc#1012382).

  - spi: SPI_FSL_DSPI should depend on HAS_DMA
    (bnc#1012382).

  - spi: uapi: spidev: add missing ioctl header
    (bnc#1012382).

  - staging: iio: cdc: fix improper return value
    (bnc#1012382).

  - staging: lustre: hsm: stack overrun in
    hai_dump_data_field (bnc#1012382).

  - staging: lustre: llite: do not invoke direct_IO for the
    EOF case (bnc#1012382).

  - staging: lustre: ptlrpc: skip lock if export failed
    (bnc#1012382).

  - staging: r8712u: Fix Sparse warning in rtl871x_xmit.c
    (bnc#1012382).

  - staging: rtl8188eu: fix incorrect ERROR tags from logs
    (bnc#1012382).

  - staging: rtl8712: fixed little endian problem
    (bnc#1012382).

  - staging: rtl8712u: Fix endian settings for structs
    describing network packets (bnc#1012382).

  - sunrpc: Fix tracepoint storage issues with svc_recv and
    svc_rqst_status (bnc#1012382).

  - supported.conf: Support spidev (bsc#1066696)

  - sysctl: add unsigned int range support (FATE#323821)

  - target: fix ALUA state file path truncation
    (bsc#1064606).

  - target: Fix node_acl demo-mode + uncached dynamic
    shutdown regression (bnc#1012382).

  - target: fix PR state file path truncation (bsc#1064606).

  - target: Fix QUEUE_FULL + SCSI task attribute handling
    (bnc#1012382).

  - target/iscsi: Fix unsolicited data seq_end_offset
    calculation (bnc#1012382 bsc#1036489).

  - target/rbd: handle zero length UNMAP requests early
    (bsc#1064320).

  - target/rbd: use target_configure_unmap_from_queue()
    helper (bsc#1064320).

  - tcp/dccp: fix ireq->opt races (bnc#1012382).

  - tcp/dccp: fix lockdep splat in inet_csk_route_req()
    (bnc#1012382).

  - tcp/dccp: fix other lockdep splats accessing ireq_opt
    (bnc#1012382).

  - tcp: do not mangle skb->cb[] in tcp_make_synack()
    (bnc#1012382).

  - tcp: fix tcp_mtu_probe() vs highest_sack (bnc#1012382).

  - test: firmware_class: report errors properly on failure
    (bnc#1012382).

  - test_sysctl: add dedicated proc sysctl test driver
    (FATE#323821)

  - test_sysctl: add generic script to expand on tests
    (FATE#323821)

  - test_sysctl: add simple proc_dointvec() case
    (FATE#323821).

  - test_sysctl: add simple proc_douintvec() case
    (FATE#323821).

  - test_sysctl: fix sysctl.sh by making it executable
    (FATE#323821).

  - test_sysctl: test against int proc_dointvec() array
    support (FATE#323821).

  - test_sysctl: test against PAGE_SIZE for int
    (FATE#323821)

  - timer: Prevent timer value 0 for MWAITX (bsc#1065717).

  - tipc: fix link attribute propagation bug (bnc#1012382).

  - tipc: use only positive error codes in messages
    (bnc#1012382).

  - tools: firmware: check for distro fallback udev cancel
    rule (bnc#1012382).

  - tpm: constify transmit data pointers (bsc#1020645,
    git-fixes).

  - tpm: kabi: do not bother with added const (bsc#1020645,
    git-fixes).

  - tpm_tis_spi: Use DMA-safe memory for SPI transfers
    (bsc#1020645, git-fixes).

  - tracing: Fix tracing sample code warning (bnc#1012382).

  - tracing/samples: Fix creation and deletion of
    simple_thread_fn creation (bnc#1012382).

  - tun: allow positive return values on
    dev_get_valid_name() call (bnc#1012382).

  - tun: bail out from tun_get_user() if the skb is empty
    (bnc#1012382).

  - tun: call dev_get_valid_name() before
    register_netdevice() (bnc#1012382).

  - tun/tap: sanitize TUNSETSNDBUF input (bnc#1012382).

  - uapi: fix linux/mroute6.h userspace compilation errors
    (bnc#1012382).

  - uapi: fix linux/rds.h userspace compilation error
    (bnc#1012382).

  - uapi: fix linux/rds.h userspace compilation errors
    (bnc#1012382).

  - udpv6: Fix the checksum computation when HW checksum
    does not apply (bnc#1012382).

  - Update config files to enable spidev on arm64.
    (bsc#1066696)

  - Update
    patches.drivers/0005-hwmon-xgene-Fix-up-error-handling-p
    ath-mixup-in-xgen.patch (bsc#1056652) Correct bugzilla
    reference.

  - Update
    patches.fixes/scsi-devinfo-cleanly-zero-pad-devinfo-stri
    ngs.patch (bsc#1062941, bsc#1037404, bsc#1012523,
    bsc#1038299).

  - Update
    patches.fixes/scsi_devinfo-fixup-string-compare.patch
    (bsc#1062941, bsc#1037404, bsc#1012523, bsc#1038299).

  - Update
    patches.fixes/scsi_devinfo-handle-non-terminated-strings
    .patch (bsc#1062941, bsc#1037404, bsc#1012523,
    bsc#1038299).

  - Update preliminary FC-NVMe patches to mainline status
    (bsc#1067734)

  - usb: Add delay-init quirk for Corsair K70 LUX keyboards
    (bnc#1012382).

  - usb: cdc_acm: Add quirk for Elatec TWN3 (bnc#1012382).

  - usb: core: fix out-of-bounds access bug in
    usb_get_bos_descriptor() (bnc#1012382).

  - usb: devio: Revert 'USB: devio: Do not corrupt user
    memory' (bnc#1012382).

  - usb: dummy-hcd: Fix deadlock caused by disconnect
    detection (bnc#1012382).

  - usb: gadget: composite: Fix use-after-free in
    usb_composite_overwrite_options (bnc#1012382).

  - usb: hcd: initialize hcd->flags to 0 when rm hcd
    (bnc#1012382).

  - usb: hub: Allow reset retry for USB2 devices on connect
    bounce (bnc#1012382).

  - usb: musb: Check for host-mode using is_host_active() on
    reset interrupt (bnc#1012382).

  - usb: musb: sunxi: Explicitly release USB PHY on exit
    (bnc#1012382).

  - usb: quirks: add quirk for WORLDE MINI MIDI keyboard
    (bnc#1012382).

  - usb: renesas_usbhs: Fix DMAC sequence for receiving
    zero-length packet (bnc#1012382).

  - usb: serial: console: fix use-after-free after failed
    setup (bnc#1012382).

  - usb: serial: cp210x: add support for ELV TFD500
    (bnc#1012382).

  - usb: serial: ftdi_sio: add id for Cypress WICED dev
    board (bnc#1012382).

  - usb: serial: garmin_gps: fix I/O after failed probe and
    remove (bnc#1012382).

  - usb: serial: garmin_gps: fix memory leak on probe errors
    (bnc#1012382).

  - usb: serial: metro-usb: add MS7820 device id
    (bnc#1012382).

  - usb: serial: option: add support for TP-Link LTE module
    (bnc#1012382).

  - usb: serial: qcserial: add Dell DW5818, DW5819
    (bnc#1012382).

  - usb: serial: qcserial: add pid/vid for Sierra Wireless
    EM7355 fw update (bnc#1012382).

  - usb: usbfs: compute urb->actual_length for isochronous
    (bnc#1012382).

  - usb: usbtest: fix NULL pointer dereference
    (bnc#1012382).

  - usb: xhci: Handle error condition in xhci_stop_device()
    (bnc#1012382).

  - vfs: expedite unmount (bsc#1024412).

  - video: fbdev: pmag-ba-fb: Remove bad `__init' annotation
    (bnc#1012382).

  - video: udlfb: Fix read EDID timeout (bsc#1031717).

  - vlan: fix a use-after-free in vlan_device_event()
    (bnc#1012382).

  - vsock: use new wait API for vsock_stream_sendmsg()
    (bnc#1012382).

  - vti: fix use after free in vti_tunnel_xmit/vti6_tnl_xmit
    (bnc#1012382).

  - watchdog: kempld: fix gcc-4.3 build (bnc#1012382).

  - workqueue: Fix NULL pointer dereference (bnc#1012382).

  - workqueue: replace pool->manager_arb mutex with a flag
    (bnc#1012382).

  - x86/ACPI/cstate: Allow ACPI C1 FFH MWAIT use on AMD
    systems (bsc#1069879).

  - x86/alternatives: Fix alt_max_short macro to really be a
    max() (bnc#1012382).

  - x86/decoder: Add new TEST instruction pattern
    (bnc#1012382).

  - x86/MCE/AMD: Always give panic severity for UC errors in
    kernel context (git-fixes bf80bbd7dcf5).

  - x86/microcode/AMD: Add support for fam17h microcode
    loading (bsc#1068032).

  - x86/microcode/intel: Disable late loading on model 79
    (bnc#1012382).

  - x86/mm: fix use-after-free of vma during userfaultfd
    fault (Git-fixes, bsc#1069916).

  - x86/oprofile/ppro: Do not use __this_cpu*() in
    preemptible context (bnc#1012382).

  - x86/uaccess, sched/preempt: Verify access_ok() context
    (bnc#1012382).

  - xen: do not print error message in case of missing
    Xenstore entry (bnc#1012382).

  - xen/events: events_fifo: Do not use (get,put)_cpu() in
    xen_evtchn_fifo_init() (bnc#1065600).

  - xen: fix booting ballooned down hvm guest (bnc#1065600).

  - xen/gntdev: avoid out of bounds access in case of
    partial gntdev_mmap() (bnc#1012382).

  - xen/manage: correct return value check on xenbus_scanf()
    (bnc#1012382).

  - xen-netback: fix error handling output (bnc#1065600).

  - xen: x86: mark xen_find_pt_base as __init (bnc#1065600).

  - xen: xenbus driver must not accept invalid transaction
    ids (bnc#1012382).

  - zd1211rw: fix NULL-deref at probe (bsc#1031717)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012523"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=744692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=789311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964944"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996376"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-debuginfo-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-4.4.103-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-debuginfo-4.4.103-36.1") ) flag++;

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
