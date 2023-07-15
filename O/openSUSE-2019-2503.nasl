#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2503.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131057);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-16231", "CVE-2019-16233", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-18805");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2503)");
  script_summary(english:"Check for the openSUSE-2019-2503 patch");

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

  - CVE-2019-0154: An unprotected read access to i915
    registers has been fixed that could have been abused to
    facilitate a local denial-of-service attack.
    (bsc#1135966)

  - CVE-2019-0155: A privilege escalation vulnerability has
    been fixed in the i915 module that allowed batch buffers
    from user mode to gain super user privileges.
    (bsc#1135967)

  - CVE-2019-16231: drivers/net/fjes/fjes_main.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150466).

  - CVE-2019-18805: There was a net/ipv4/tcp_input.c signed
    integer overflow in tcp_ack_update_rtt() when userspace
    writes a very large integer to
    /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading to a denial
    of service or possibly unspecified other impact, aka
    CID-19fad20d15a6 (bnc#1156187).

  - CVE-2019-17055: base_sock_create in
    drivers/isdn/mISDN/socket.c in the AF_ISDN network
    module did not enforce CAP_NET_RAW, which means that
    unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21 (bnc#1152782).

  - CVE-2019-16995: A memory leak exits in
    hsr_dev_finalize() in net/hsr/hsr_device.c, if
    hsr_add_port fails to add a port, which may cause denial
    of service, aka CID-6caabe7f197d (bnc#1152685).

  - CVE-2019-11135: Aborting an asynchronous TSX operation
    on Intel CPUs with Transactional Memory support could be
    used to facilitate sidechannel information leaks out of
    microarchitectural buffers, similar to the previously
    described 'Microarchitectural Data Sampling' attack.

    The Linux kernel was supplemented with the option to
    disable TSX operation altogether (requiring CPU
    Microcode updates on older systems) and better flushing
    of microarchitectural buffers (VERW).

    The set of options available is described in our TID at
    https://www.suse.com/support/kb/doc/?id=7024251

  - CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150457).

  - CVE-2018-12207: Untrusted virtual machines on Intel CPUs
    could exploit a race condition in the Instruction Fetch
    Unit of the Intel CPU to cause a Machine Exception
    during Page Size Change, causing the CPU core to be
    non-functional.

    The Linux Kernel kvm hypervisor was adjusted to avoid
    page size changes in executable pages by splitting /
    merging huge pages into small pages as needed.

    More information can be found on
    https://www.suse.com/support/kb/doc/?id=7023735

  - CVE-2019-10220: Added sanity checks on the pathnames
    passed to the user space. (bsc#1144903).

The following non-security bugs were fixed :

  - ALSA: bebob: Fix prototype of helper function to return
    negative value (bsc#1051510).

  - ALSA: bebob: fix to detect configured source of sampling
    clock for Focusrite Saffire Pro i/o series (git-fixes).

  - ALSA: hda: Add Elkhart Lake PCI ID (bsc#1051510).

  - ALSA: hda: Add Tigerlake/Jasperlake PCI ID
    (bsc#1051510).

  - ALSA: hda/ca0132 - Fix possible workqueue stall
    (bsc#1155836).

  - ALSA: hda/realtek - Add support for ALC623
    (bsc#1051510).

  - ALSA: hda/realtek - Add support for ALC711
    (bsc#1051510).

  - ALSA: hda/realtek - Fix 2 front mics of codec 0x623
    (bsc#1051510).

  - ALSA: timer: Fix incorrectly assigned timer instance
    (git-fixes).

  - ALSA: timer: Fix mutex deadlock at releasing card
    (bsc#1051510).

  - arcnet: provide a buffer big enough to actually receive
    packets (networking-stable-19_09_30).

  - ASoc: rockchip: i2s: Fix RPM imbalance (bsc#1051510).

  - ASoC: rsnd: Reinitialize bit clock inversion flag for
    every format setting (bsc#1051510).

  - bpf: fix use after free in prog symbol exposure
    (bsc#1083647).

  - btrfs: block-group: Fix a memory leak due to missing
    btrfs_put_block_group() (bsc#1155178).

  - btrfs: qgroup: Always free PREALLOC META reserve in
    btrfs_delalloc_release_extents() (bsc#1155179).

  - btrfs: tracepoints: Fix bad entry members of qgroup
    events (bsc#1155186).

  - btrfs: tracepoints: Fix wrong parameter order for qgroup
    events (bsc#1155184).

  - can: dev: call netif_carrier_off() in register_candev()
    (bsc#1051510).

  - crypto: af_alg - consolidation of duplicate code
    (bsc#1154737).

  - crypto: af_alg - fix race accessing cipher request
    (bsc#1154737).

  - crypto: af_alg - Fix race around ctx->rcvused by making
    it atomic_t (bsc#1154737).

  - crypto: af_alg - Initialize sg_num_bytes in error code
    path (bsc#1051510).

  - crypto: af_alg - remove locking in async callback
    (bsc#1154737).

  - crypto: af_alg - update correct dst SGL entry
    (bsc#1051510).

  - crypto: af_alg - wait for data at beginning of recvmsg
    (bsc#1154737).

  - crypto: algif_aead - copy AAD from src to dst
    (bsc#1154737).

  - crypto: algif_aead - fix reference counting of null
    skcipher (bsc#1154737).

  - crypto: algif_aead - overhaul memory management
    (bsc#1154737).

  - crypto: algif_aead - skip SGL entries with NULL page
    (bsc#1154737).

  - crypto: algif - return error code when no data was
    processed (bsc#1154737).

  - crypto: algif_skcipher - overhaul memory management
    (bsc#1154737).

  - cxgb4:Fix out-of-bounds MSI-X info array access
    (networking-stable-19_10_05).

  - dmaengine: bcm2835: Print error in case setting DMA mask
    fails (bsc#1051510).

  - dmaengine: imx-sdma: fix size check for sdma
    script_number (bsc#1051510).

  - drm/edid: Add 6 bpc quirk for SDC panel in Lenovo G50
    (bsc#1051510).

  - drm/i915: Add gen9 BCS cmdparsing (bsc#1135967)

  - drm/i915: Add support for mandatory cmdparsing
    (bsc#1135967)

  - drm/i915: Allow parsing of unsized batches (bsc#1135967)

  - drm/i915/cmdparser: Add support for backward jumps
    (bsc#1135967)

  - drm/i915/cmdparser: Ignore Length operands during
    command matching (bsc#1135967)

  - drm/i915/cmdparser: Use explicit goto for error paths
    (bsc#1135967)

  - drm/i915: Disable Secure Batches for gen6+

  - drm/i915/gen8+: Add RC6 CTX corruption WA (bsc#1135967)

  - drm/i915/gtt: Add read only pages to gen8_pte_encode
    (bsc#1135967)

  - drm/i915/gtt: Disable read-only support under GVT
    (bsc#1135967)

  - drm/i915/gtt: Read-only pages for insert_entries on bdw
    (bsc#1135967)

  - drm/i915: Lower RM timeout to avoid DSI hard hangs
    (bsc#1135967)

  - drm/i915: Prevent writing into a read-only object via a
    GGTT mmap (bsc#1135967)

  - drm/i915: Remove Master tables from cmdparser

  - drm/i915: Rename gen7 cmdparser tables (bsc#1135967)

  - drm/i915: Support ro ppgtt mapped cmdparser shadow
    buffers (bsc#1135967)

  - efi: cper: print AER info of PCIe fatal error
    (bsc#1051510).

  - efi/memattr: Do not bail on zero VA if it equals the
    region's PA (bsc#1051510).

  - efivar/ssdt: Do not iterate over EFI vars if no SSDT
    override was specified (bsc#1051510).

  - HID: fix error message in hid_open_report()
    (bsc#1051510).

  - HID: logitech-hidpp: do all FF cleanup in
    hidpp_ff_destroy() (bsc#1051510).

  - hso: fix NULL-deref on tty open (bsc#1051510).

  - hyperv: set nvme msi interrupts to unmanaged
    (jsc#SLE-8953, jsc#SLE-9221, jsc#SLE-4941, bsc#1119461,
    bsc#1119465, bsc#1138190, bsc#1154905).

  - IB/core: Add mitigation for Spectre V1 (bsc#1155671)

  - ieee802154: ca8210: prevent memory leak (bsc#1051510).

  - input: synaptics-rmi4 - avoid processing unknown IRQs
    (bsc#1051510).

  - integrity: prevent deadlock during digsig verification
    (bsc#1090631).

  - ipv6: drop incoming packets having a v4mapped source
    address (networking-stable-19_10_05).

  - ipv6: Handle missing host route in __ipv6_ifa_notify
    (networking-stable-19_10_05).

  - iwlwifi: do not panic in error path on non-msix systems
    (bsc#1155692).

  - iwlwifi: exclude GEO SAR support for 3168 (git-fixes).

  - kABI workaround for crypto/af_alg changes (bsc#1154737).

  - kABI workaround for drm_vma_offset_node readonly field
    addition (bsc#1135967)

  - ksm: cleanup stable_node chain collapse case
    (bnc#1144338).

  - ksm: fix use after free with merge_across_nodes = 0
    (bnc#1144338).

  - ksm: introduce ksm_max_page_sharing per page
    deduplication limit (bnc#1144338).

  - ksm: optimize refile of stable_node_dup at the head of
    the chain (bnc#1144338).

  - ksm: swap the two output parameters of chain/chain_prune
    (bnc#1144338).

  - KVM: vmx, svm: always run with EFER.NXE=1 when shadow
    paging is active (bsc#1117665).

  - mac80211: fix txq NULL pointer dereference
    (bsc#1051510).

  - mac80211: Reject malformed SSID elements (bsc#1051510).

  - md/raid0: avoid RAID0 data corruption due to layout
    confusion (bsc#1140090).

  - md/raid0: fix warning message for parameter
    default_layout (bsc#1140090).

  - Move upstreamed CA0132 fix into sorted section

  - netfilter: nf_nat: do not bug when mapping already
    exists (bsc#1146612).

  - net: openvswitch: free vport unless register_netdevice()
    succeeds (git-fixes).

  - net/phy: fix DP83865 10 Mbps HDX loopback disable
    function (networking-stable-19_09_30).

  - net: qlogic: Fix memory leak in ql_alloc_large_buffers
    (networking-stable-19_10_05).

  - net: qrtr: Stop rx_worker before freeing node
    (networking-stable-19_09_30).

  - net/rds: Fix error handling in rds_ib_add_one()
    (networking-stable-19_10_05).

  - net/rds: fix warn in rds_message_alloc_sgs
    (bsc#1154848).

  - net/rds: remove user triggered WARN_ON in rds_sendmsg
    (bsc#1154848).

  - net: Replace NF_CT_ASSERT() with WARN_ON()
    (bsc#1146612).

  - net/sched: act_sample: do not push mac header on ip6gre
    ingress (networking-stable-19_09_30).

  - net_sched: add policy validation for action attributes
    (networking-stable-19_09_30).

  - net_sched: fix backward compatibility for TCA_ACT_KIND
    (git-fixes).

  - net: Unpublish sk from sk_reuseport_cb before call_rcu
    (networking-stable-19_10_05).

  - NFSv4.1 - backchannel request should hold ref on xprt
    (bsc#1152624).

  - nl80211: fix NULL pointer dereference (bsc#1051510).

  - openvswitch: change type of UPCALL_PID attribute to
    NLA_UNSPEC (networking-stable-19_09_30).

  - power: supply: max14656: fix potential use-after-free
    (bsc#1051510).

  - qmi_wwan: add support for Cinterion CLS8 devices
    (networking-stable-19_10_05).

  - r8152: Set macpassthru in reset_resume callback
    (bsc#1051510).

  - rds: Fix warning (bsc#1154848).

  - Revert 'ALSA: hda: Flush interrupts on disabling'
    (bsc#1051510).

  - Revert 'drm/radeon: Fix EEH during kexec' (bsc#1051510).

  - Revert synaptics-rmi4 patch due to regression
    (bsc#1155982) Also blacklisting it

  - rpm/kernel-subpackage-spec: Mention debuginfo in the
    subpackage description (bsc#1149119).

  - s390/cmf: set_schib_wait add timeout (bsc#1153509,
    bsc#1153476).

  - s390/cpumsf: Check for CPU Measurement sampling
    (bsc#1153681 LTC#181855).

  - sc16is7xx: Fix for 'Unexpected interrupt: 8'
    (bsc#1051510).

  - sch_cbq: validate TCA_CBQ_WRROPT to avoid crash
    (networking-stable-19_10_05).

  - sch_dsmark: fix potential NULL deref in dsmark_init()
    (networking-stable-19_10_05).

  - sched/fair: Avoid divide by zero when rebalancing
    domains (bsc#1096254).

  - sch_netem: fix a divide by zero in tabledist()
    (networking-stable-19_09_30).

  - scsi: lpfc: Fix devices that do not return after devloss
    followed by rediscovery (bsc#1137040).

  - scsi: lpfc: Limit xri count for kdump environment
    (bsc#1154124).

  - scsi: qla2xxx: Add error handling for PLOGI ELS
    passthrough (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Capture FW dump on MPI heartbeat stop
    event (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Check for MB timeout while capturing
    ISP27/28xx FW dump (bsc#1143706 bsc#1082635
    bsc#1123034).

  - scsi: qla2xxx: Do command completion on abort timeout
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: do not use zero for FC4_PRIORITY_NVME
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Dual FCP-NVMe target port support
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix a dma_pool_free() call (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix device connect issues in P2P
    configuration (bsc#1143706 bsc#1082635 bsc#1154526
    bsc#1048942).

  - scsi: qla2xxx: Fix double scsi_done for abort path
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix driver unload hang (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix memory leak when sending I/O fails
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix N2N link reset (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix N2N link up fail (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix partial flash write of MBI
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix SRB leak on switch command timeout
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Fix stale mem access on driver unload
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix unbound sleep in fcport delete path
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: fixup incorrect usage of host_byte
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix wait condition in loop (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Improve logging for scan thread
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Initialized mailbox to prevent driver
    load failure (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: initialize fc4_type_priority (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Optimize NPIV tear down process
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Remove an include directive (bsc#1143706
    bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: remove redundant assignment to pointer
    host (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Retry PLOGI on FC-NVMe PRLI failure
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: qla2xxx: Set remove flag for all VP (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Silence fwdump template message
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: stop timer in shutdown path (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Update driver version to 10.01.00.20-k
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Update driver version to 10.01.00.21-k
    (bsc#1143706 bsc#1082635 bsc#1154526 bsc#1048942).

  - scsi: sd: Ignore a failure to sync cache due to lack of
    authorization (git-fixes).

  - scsi: storvsc: Add ability to change scsi queue depth
    (bsc#1155021).

  - scsi: zfcp: fix reaction on bit error threshold
    notification (bsc#1154956 LTC#182054).

  - serial: fix kernel-doc warning in comments
    (bsc#1051510).

  - serial: mctrl_gpio: Check for NULL pointer
    (bsc#1051510).

  - serial: uartlite: fix exit path NULL pointer
    (bsc#1051510).

  - skge: fix checksum byte order
    (networking-stable-19_09_30).

  - staging: rtl8188eu: fix null dereference when kzalloc
    fails (bsc#1051510).

  - staging: wlan-ng: fix exit return when sme->key_idx >=
    NUM_WEPKEYS (bsc#1051510).

  - supporte.conf: add efivarfs to kernel-default-base
    (bsc#1154858).

  - tipc: fix unlimited bundling of small messages
    (networking-stable-19_10_05).

  - tracing: Get trace_array reference for available_tracers
    files (bsc#1156429).

  - usb: gadget: Reject endpoints with 0 maxpacket value
    (bsc#1051510).

  - usb: gadget: udc: atmel: Fix interrupt storm in FIFO
    mode (bsc#1051510).

  - usb: handle warm-reset port requests on hub resume
    (bsc#1051510).

  - usb: ldusb: fix control-message timeout (bsc#1051510).

  - usb: ldusb: fix memleak on disconnect (bsc#1051510).

  - usb: ldusb: fix NULL-derefs on driver unbind
    (bsc#1051510).

  - usb: ldusb: fix read info leaks (bsc#1051510).

  - usb: ldusb: fix ring-buffer locking (bsc#1051510).

  - usb: legousbtower: fix a signedness bug in tower_probe()
    (bsc#1051510).

  - usb: legousbtower: fix memleak on disconnect
    (bsc#1051510).

  - usb: serial: ti_usb_3410_5052: fix port-close races
    (bsc#1051510).

  - usb: serial: whiteheat: fix line-speed endianness
    (bsc#1051510).

  - usb: serial: whiteheat: fix potential slab corruption
    (bsc#1051510).

  - usb-storage: Revert commit 747668dbc061 ('usb-storage:
    Set virt_boundary_mask to avoid SG overflows')
    (bsc#1051510).

  - usb: udc: lpc32xx: fix bad bit shift operation
    (bsc#1051510).

  - usb: usblp: fix use-after-free on disconnect
    (bsc#1051510).

  - vsock: Fix a lockdep warning in __vsock_release()
    (networking-stable-19_10_05).

  - x86/boot/64: Make level2_kernel_pgt pages invalid
    outside kernel area (bnc#1153969).

  - x86/boot/64: Round memory hole size up to next PMD page
    (bnc#1153969)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc/?id=7023735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc/?id=7024251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10220");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.82.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.82.1") ) flag++;

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
