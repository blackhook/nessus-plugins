#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135559);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4544",
    "CVE-2015-4037",
    "CVE-2015-5239",
    "CVE-2015-5278",
    "CVE-2015-5279",
    "CVE-2015-5745",
    "CVE-2015-6815",
    "CVE-2015-6855",
    "CVE-2015-7295",
    "CVE-2015-7549",
    "CVE-2015-8345",
    "CVE-2015-8504",
    "CVE-2015-8558",
    "CVE-2015-8567",
    "CVE-2015-8568",
    "CVE-2015-8613",
    "CVE-2016-1568",
    "CVE-2016-2198",
    "CVE-2016-2391",
    "CVE-2016-2392",
    "CVE-2016-2538",
    "CVE-2016-2841",
    "CVE-2016-2858",
    "CVE-2016-4001",
    "CVE-2016-4002",
    "CVE-2016-4037",
    "CVE-2016-4453",
    "CVE-2016-4454",
    "CVE-2016-6834",
    "CVE-2016-6835",
    "CVE-2016-6836",
    "CVE-2016-6888",
    "CVE-2016-7116",
    "CVE-2016-7161",
    "CVE-2016-7421",
    "CVE-2016-7908",
    "CVE-2016-7909",
    "CVE-2016-8576",
    "CVE-2016-8669",
    "CVE-2016-8909",
    "CVE-2016-8910",
    "CVE-2016-9102",
    "CVE-2016-9103",
    "CVE-2016-9104",
    "CVE-2016-9105",
    "CVE-2016-9106",
    "CVE-2016-9381",
    "CVE-2016-9907",
    "CVE-2016-9911",
    "CVE-2017-10806",
    "CVE-2017-11434",
    "CVE-2017-18043",
    "CVE-2017-5579",
    "CVE-2017-5973",
    "CVE-2017-8309",
    "CVE-2017-9373",
    "CVE-2017-9374",
    "CVE-2018-10839",
    "CVE-2018-15746",
    "CVE-2018-17958",
    "CVE-2018-17963",
    "CVE-2019-11135",
    "CVE-2019-14378",
    "CVE-2019-6778",
    "CVE-2020-7039",
    "CVE-2020-8608"
  );
  script_bugtraq_id(
    66955,
    74809
  );

  script_name(english:"EulerOS 2.0 SP3 : qemu-kvm (EulerOS-SA-2020-1430)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c
    misuses snprintf return values, leading to a buffer
    overflow in later code.(CVE-2020-8608)

  - This vulnerability has been modified since it was last
    analyzed by the NVD. It is awaiting reanalysis which
    may result in further changes to the information
    provided.(CVE-2019-11135)

  - tcp_emu in tcp_subr.c in libslirp 4.1.0, as used in
    QEMU 4.2.0, mismanages memory, as demonstrated by IRC
    DCC commands in EMU_IRC. This can cause a heap-based
    buffer overflow or other out-of-bounds access which can
    lead to a DoS or potential execute arbitrary
    code.(CVE-2020-7039)

  - ip_reass in ip_input.c in libslirp 4.0.0 has a
    heap-based buffer overflow via a large packet because
    it mishandles a case involving the first
    fragment.(CVE-2019-14378)

  - Integer overflow in the VNC display driver in QEMU
    before 2.1.0 allows attachers to cause a denial of
    service (process crash) via a CLIENT_CUT_TEXT message,
    which triggers an infinite loop.(CVE-2015-5239)

  - Buffer overflow in the send_control_msg function in
    hw/char/virtio-serial-bus.c in QEMU before 2.4.0 allows
    guest users to cause a denial of service (QEMU process
    crash) via a crafted virtio control
    message.(CVE-2015-5745)

  - The ne2000_receive function in hw/net/ne2000.c in QEMU
    before 2.4.0.1 allows attackers to cause a denial of
    service (infinite loop and instance crash) or possibly
    execute arbitrary code via vectors related to receiving
    packets.(CVE-2015-5278)

  - The process_tx_desc function in hw/net/e1000.c in QEMU
    before 2.4.0.1 does not properly process transmit
    descriptor data when sending a network packet, which
    allows attackers to cause a denial of service (infinite
    loop and guest crash) via unspecified
    vectors.(CVE-2015-6815)

  - Heap-based buffer overflow in the ne2000_receive
    function in hw/net/ne2000.c in QEMU before 2.4.0.1
    allows guest OS users to cause a denial of service
    (instance crash) or possibly execute arbitrary code via
    vectors related to receiving packets.(CVE-2015-5279)

  - Heap-based buffer overflow in the .receive callback of
    xlnx.xps-ethernetlite in QEMU (aka Quick Emulator)
    allows attackers to execute arbitrary code on the QEMU
    host via a large ethlite packet.(CVE-2016-7161)

  - hw/net/vmxnet3.c in QEMU 2.0.0-rc0, 1.7.1, and earlier
    allows local guest users to cause a denial of service
    or possibly execute arbitrary code via vectors related
    to (1) RX or (2) TX queue numbers or (3) interrupt
    indices. NOTE: some of these details are obtained from
    third party information.(CVE-2013-4544)

  - The slirp_smb function in net/slirp.c in QEMU 2.3.0 and
    earlier creates temporary files with predictable names,
    which allows local users to cause a denial of service
    (instantiation failure) by creating /tmp/qemu-smb.*-*
    files before the program.(CVE-2015-4037)

  - hw/ide/core.c in QEMU does not properly restrict the
    commands accepted by an ATAPI device, which allows
    guest users to cause a denial of service or possibly
    have unspecified other impact via certain IDE commands,
    as demonstrated by a WIN_READ_NATIVE_MAX command to an
    empty drive, which triggers a divide-by-zero error and
    instance crash.(CVE-2015-6855)

  - hw/virtio/virtio.c in the Virtual Network Device
    (virtio-net) support in QEMU, when big or mergeable
    receive buffers are not supported, allows remote
    attackers to cause a denial of service (guest network
    consumption) via a flood of jumbo frames on the (1)
    tuntap or (2) macvtap interface.(CVE-2015-7295)

  - The MSI-X MMIO support in hw/pci/msix.c in QEMU (aka
    Quick Emulator) allows local guest OS privileged users
    to cause a denial of service (NULL pointer dereference
    and QEMU process crash) by leveraging failure to define
    the .write method.(CVE-2015-7549)

  - The eepro100 emulator in QEMU qemu-kvm blank allows
    local guest users to cause a denial of service
    (application crash and infinite loop) via vectors
    involving the command block list.(CVE-2015-8345)

  - Qemu, when built with VNC display driver support,
    allows remote attackers to cause a denial of service
    (arithmetic exception and application crash) via
    crafted SetPixelFormat messages from a
    client.(CVE-2015-8504)

  - The ehci_process_itd function in hw/usb/hcd-ehci.c in
    QEMU allows local guest OS administrators to cause a
    denial of service (infinite loop and CPU consumption)
    via a circular isochronous transfer descriptor (iTD)
    list.(CVE-2015-8558)

  - Memory leak in net/vmxnet3.c in QEMU allows remote
    attackers to cause a denial of service (memory
    consumption).(CVE-2015-8567)

  - Memory leak in QEMU, when built with a VMWARE VMXNET3
    paravirtual NIC emulator support, allows local guest
    users to cause a denial of service (host memory
    consumption) by trying to activate the vmxnet3 device
    repeatedly.(CVE-2015-8568)

  - Stack-based buffer overflow in the
    megasas_ctrl_get_info function in QEMU, when built with
    SCSI MegaRAID SAS HBA emulation support, allows local
    guest users to cause a denial of service (QEMU instance
    crash) via a crafted SCSI controller CTRL_GET_INFO
    command.(CVE-2015-8613)

  - Use-after-free vulnerability in hw/ide/ahci.c in QEMU,
    when built with IDE AHCI Emulation support, allows
    guest OS users to cause a denial of service (instance
    crash) or possibly execute arbitrary code via an
    invalid AHCI Native Command Queuing (NCQ) AIO
    command.(CVE-2016-1568)

  - QEMU (aka Quick Emulator) built with the USB EHCI
    emulation support is vulnerable to a null pointer
    dereference flaw. It could occur when an application
    attempts to write to EHCI capabilities registers. A
    privileged user inside quest could use this flaw to
    crash the QEMU process instance resulting in
    DoS.(CVE-2016-2198)

  - The ohci_bus_start function in the USB OHCI emulation
    support (hw/usb/hcd-ohci.c) in QEMU allows local guest
    OS administrators to cause a denial of service (NULL
    pointer dereference and QEMU process crash) via vectors
    related to multiple eof_timers.(CVE-2016-2391)

  - The is_rndis function in the USB Net device emulator
    (hw/usb/dev-network.c) in QEMU before 2.5.1 does not
    properly validate USB configuration descriptor objects,
    which allows local guest OS administrators to cause a
    denial of service (NULL pointer dereference and QEMU
    process crash) via vectors involving a remote NDIS
    control message packet.(CVE-2016-2392)

  - Multiple integer overflows in the USB Net device
    emulator (hw/usb/dev-network.c) in QEMU before 2.5.1
    allow local guest OS administrators to cause a denial
    of service (QEMU process crash) or obtain sensitive
    host memory information via a remote NDIS control
    message packet that is mishandled in the (1)
    rndis_query_response, (2) rndis_set_response, or (3)
    usb_net_handle_dataout function.(CVE-2016-2538)

  - The ne2000_receive function in the NE2000 NIC emulation
    support (hw/net/ne2000.c) in QEMU before 2.5.1 allows
    local guest OS administrators to cause a denial of
    service (infinite loop and QEMU process crash) via
    crafted values for the PSTART and PSTOP registers,
    involving ring buffer control.(CVE-2016-2841)

  - QEMU, when built with the Pseudo Random Number
    Generator (PRNG) back-end support, allows local guest
    OS users to cause a denial of service (process crash)
    via an entropy request, which triggers arbitrary stack
    based allocation and memory corruption.(CVE-2016-2858)

  - Buffer overflow in the stellaris_enet_receive function
    in hw/net/stellaris_enet.c in QEMU, when the Stellaris
    ethernet controller is configured to accept large
    packets, allows remote attackers to cause a denial of
    service (QEMU crash) via a large packet.(CVE-2016-4001)

  - Buffer overflow in the mipsnet_receive function in
    hw/net/mipsnet.c in QEMU, when the guest NIC is
    configured to accept large packets, allows remote
    attackers to cause a denial of service (memory
    corruption and QEMU crash) or possibly execute
    arbitrary code via a packet larger than 1514
    bytes.(CVE-2016-4002)

  - The ehci_advance_state function in hw/usb/hcd-ehci.c in
    QEMU allows local guest OS administrators to cause a
    denial of service (infinite loop and CPU consumption)
    via a circular split isochronous transfer descriptor
    (siTD) list, a related issue to
    CVE-2015-8558.(CVE-2016-4037)

  - The vmsvga_fifo_run function in hw/display/vmware_vga.c
    in QEMU allows local guest OS administrators to cause a
    denial of service (infinite loop and QEMU process
    crash) via a VGA command.(CVE-2016-4453)

  - The vmsvga_fifo_read_raw function in
    hw/display/vmware_vga.c in QEMU allows local guest OS
    administrators to obtain sensitive host memory
    information or cause a denial of service (QEMU process
    crash) by changing FIFO registers and issuing a VGA
    command, which triggers an out-of-bounds
    read.(CVE-2016-4454)

  - The net_tx_pkt_do_sw_fragmentation function in
    hw/net/net_tx_pkt.c in QEMU (aka Quick Emulator) allows
    local guest OS administrators to cause a denial of
    service (infinite loop and QEMU process crash) via a
    zero length for the current fragment
    length.(CVE-2016-6834)

  - The vmxnet_tx_pkt_parse_headers function in
    hw/net/vmxnet_tx_pkt.c in QEMU (aka Quick Emulator)
    allows local guest OS administrators to cause a denial
    of service (buffer over-read) by leveraging failure to
    check IP header length.(CVE-2016-6835)

  - The vmxnet3_complete_packet function in
    hw/net/vmxnet3.c in QEMU (aka Quick Emulator) allows
    local guest OS administrators to obtain sensitive host
    memory information by leveraging failure to initialize
    the txcq_descr object.(CVE-2016-6836)

  - Integer overflow in the net_tx_pkt_init function in
    hw/net/net_tx_pkt.c in QEMU (aka Quick Emulator) allows
    local guest OS administrators to cause a denial of
    service (QEMU process crash) via the maximum
    fragmentation count, which triggers an unchecked
    multiplication and NULL pointer
    dereference.(CVE-2016-6888)

  - Directory traversal vulnerability in hw/9pfs/9p.c in
    QEMU (aka Quick Emulator) allows local guest OS
    administrators to access host files outside the export
    path via a .. (dot dot) in an unspecified
    string.(CVE-2016-7116)

  - The pvscsi_ring_pop_req_descr function in
    hw/scsi/vmw_pvscsi.c in QEMU (aka Quick Emulator)
    allows local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) by
    leveraging failure to limit process IO loop to the ring
    size.(CVE-2016-7421)

  - The mcf_fec_do_tx function in hw/net/mcf_fec.c in QEMU
    (aka Quick Emulator) does not properly limit the buffer
    descriptor count when transmitting packets, which
    allows local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of
    0 and crafted values in bd.flags.(CVE-2016-7908)

  - The pcnet_rdra_addr function in hw/net/pcnet.c in QEMU
    (aka Quick Emulator) allows local guest OS
    administrators to cause a denial of service (infinite
    loop and QEMU process crash) by setting the (1) receive
    or (2) transmit descriptor ring length to
    0.(CVE-2016-7909)

  - The xhci_ring_fetch function in hw/usb/hcd-xhci.c in
    QEMU (aka Quick Emulator) allows local guest OS
    administrators to cause a denial of service (infinite
    loop and QEMU process crash) by leveraging failure to
    limit the number of link Transfer Request Blocks (TRB)
    to process.(CVE-2016-8576)

  - The serial_update_parameters function in
    hw/char/serial.c in QEMU (aka Quick Emulator) allows
    local guest OS administrators to cause a denial of
    service (divide-by-zero error and QEMU process crash)
    via vectors involving a value of divider greater than
    baud base.(CVE-2016-8669)

  - The intel_hda_xfer function in hw/audio/intel-hda.c in
    QEMU (aka Quick Emulator) allows local guest OS
    administrators to cause a denial of service (infinite
    loop and CPU consumption) via an entry with the same
    value for buffer length and pointer
    position.(CVE-2016-8909)

  - The rtl8139_cplus_transmit function in hw/net/rtl8139.c
    in QEMU (aka Quick Emulator) allows local guest OS
    administrators to cause a denial of service (infinite
    loop and CPU consumption) by leveraging failure to
    limit the ring descriptor count.(CVE-2016-8910)

  - Memory leak in the v9fs_xattrcreate function in
    hw/9pfs/9p.c in QEMU (aka Quick Emulator) allows local
    guest OS administrators to cause a denial of service
    (memory consumption and QEMU process crash) via a large
    number of Txattrcreate messages with the same fid
    number.(CVE-2016-9102)

  - The v9fs_xattrcreate function in hw/9pfs/9p.c in QEMU
    (aka Quick Emulator) allows local guest OS
    administrators to obtain sensitive host heap memory
    information by reading xattribute values before writing
    to them.(CVE-2016-9103)

  - Multiple integer overflows in the (1) v9fs_xattr_read
    and (2) v9fs_xattr_write functions in hw/9pfs/9p.c in
    QEMU (aka Quick Emulator) allow local guest OS
    administrators to cause a denial of service (QEMU
    process crash) via a crafted offset, which triggers an
    out-of-bounds access.(CVE-2016-9104)

  - Memory leak in the v9fs_link function in hw/9pfs/9p.c
    in QEMU (aka Quick Emulator) allows local guest OS
    administrators to cause a denial of service (memory
    consumption) via vectors involving a reference to the
    source fid object.(CVE-2016-9105)

  - Memory leak in the v9fs_write function in hw/9pfs/9p.c
    in QEMU (aka Quick Emulator) allows local guest OS
    administrators to cause a denial of service (memory
    consumption) by leveraging failure to free an IO
    vector.(CVE-2016-9106)

  - Race condition in QEMU in Xen allows local x86 HVM
    guest OS administrators to gain privileges by changing
    certain data on shared rings, aka a 'double fetch'
    vulnerability.(CVE-2016-9381)

  - Quick Emulator (Qemu) built with the USB redirector
    usb-guest support is vulnerable to a memory leakage
    flaw. It could occur while destroying the USB
    redirector in 'usbredir_handle_destroy'. A guest
    user/process could use this issue to leak host memory,
    resulting in DoS for a host.(CVE-2016-9907)

  - Quick Emulator (Qemu) built with the USB EHCI Emulation
    support is vulnerable to a memory leakage issue. It
    could occur while processing packet data in
    'ehci_init_transfer'. A guest user/process could use
    this issue to leak host memory, resulting in DoS for a
    host.(CVE-2016-9911)

  - Stack-based buffer overflow in hw/usb/redirect.c in
    QEMU (aka Quick Emulator) allows local guest OS users
    to cause a denial of service (QEMU process crash) via
    vectors related to logging debug
    messages.(CVE-2017-10806)

  - The dhcp_decode function in slirp/bootp.c in QEMU (aka
    Quick Emulator) allows local guest OS users to cause a
    denial of service (out-of-bounds read and QEMU process
    crash) via a crafted DHCP options
    string.(CVE-2017-11434)

  - Integer overflow in the macro ROUND_UP (n, d) in Quick
    Emulator (Qemu) allows a user to cause a denial of
    service (Qemu process crash).(CVE-2017-18043)

  - Memory leak in the serial_exit_core function in
    hw/char/serial.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption and QEMU process
    crash) via a large number of device unplug
    operations.(CVE-2017-5579)

  - The xhci_kick_epctx function in hw/usb/hcd-xhci.c in
    QEMU (aka Quick Emulator) allows local guest OS
    privileged users to cause a denial of service (infinite
    loop and QEMU process crash) via vectors related to
    control transfer descriptor sequence.(CVE-2017-5973)

  - Memory leak in the audio/audio.c in QEMU (aka Quick
    Emulator) allows remote attackers to cause a denial of
    service (memory consumption) by repeatedly starting and
    stopping audio capture.(CVE-2017-8309)

  - Memory leak in QEMU (aka Quick Emulator), when built
    with IDE AHCI Emulation support, allows local guest OS
    privileged users to cause a denial of service (memory
    consumption) by repeatedly hot-unplugging the AHCI
    device.(CVE-2017-9373)

  - Memory leak in QEMU (aka Quick Emulator), when built
    with USB EHCI Emulation support, allows local guest OS
    privileged users to cause a denial of service (memory
    consumption) by repeatedly hot-unplugging the
    device.(CVE-2017-9374)

  - Qemu emulator <= 3.0.0 built with the NE2000 NIC
    emulation support is vulnerable to an integer overflow,
    which could lead to buffer overflow issue. It could
    occur when receiving packets over the network. A user
    inside guest could use this flaw to crash the Qemu
    process resulting in DoS.(CVE-2018-10839)

  - qemu-seccomp.c in QEMU might allow local OS guest users
    to cause a denial of service (guest crash) by
    leveraging mishandling of the seccomp policy for
    threads other than the main thread.(CVE-2018-15746)

  - Qemu has a Buffer Overflow in rtl8139_do_receive in
    hw/net/rtl8139.c because an incorrect integer data type
    is used.(CVE-2018-17958)

  - qemu_deliver_packet_iov in net/net.c in Qemu accepts
    packet sizes greater than INT_MAX, which allows
    attackers to cause a denial of service or possibly have
    unspecified other impact.(CVE-2018-17963)

  - In QEMU 3.0.0, tcp_emu in slirp/tcp_subr.c has a
    heap-based buffer overflow.(CVE-2019-6778)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1430
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3afa4311");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8608");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-img-1.5.3-156.5.h12",
        "qemu-kvm-1.5.3-156.5.h12",
        "qemu-kvm-common-1.5.3-156.5.h12"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
