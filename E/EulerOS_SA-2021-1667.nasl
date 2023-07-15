#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2018-12617",
    "CVE-2019-14378",
    "CVE-2019-15890",
    "CVE-2019-20175",
    "CVE-2019-20382",
    "CVE-2020-1711",
    "CVE-2020-1983",
    "CVE-2020-7039",
    "CVE-2020-7211",
    "CVE-2020-8608",
    "CVE-2020-10702",
    "CVE-2020-10756",
    "CVE-2020-11869",
    "CVE-2020-12829",
    "CVE-2020-13253",
    "CVE-2020-13361",
    "CVE-2020-13362",
    "CVE-2020-13659",
    "CVE-2020-13765",
    "CVE-2020-13791",
    "CVE-2020-13800",
    "CVE-2020-15863",
    "CVE-2020-16092",
    "CVE-2020-25624",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-27616",
    "CVE-2020-27617",
    "CVE-2020-27821",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29130"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : qemu (EulerOS-SA-2021-1667)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - In QEMU through 5.0.0, an integer overflow was found in
    the SM501 display driver implementation. This flaw
    occurs in the COPY_AREA macro while handling MMIO write
    operations through the sm501_2d_engine_write()
    callback. A local attacker could abuse this flaw to
    crash the QEMU process in sm501_2d_operation() in
    hw/display/sm501.c on the host, resulting in a denial
    of service.(CVE-2020-12829)

  - slirp.c in libslirp through 4.3.1 has a buffer
    over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet
    length.(CVE-2020-29130)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read
    because it tries to read a certain amount of header
    data even if that exceeds the total packet
    length.(CVE-2020-29129)

  - hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop
    via an RX descriptor with a NULL buffer
    address.(CVE-2020-28916)

  - ati_2d_blt in hw/display/ati_2d.c in QEMU 4.2.1 can
    encounter an outside-limits situation in a calculation.
    A guest can crash the QEMU process.(CVE-2020-27616)

  - eth_get_gso_type in net/eth.c in QEMU 4.2.1 allows
    guest OS users to trigger an assertion failure. A guest
    can crash the QEMU process via packet data that lacks a
    valid Layer 3 protocol.(CVE-2020-27617)

  - A reachable assertion issue was found in the USB EHCI
    emulation code of QEMU. It could occur while processing
    USB requests due to missing handling of DMA memory map
    failure. A malicious privileged user within the guest
    may abuse this flaw to send bogus USB requests and
    crash the QEMU process on the host, resulting in a
    denial of service.(CVE-2020-25723)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has a stack-based
    buffer over-read via values obtained from the host
    controller driver.(CVE-2020-25624)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has an infinite loop
    when a TD list has a loop.(CVE-2020-25625)

  - In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c
    misuses snprintf return values, leading to a buffer
    overflow in later code.(CVE-2020-8608)

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

  - A flaw was found in the memory management API of QEMU
    during the initialization of a memory region cache.
    This issue could lead to an out-of-bounds write access
    to the MSI-X table while performing MMIO operations. A
    guest user may abuse this flaw to crash the QEMU
    process on the host, resulting in a denial of service.
    This flaw affects QEMU versions prior to
    5.2.0.(CVE-2020-27821)

  - QEMU: reachable assertion failure in
    net_tx_pkt_add_raw_fragment() in hw/net/net_tx_pkt.c
    (CVE-2020-16092)

  - hw/pci/pci.c in QEMU 4.2.0 allows guest OS users to
    trigger an out-of-bounds access by providing an address
    near the end of the PCI configuration
    space(CVE-2020-13791)

  - qmp_guest_file_read in qga/commands-posix.c and
    qga/commands-win32.c in qemu-ga (aka QEMU Guest Agent)
    in QEMU 2.12.50 has an integer overflow causing a
    g_malloc0() call to trigger a segmentation fault when
    trying to allocate a large memory chunk. The
    vulnerability can be exploited by sending a crafted QMP
    command (including guest-file-read with a large count
    value) to the agent via the listening
    socket.(CVE-2018-12617)

  - sd_wp_addr in hw/sd/sd.c in QEMU 4.2.0 uses an
    unvalidated address, which leads to an out-of-bounds
    read during sdhci_write() operations. A guest OS user
    can crash the QEMU process.(CVE-2020-13253)

  - QEMU 4.1.0 has a memory leak in zrle_compress_data in
    ui/vnc-enc-zrle.c during a VNC disconnect operation
    because libz is misused, resulting in a situation where
    memory allocated in deflateInit2 is not freed in
    deflateEnd.(CVE-2019-20382)

  - An integer overflow was found in QEMU 4.0.1 through
    4.2.0 in the way it implemented ATI VGA emulation. This
    flaw occurs in the ati_2d_blt() routine in
    hw/display/ati-2d.c while handling MMIO write
    operations through the ati_mm_write() callback. A
    malicious guest could abuse this flaw to crash the QEMU
    process, resulting in a denial of
    service.(CVE-2020-11869)

  - This vulnerability has been modified since it was last
    analyzed by the NVD. It is awaiting reanalysis which
    may result in further changes to the information
    provided.(CVE-2020-13659)

  - A flaw was found in QEMU in the implementation of the
    Pointer Authentication (PAuth) support for ARM
    introduced in version 4.0 and fixed in version 5.0.0. A
    general failure of the signature generation process
    caused every PAuth-enforced pointer to be signed with
    the same signature. A local attacker could obtain the
    signature of a protected pointer and abuse this flaw to
    bypass PAuth protection for all programs running on
    QEMU.(CVE-2020-10702)

  - hw/net/xgmac.c in the XGMAC Ethernet controller in QEMU
    before 07-20-2020 has a buffer overflow. This occurs
    during packet transmission and affects the highbank and
    midway emulated machines. A guest user or process could
    use this flaw to crash the QEMU process on the host,
    resulting in a denial of service or potential
    privileged code execution. This was fixed in commit
    5519724a13664b43e225ca05351c60b4468e4555.(CVE-2020-1586
    3)

  - In QEMU 5.0.0 and earlier, megasas_lookup_frame in
    hw/scsi/megasas.c has an out-of-bounds read via a
    crafted reply_queue_head field from a guest OS
    user.(CVE-2020-13362)

  - ** DISPUTED ** An issue was discovered in ide_dma_cb()
    in hw/ide/core.c in QEMU 2.4.0 through 4.2.0. The guest
    system can crash the QEMU process in the host system
    via a special SCSI_IOCTL_SEND_COMMAND. It hits an
    assertion that implies that the size of successful DMA
    transfers there must be a multiple of 512 (the size of
    a sector). NOTE: a member of the QEMU security team
    disputes the significance of this issue because a
    'privileged guest user has many ways to cause similar
    DoS effect, without triggering this
    assert.'(CVE-2019-20175)

  - In QEMU 5.0.0 and earlier, es1370_transfer_audio in
    hw/audio/es1370.c does not properly validate the frame
    count, which allows guest OS users to trigger an
    out-of-bounds access during an es1370_write()
    operation.(CVE-2020-13361)

  - rom_copy() in hw/core/loader.c in QEMU 4.1.0 does not
    validate the relationship between two addresses, which
    allows attackers to trigger an invalid memory copy
    operation.(CVE-2020-13765)

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a
    use-after-free in ip_reass in
    ip_input.c.(CVE-2019-15890)

  - A use after free vulnerability in ip_reass() in
    ip_input.c of libslirp 4.2.0 and prior releases allows
    crafted packets to cause a denial of
    service.(CVE-2020-1983)

  - ati-vga in hw/display/ati.c in QEMU 4.2.0 allows guest
    OS users to trigger infinite recursion via a crafted
    mm_index value during an ati_mm_read or ati_mm_write
    call.(CVE-2020-13800)

  - An out-of-bounds heap buffer access flaw was found in
    the way the iSCSI Block driver in QEMU versions 2.12.0
    before 4.2.1 handled a response coming from an iSCSI
    server while checking the status of a Logical Address
    Block (LBA) in an iscsi_co_block_status() routine. A
    remote user could use this flaw to crash the QEMU
    process, resulting in a denial of service or potential
    execution of arbitrary code with privileges of the QEMU
    process on the host.(CVE-2020-1711)

  - tftp.c in libslirp 4.1.0, as used in QEMU 4.2.0, does
    not prevent ..\ directory traversal on
    Windows.(CVE-2020-7211)

  - An out-of-bounds read vulnerability was found in the
    SLiRP networking implementation of the QEMU emulator.
    This flaw occurs in the icmp6_send_echoreply() routine
    while replying to an ICMP echo request, also known as
    ping. This flaw allows a malicious guest to leak the
    contents of the host memory, resulting in possible
    information disclosure. This flaw affects versions of
    libslirp before 4.3.1.(CVE-2020-10756)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1667
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82d9e490");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8608");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14378");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-4.1.0-2.9.1.2.208",
        "qemu-debuginfo-4.1.0-2.9.1.1.208",
        "qemu-debugsource-4.1.0-2.9.1.2.208",
        "qemu-guest-agent-4.1.0-2.9.1.2.208",
        "qemu-img-4.1.0-2.9.1.2.208"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
