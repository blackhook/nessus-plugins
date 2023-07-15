#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138009);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-4952",
    "CVE-2016-7907",
    "CVE-2017-10806",
    "CVE-2017-11434",
    "CVE-2017-13711",
    "CVE-2017-5525",
    "CVE-2017-5526",
    "CVE-2017-5856",
    "CVE-2017-5973",
    "CVE-2017-5987",
    "CVE-2017-7493",
    "CVE-2017-8112",
    "CVE-2017-8380",
    "CVE-2017-9524",
    "CVE-2018-11806",
    "CVE-2018-15746",
    "CVE-2018-16872",
    "CVE-2018-17958",
    "CVE-2018-17962",
    "CVE-2018-17963",
    "CVE-2018-18438",
    "CVE-2018-18849",
    "CVE-2018-19364",
    "CVE-2018-19489",
    "CVE-2018-19665",
    "CVE-2018-20815",
    "CVE-2019-11135",
    "CVE-2019-12068",
    "CVE-2019-12155",
    "CVE-2019-13164",
    "CVE-2019-20175",
    "CVE-2019-3812",
    "CVE-2019-9824"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : qemu-kvm (EulerOS-SA-2020-1790)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Memory leak in hw/audio/es1370.c in QEMU (aka Quick
    Emulator) allows local guest OS privileged users to
    cause a denial of service (host memory consumption and
    QEMU process crash) via a large number of device unplug
    operations.(CVE-2017-5526)

  - Memory leak in hw/audio/ac97.c in QEMU (aka Quick
    Emulator) allows local guest OS privileged users to
    cause a denial of service (host memory consumption and
    QEMU process crash) via a large number of device unplug
    operations.(CVE-2017-5525)

  - The xhci_kick_epctx function in hw/usb/hcd-xhci.c in
    QEMU (aka Quick Emulator) allows local guest OS
    privileged users to cause a denial of service (infinite
    loop and QEMU process crash) via vectors related to
    control transfer descriptor sequence.(CVE-2017-5973)

  - The sdhci_sdma_transfer_multi_blocks function in
    hw/sd/sdhci.c in QEMU (aka Quick Emulator) allows local
    OS guest privileged users to cause a denial of service
    (infinite loop and QEMU process crash) via vectors
    involving the transfer mode register during multi block
    transfer.(CVE-2017-5987)

  - Memory leak in the megasas_handle_dcmd function in
    hw/scsi/megasas.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption) via MegaRAID Firmware
    Interface (MFI) commands with the sglist size set to a
    value over 2 Gb.(CVE-2017-5856)

  - qemu_deliver_packet_iov in net/net.c in Qemu accepts
    packet sizes greater than INT_MAX, which allows
    attackers to cause a denial of service or possibly have
    unspecified other impact.(CVE-2018-17963)

  - qemu-bridge-helper.c in QEMU 4.0.0 does not ensure that
    a network interface name (obtained from bridge.conf or
    a --br=bridge option) is limited to the IFNAMSIZ size,
    which can lead to an ACL bypass.(CVE-2019-13164)

  - Buffer overflow in the 'megasas_mmio_write' function in
    Qemu 2.9.0 allows remote attackers to have unspecified
    impact via unknown vectors.(CVE-2017-8380)

  - Quick Emulator (Qemu) built with the VirtFS, host
    directory sharing via Plan 9 File System(9pfs) support,
    is vulnerable to an improper access control issue. It
    could occur while accessing virtfs metadata files in
    mapped-file security mode. A guest user could use this
    flaw to escalate their privileges inside
    guest.(CVE-2017-7493)

  - In QEMU 3.1.0, load_device_tree in device_tree.c calls
    the deprecated load_image function, which has a buffer
    overflow risk.(CVE-2018-20815)

  - Use-after-free vulnerability in the sofree function in
    slirp/socket.c in QEMU (aka Quick Emulator) allows
    attackers to cause a denial of service (QEMU instance
    crash) by leveraging failure to properly clear ifq_so
    from pending packets.(CVE-2017-13711)

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

  - The imx_fec_do_tx function in hw/net/imx_fec.c in QEMU
    (aka Quick Emulator) does not properly limit the buffer
    descriptor count when transmitting packets, which
    allows local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of
    0 and crafted values in bd.flags.(CVE-2016-7907)

  - tcp_emu in slirp/tcp_subr.c (aka slirp/src/tcp_subr.c)
    in QEMU 3.0.0 uses uninitialized data in an snprintf
    call, leading to Information disclosure.(CVE-2019-9824)

  - interface_release_resource in hw/display/qxl.c in QEMU
    4.0.0 has a NULL pointer dereference.(CVE-2019-12155)

  - hw/scsi/vmw_pvscsi.c in QEMU (aka Quick Emulator)
    allows local guest OS privileged users to cause a
    denial of service (infinite loop and CPU consumption)
    via the message ring page count.(CVE-2017-8112)

  - Qemu has a Buffer Overflow in rtl8139_do_receive in
    hw/net/rtl8139.c because an incorrect integer data type
    is used.(CVE-2018-17958)

  - TSX Asynchronous Abort condition on some CPUs utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access.(CVE-2019-11135)

  - In QEMU 1:4.1-1, 1:2.1+dfsg-12+deb8u6,
    1:2.8+dfsg-6+deb9u8, 1:3.1+dfsg-8~deb10u1,
    1:3.1+dfsg-8+deb10u2, and 1:2.1+dfsg-12+deb8u12
    (fixed), when executing script in lsi_execute_script(),
    the LSI scsi adapter emulator advances 's->dsp' index
    to read next opcode. This can lead to an infinite loop
    if the next opcode is empty. Move the existing loop
    exit after 10k iterations so that it covers no-op
    opcodes as well.(CVE-2019-12068)

  - qemu-seccomp.c in QEMU might allow local OS guest users
    to cause a denial of service (guest crash) by
    leveraging mishandling of the seccomp policy for
    threads other than the main thread.(CVE-2018-15746)

  - Qemu has a Buffer Overflow in pcnet_receive in
    hw/net/pcnet.c because an incorrect integer data type
    is used.(CVE-2018-17962)

  - Quick Emulator(Qemu) built with the VMWARE PVSCSI
    paravirtual SCSI bus emulation support is vulnerable to
    an OOB r/w access issue. It could occur while
    processing SCSI commands 'PVSCSI_CMD_SETUP_RINGS' or
    'PVSCSI_CMD_SETUP_MSG_RING'. A privileged user inside
    guest could use this flaw to crash the Qemu process
    resulting in DoS.(CVE-2016-4952)

  - m_cat in slirp/mbuf.c in Qemu has a heap-based buffer
    overflow via incoming fragmented
    datagrams.(CVE-2018-11806)

  - In Qemu 3.0.0, lsi_do_msgin in hw/scsi/lsi53c895a.c
    allows out-of-bounds access by triggering an invalid
    msg_len value.(CVE-2018-18849)

  - hw/9pfs/cofile.c and hw/9pfs/9p.c in QEMU can modify an
    fid path while it is being accessed by a second thread,
    leading to (for example) a use-after-free
    outcome.(CVE-2018-19364)

  - v9fs_wstat in hw/9pfs/9p.c in QEMU allows guest OS
    users to cause a denial of service (crash) because of a
    race condition during file renaming.(CVE-2018-19489)

  - QEMU, through version 2.10 and through version 3.1.0,
    is vulnerable to an out-of-bounds read of up to 128
    bytes in the hw/i2c/i2c-ddc.c:i2c_ddc() function. A
    local attacker with permission to execute i2c commands
    could exploit this to read stack memory of the qemu
    process on the host.(CVE-2019-3812)

  - A flaw was found in QEMU's Media Transfer Protocol
    (MTP). The code opening files in usb_mtp_get_object and
    usb_mtp_get_partial_object and directories in
    usb_mtp_object_readdir doesn't consider that the
    underlying filesystem may have changed since the time
    lstat(2) was called in usb_mtp_object_alloc, a
    classical TOCTTOU problem. An attacker with write
    access to the host filesystem, shared with a guest, can
    use this property to navigate the host filesystem in
    the context of the QEMU process and read any file the
    QEMU process has access to. Access to the filesystem
    may be local or via a network share protocol such as
    CIFS.(CVE-2018-16872)

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

  - Quick Emulator (QEMU) built with Network Block Device
    (NBD) Server support was vulnerable to a null-pointer
    dereference issue. The flaw could occur when releasing
    a client that was not initialized due to failed
    negotiation. A remote user or process could exploit
    this flaw to crash the qemu-nbd server (denial of
    service).(CVE-2017-9524)

  - Qemu has integer overflows because IOReadHandler and
    its associated functions use a signed integer data type
    for a size value.(CVE-2018-18438)

  - The Bluetooth subsystem in QEMU mishandles negative
    values for length variables, leading to memory
    corruption.(CVE-2018-19665)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1790
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67642d52");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-gpu-specs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-gpu-specs-2.8.1-30.184",
        "qemu-guest-agent-2.8.1-30.184",
        "qemu-img-2.8.1-30.184",
        "qemu-kvm-2.8.1-30.184",
        "qemu-kvm-common-2.8.1-30.184",
        "qemu-kvm-tools-2.8.1-30.184",
        "qemu-seabios-2.8.1-30.184"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
