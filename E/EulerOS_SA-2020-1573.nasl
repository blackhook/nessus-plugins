#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136276);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2017-10664",
    "CVE-2017-11434",
    "CVE-2017-12809",
    "CVE-2017-13672",
    "CVE-2017-15038",
    "CVE-2017-17381",
    "CVE-2017-5579",
    "CVE-2017-5856",
    "CVE-2017-6505",
    "CVE-2017-7718",
    "CVE-2017-8086",
    "CVE-2017-9310",
    "CVE-2017-9503",
    "CVE-2018-11806",
    "CVE-2018-15746",
    "CVE-2018-17958",
    "CVE-2018-17962",
    "CVE-2018-17963",
    "CVE-2018-18954",
    "CVE-2018-20815",
    "CVE-2018-7858",
    "CVE-2019-12068",
    "CVE-2019-12155",
    "CVE-2019-12247",
    "CVE-2019-13164",
    "CVE-2019-20175",
    "CVE-2019-9824"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : qemu-kvm (EulerOS-SA-2020-1573)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - qemu-kvm is an open source virtualizer that provides
    hardware emulation for the KVM hypervisor. qemu-kvm
    acts as a virtual machine monitor together with the KVM
    kernel modules, and emulates the hardware for a full
    system such as a PC and its assocated peripherals. As
    qemu-kvm requires no host kernel patches to run, it is
    safe and easy to use. Security Fix(es):The
    ohci_service_ed_list function in hw/usb/hcd-ohci.c in
    QEMU (aka Quick Emulator) before 2.9.0 allows local
    guest OS users to cause a denial of service (infinite
    loop) via vectors involving the number of link endpoint
    list descriptors, a different vulnerability than
    CVE-2017-9330.(CVE-2017-6505)** DISPUTED ** QEMU 3.0.0
    has an Integer Overflow because the qga/commands*.c
    files do not check the length of the argument list or
    the number of environment variables. NOTE: This has
    been disputed as not exploitable.(CVE-2019-12247)**
    DISPUTED ** An issue was discovered in ide_dma_cb() in
    hw/ide/core.c in QEMU 2.4.0 through 4.2.0. The guest
    system can crash the QEMU process in the host system
    via a special SCSI_IOCTL_SEND_COMMAND. It hits an
    assertion that implies that the size of successful DMA
    transfers there must be a multiple of 512 (the size of
    a sector). NOTE: a member of the QEMU security team
    disputes the significance of this issue because a
    'privileged guest user has many ways to cause similar
    DoS effect, without triggering this
    assert.'(CVE-2019-20175)Race condition in the
    v9fs_xattrwalk function in hw/9pfs/9p.c in QEMU (aka
    Quick Emulator) allows local guest OS users to obtain
    sensitive information from host heap memory via vectors
    related to reading extended
    attributes.(cve-2017-15038)Memory leak in the
    megasas_handle_dcmd function in hw/scsi/megasas.c in
    QEMU (aka Quick Emulator) allows local guest OS
    privileged users to cause a denial of service (host
    memory consumption) via MegaRAID Firmware Interface
    (MFI) commands with the sglist size set to a value over
    2 Gb.(cve-2017-5856)QEMU (aka Quick Emulator), when
    built with the e1000e NIC emulation support, allows
    local guest OS privileged users to cause a denial of
    service (infinite loop) via vectors related to setting
    the initial receive / transmit descriptor head
    (TDH/RDH) outside the allocated descriptor
    buffer.(cve-2017-9310)QEMU (aka Quick Emulator), when
    built with MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support, allows local guest OS privileged
    users to cause a denial of service (NULL pointer
    dereference and QEMU process crash) via vectors
    involving megasas command processing.(cve-2017-9503)The
    dhcp_decode function in slirp/bootp.c in QEMU (aka
    Quick Emulator) allows local guest OS users to cause a
    denial of service (out-of-bounds read and QEMU process
    crash) via a crafted DHCP options
    string.(CVE-2017-11434)Memory leak in the
    v9fs_list_xattr function in hw/9pfs/9p-xattr.c in QEMU
    (aka Quick Emulator) allows local guest OS privileged
    users to cause a denial of service (memory consumption)
    via vectors involving the orig_value
    variable.(CVE-2017-8086)m_cat in slirp/mbuf.c in Qemu
    has a heap-based buffer overflow via incoming
    fragmented datagrams.(CVE-2018-11806)In QEMU 3.1.0,
    load_device_tree in device_tree.c calls the deprecated
    load_image function, which has a buffer overflow
    risk.(CVE-2018-20815)The pnv_lpc_do_eccb function in
    hw/ppc/pnv_lpc.c in Qemu before 3.1 allows
    out-of-bounds write or read access to PowerNV
    memory.(cve-2018-18954)qemu_deliver_packet_iov in
    net/net.c in Qemu accepts packet sizes greater than
    INT_MAX, which allows attackers to cause a denial of
    service or possibly have unspecified other
    impact.(CVE-2018-17963)Qemu has a Buffer Overflow in
    pcnet_receive in hw/net/pcnet.c because an incorrect
    integer data type is used.(CVE-2018-17962)Qemu has a
    Buffer Overflow in rtl8139_do_receive in
    hw/net/rtl8139.c because an incorrect integer data type
    is used.(CVE-2018-17958)qemu-seccomp.c in QEMU might
    allow local OS guest users to cause a denial of service
    (guest crash) by leveraging mishandling of the seccomp
    policy for threads other than the main
    thread.(CVE-2018-15746)In QEMU 1:4.1-1,
    1:2.1+dfsg-12+deb8u6, 1:2.8+dfsg-6+deb9u8,
    1:3.1+dfsg-8~deb10u1, 1:3.1+dfsg-8+deb10u2, and
    1:2.1+dfsg-12+deb8u12 (fixed), when executing script in
    lsi_execute_script(), the LSI scsi adapter emulator
    advances 's->dsp' index to read next opcode. This can
    lead to an infinite loop if the next opcode is empty.
    Move the existing loop exit after 10k iterations so
    that it covers no-op opcodes as
    well.(CVE-2019-12068)qemu-bridge-helper.c in QEMU 4.0.0
    does not ensure that a network interface name (obtained
    from bridge.conf or a --br=bridge option) is limited to
    the IFNAMSIZ size, which can lead to an ACL
    bypass.(CVE-2019-13164)tcp_emu in slirp/tcp_subr.c (aka
    slirp/src/tcp_subr.c) in QEMU 3.0.0 uses uninitialized
    data in an snprintf call, leading to Information
    disclosure.(CVE-2019-9824)interface_release_resource in
    hw/display/qxl.c in QEMU 4.0.0 has a NULL pointer
    dereference.(CVE-2019-12155)The Virtio Vring
    implementation in QEMU allows local OS guest users to
    cause a denial of service (divide-by-zero error and
    QEMU process crash) by unsetting vring alignment while
    updating Virtio
    rings.(CVE-2017-17381)hw/display/cirrus_vga_rop.h in
    QEMU (aka Quick Emulator) allows local guest OS
    privileged users to cause a denial of service
    (out-of-bounds read and QEMU process crash) via vectors
    related to copying VGA data via the
    cirrus_bitblt_rop_fwd_transp_ and
    cirrus_bitblt_rop_fwd_ functions.(CVE-2017-7718)Memory
    leak in the serial_exit_core function in
    hw/char/serial.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption and QEMU process
    crash) via a large number of device unplug
    operations.(CVE-2017-5579)Quick Emulator (aka QEMU),
    when built with the Cirrus CLGD 54xx VGA Emulator
    support, allows local guest OS privileged users to
    cause a denial of service (out-of-bounds access and
    QEMU process crash) by leveraging incorrect region
    calculation when updating VGA
    display.(CVE-2018-7858)qemu-nbd in QEMU (aka Quick
    Emulator) does not ignore SIGPIPE, which allows remote
    attackers to cause a denial of service (daemon crash)
    by disconnecting during a server-to-client reply
    attempt.(CVE-2017-10664)QEMU (aka Quick Emulator), when
    built with the VGA display emulator support, allows
    local guest OS privileged users to cause a denial of
    service (out-of-bounds read and QEMU process crash) via
    vectors involving display update.(CVE-2017-13672)QEMU
    (aka Quick Emulator), when built with the IDE disk and
    CD/DVD-ROM Emulator support, allows local guest OS
    privileged users to cause a denial of service (NULL
    pointer dereference and QEMU process crash) by flushing
    an empty CDROM device drive.(CVE-2017-12809)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1573
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b6b2cf4");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20815");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.115",
        "qemu-kvm-2.8.1-30.115",
        "qemu-kvm-common-2.8.1-30.115",
        "qemu-kvm-tools-2.8.1-30.115"];

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
