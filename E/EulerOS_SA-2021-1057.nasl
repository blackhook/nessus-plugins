#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144829);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2017-7493",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-8380",
    "CVE-2017-13711",
    "CVE-2017-16845",
    "CVE-2017-18030",
    "CVE-2018-11806",
    "CVE-2018-17958",
    "CVE-2018-17962",
    "CVE-2018-17963",
    "CVE-2018-20815",
    "CVE-2019-12155",
    "CVE-2019-13164",
    "CVE-2019-14378",
    "CVE-2019-20175",
    "CVE-2020-14364"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.6 : qemu (EulerOS-SA-2021-1057)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - Quick Emulator (Qemu) built with the VirtFS, host
    directory sharing via Plan 9 File System(9pfs) support,
    is vulnerable to an improper access control issue. It
    could occur while accessing virtfs metadata files in
    mapped-file security mode. A guest user could use this
    flaw to escalate their privileges inside
    guest.(CVE-2017-7493)

  - qemu-bridge-helper.c in QEMU 4.0.0 does not ensure that
    a network interface name (obtained from bridge.conf or
    a --br=bridge option) is limited to the IFNAMSIZ size,
    which can lead to an ACL bypass.(CVE-2019-13164)

  - Qemu has a Buffer Overflow in pcnet_receive in
    hw/net/pcnet.c because an incorrect integer data type
    is used.(CVE-2018-17962)

  - Buffer overflow in the 'megasas_mmio_write' function in
    Qemu 2.9.0 allows remote attackers to have unspecified
    impact via unknown vectors.(CVE-2017-8380)

  - qemu_deliver_packet_iov in net/net.c in Qemu accepts
    packet sizes greater than INT_MAX, which allows
    attackers to cause a denial of service or possibly have
    unspecified other impact.(CVE-2018-17963)

  - In QEMU 3.1.0, load_device_tree in device_tree.c calls
    the deprecated load_image function, which has a buffer
    overflow risk.(CVE-2018-20815)

  - interface_release_resource in hw/display/qxl.c in QEMU
    4.0.0 has a NULL pointer dereference.(CVE-2019-12155)

  - An issue was discovered in ide_dma_cb() in
    hw/ide/core.c in QEMU 2.4.0 through 4.2.0. The guest
    system can crash the QEMU process in the host system
    via a special SCSI_IOCTL_SEND_COMMAND. It hits an
    assertion that implies that the size of successful DMA
    transfers there must be a multiple of 512 (the size of
    a sector). NOTE: a member of the QEMU security team
    disputes the significance of this issue because a
    'privileged guest user has many ways to cause similar
    DoS effect, without triggering this
    assert.'(CVE-2019-20175)

  - Use-after-free vulnerability in the sofree function in
    slirp/socket.c in QEMU (aka Quick Emulator) allows
    attackers to cause a denial of service (QEMU instance
    crash) by leveraging failure to properly clear ifq_so
    from pending packets.(CVE-2017-13711)

  - Qemu has a Buffer Overflow in rtl8139_do_receive in
    hw/net/rtl8139.c because an incorrect integer data type
    is used.(CVE-2018-17958)

  - ip_reass in ip_input.c in libslirp 4.0.0 has a
    heap-based buffer overflow via a large packet because
    it mishandles a case involving the first
    fragment.(CVE-2019-14378)

  - m_cat in slirp/mbuf.c in Qemu has a heap-based buffer
    overflow via incoming fragmented
    datagrams.(CVE-2018-11806)

  - Memory leak in the audio/audio.c in QEMU (aka Quick
    Emulator) allows remote attackers to cause a denial of
    service (memory consumption) by repeatedly starting and
    stopping audio capture.(CVE-2017-8309)

  - Memory leak in the keyboard input event handlers
    support in QEMU (aka Quick Emulator) allows local guest
    OS privileged users to cause a denial of service (host
    memory consumption) by rapidly generating large
    keyboard events.(CVE-2017-8379)

  - hw/input/ps2.c in Qemu does not validate 'rptr' and
    'count' values during guest migration, leading to
    out-of-bounds access(CVE-2017-16845)

  - The cirrus_invalidate_region function in
    hw/display/cirrus_vga.c in Qemu allows local OS guest
    privileged users to cause a denial of service
    (out-of-bounds array access and QEMU process crash) via
    vectors related to negative pitch.(CVE-2017-18030)

  - An out-of-bounds read/write access flaw was found in
    the USB emulator of the QEMU in versions before 5.2.0.
    This issue occurs while processing USB packets from a
    guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out
    routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the
    potential execution of arbitrary code with the
    privileges of the QEMU process on the
    host.(CVE-2020-14364)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1057
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9108692");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20815");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-gpu-specs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.6");
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
if (uvp != "3.0.2.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-gpu-specs-2.8.1-30.086",
        "qemu-kvm-2.8.1-30.086",
        "qemu-kvm-common-2.8.1-30.086",
        "qemu-kvm-tools-2.8.1-30.086"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
