#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137489);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-5239",
    "CVE-2015-5278",
    "CVE-2015-5745",
    "CVE-2016-9602",
    "CVE-2017-5525",
    "CVE-2017-5526",
    "CVE-2017-6505",
    "CVE-2017-9330",
    "CVE-2018-12617",
    "CVE-2018-19364",
    "CVE-2018-19489",
    "CVE-2020-7039",
    "CVE-2020-8608"
  );

  script_name(english:"EulerOS 2.0 SP2 : qemu-kvm (EulerOS-SA-2020-1647)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - qemu-kvm is an open source virtualizer that provides
    hardware emulation for the KVM hypervisor. qemu-kvm
    acts as a virtual machine monitor together with the KVM
    kernel modules, and emulates the hardware for a full
    system such as a PC and its associated
    peripherals.Security Fix(es):In libslirp 4.1.0, as used
    in QEMU 4.2.0, tcp_subr.c misuses snprintf return
    values, leading to a buffer overflow in later
    code.(CVE-2020-8608)Integer overflow in the VNC display
    driver in QEMU before 2.1.0 allows attachers to cause a
    denial of service (process crash) via a CLIENT_CUT_TEXT
    message, which triggers an infinite
    loop.(CVE-2015-5239)The ne2000_receive function in
    hwete2000.c in QEMU before 2.4.0.1 allows attackers to
    cause a denial of service (infinite loop and instance
    crash) or possibly execute arbitrary code via vectors
    related to receiving packets.(CVE-2015-5278)Buffer
    overflow in the send_control_msg function in
    hw/char/virtio-serial-bus.c in QEMU before 2.4.0 allows
    guest users to cause a denial of service (QEMU process
    crash) via a crafted virtio control
    message.(CVE-2015-5745)tcp_emu in tcp_subr.c in
    libslirp 4.1.0, as used in QEMU 4.2.0, mismanages
    memory, as demonstrated by IRC DCC commands in EMU_IRC.
    This can cause a heap-based buffer overflow or other
    out-of-bounds access which can lead to a DoS or
    potential execute arbitrary code.(CVE-2020-7039)Qemu
    before version 2.9 is vulnerable to an improper link
    following when built with the VirtFS. A privileged user
    inside guest could use this flaw to access host file
    system beyond the shared folder and potentially
    escalating their privileges on a
    host.(CVE-2016-9602)The ohci_service_ed_list function
    in hw/usb/hcd-ohci.c in QEMU (aka Quick Emulator)
    before 2.9.0 allows local guest OS users to cause a
    denial of service (infinite loop) via vectors involving
    the number of link endpoint list descriptors, a
    different vulnerability than
    CVE-2017-9330.(CVE-2017-6505)qmp_guest_file_read in
    qga/commands-posix.c and qga/commands-win32.c in
    qemu-ga (aka QEMU Guest Agent) in QEMU 2.12.50 has an
    integer overflow causing a g_malloc0() call to trigger
    a segmentation fault when trying to allocate a large
    memory chunk. The vulnerability can be exploited by
    sending a crafted QMP command (including
    guest-file-read with a large count value) to the agent
    via the listening socket.(CVE-2018-12617)Memory leak in
    hw/audio/ac97.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption and QEMU process
    crash) via a large number of device unplug
    operations.(CVE-2017-5525)Memory leak in
    hw/audio/es1370.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption and QEMU process
    crash) via a large number of device unplug
    operations.(CVE-2017-5526)QEMU (aka Quick Emulator)
    before 2.9.0, when built with the USB OHCI Emulation
    support, allows local guest OS users to cause a denial
    of service (infinite loop) by leveraging an incorrect
    return value, a different vulnerability than
    CVE-2017-6505.(CVE-2017-9330)v9fs_wstat in hw/9pfs/9p.c
    in QEMU allows guest OS users to cause a denial of
    service (crash) because of a race condition during file
    renaming.(CVE-2018-19489)hw/9pfs/cofile.c and
    hw/9pfs/9p.c in QEMU can modify an fid path while it is
    being accessed by a second thread, leading to (for
    example) a use-after-free outcome.(CVE-2018-19364)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1647
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?263069b2");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9602");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-img-1.5.3-156.5.h31",
        "qemu-kvm-1.5.3-156.5.h31",
        "qemu-kvm-common-1.5.3-156.5.h31"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
