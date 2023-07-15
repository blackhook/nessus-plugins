#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3422-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103326);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-10044", "CVE-2016-10200", "CVE-2016-7097", "CVE-2016-8650", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9178", "CVE-2016-9191", "CVE-2016-9604", "CVE-2016-9754", "CVE-2017-1000251", "CVE-2017-5970", "CVE-2017-6214", "CVE-2017-6346", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7472", "CVE-2017-7541");
  script_xref(name:"USN", value:"3422-1");

  script_name(english:"Ubuntu 14.04 LTS : linux vulnerabilities (USN-3422-1) (BlueBorne)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that a buffer overflow existed in the Bluetooth
stack of the Linux kernel when handling L2CAP configuration responses.
A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2017-1000251)

It was discovered that the asynchronous I/O (aio) subsystem of the
Linux kernel did not properly set permissions on aio memory mappings
in some situations. An attacker could use this to more easily exploit
other vulnerabilities. (CVE-2016-10044)

Baozeng Ding and Andrey Konovalov discovered a race condition in the
L2TPv3 IP Encapsulation implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2016-10200)

Andreas Gruenbacher and Jan Kara discovered that the filesystem
implementation in the Linux kernel did not clear the setgid bit during
a setxattr call. A local attacker could use this to possibly elevate
group privileges. (CVE-2016-7097)

Sergej Schumilo, Ralf Spenneberg, and Hendrik Schwartke discovered
that the key management subsystem in the Linux kernel did not properly
allocate memory in some situations. A local attacker could use this to
cause a denial of service (system crash). (CVE-2016-8650)

Vlad Tsyrklevich discovered an integer overflow vulnerability in the
VFIO PCI driver for the Linux kernel. A local attacker with access to
a vfio PCI device file could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2016-9083,
CVE-2016-9084)

It was discovered that an information leak existed in
__get_user_asm_ex() in the Linux kernel. A local attacker could use
this to expose sensitive information. (CVE-2016-9178)

CAI Qian discovered that the sysctl implementation in the Linux kernel
did not properly perform reference counting in some situations. An
unprivileged attacker could use this to cause a denial of service
(system hang). (CVE-2016-9191)

It was discovered that the keyring implementation in the Linux kernel
in some situations did not prevent special internal keyrings from
being joined by userspace keyrings. A privileged local attacker could
use this to bypass module verification. (CVE-2016-9604)

It was discovered that an integer overflow existed in the trace
subsystem of the Linux kernel. A local privileged attacker could use
this to cause a denial of service (system crash). (CVE-2016-9754)

Andrey Konovalov discovered that the IPv4 implementation in the Linux
kernel did not properly handle invalid IP options in some situations.
An attacker could use this to cause a denial of service or possibly
execute arbitrary code. (CVE-2017-5970)

Dmitry Vyukov discovered that the Linux kernel did not properly handle
TCP packets with the URG flag. A remote attacker could use this to
cause a denial of service. (CVE-2017-6214)

It was discovered that a race condition existed in the AF_PACKET
handling code in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-6346)

It was discovered that the keyring implementation in the Linux kernel
did not properly restrict searches for dead keys. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2017-6951)

Dmitry Vyukov discovered that the generic SCSI (sg) subsystem in the
Linux kernel contained a stack-based buffer overflow. A local attacker
with access to an sg device could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-7187)

Eric Biggers discovered a memory leak in the keyring implementation in
the Linux kernel. A local attacker could use this to cause a denial of
service (memory consumption). (CVE-2017-7472)

It was discovered that a buffer overflow existed in the Broadcom
FullMAC WLAN driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-7541).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3422-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2016-10044", "CVE-2016-10200", "CVE-2016-7097", "CVE-2016-8650", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9178", "CVE-2016-9191", "CVE-2016-9604", "CVE-2016-9754", "CVE-2017-1000251", "CVE-2017-5970", "CVE-2017-6214", "CVE-2017-6346", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7472", "CVE-2017-7541");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3422-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-132-generic", pkgver:"3.13.0-132.181")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-132-generic-lpae", pkgver:"3.13.0-132.181")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-132-lowlatency", pkgver:"3.13.0-132.181")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic", pkgver:"3.13.0.132.141")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae", pkgver:"3.13.0.132.141")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency", pkgver:"3.13.0.132.141")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae / etc");
}
