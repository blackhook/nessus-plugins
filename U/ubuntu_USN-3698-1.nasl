#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3698-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110900);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-12154", "CVE-2017-12193", "CVE-2017-15265", "CVE-2018-1130", "CVE-2018-3665", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7755", "CVE-2018-7757");
  script_xref(name:"USN", value:"3698-1");

  script_name(english:"Ubuntu 14.04 LTS : linux vulnerabilities (USN-3698-1)");
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
"It was discovered that the nested KVM implementation in the Linux
kernel in some situations did not properly prevent second level guests
from reading and writing the hardware CR8 register. A local attacker
in a guest could use this to cause a denial of service (system crash).
(CVE-2017-12154)

Fan Wu, Haoran Qiu, and Shixiong Zhao discovered that the associative
array implementation in the Linux kernel sometimes did not properly
handle adding a new entry. A local attacker could use this to cause a
denial of service (system crash). (CVE-2017-12193)

It was discovered that a race condition existed in the ALSA subsystem
of the Linux kernel when creating and deleting a port via ioctl(). A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-15265)

It was discovered that a NULL pointer dereference vulnerability
existed in the DCCP protocol implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system
crash). (CVE-2018-1130)

Julian Stecklina and Thomas Prescher discovered that FPU register
states (such as MMX, SSE, and AVX registers) which are lazily restored
are potentially vulnerable to a side channel attack. A local attacker
could use this to expose sensitive information. (CVE-2018-3665)

Wang Qize discovered that an information disclosure vulnerability
existed in the SMBus driver for ACPI Embedded Controllers in the Linux
kernel. A local attacker could use this to expose sensitive
information (kernel pointer addresses). (CVE-2018-5750)

It was discovered that the SCTP Protocol implementation in the Linux
kernel did not properly validate userspace provided payload lengths in
some situations. A local attacker could use this to cause a denial of
service (system crash). (CVE-2018-5803)

It was discovered that an integer overflow error existed in the futex
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2018-6927)

It was discovered that an information leak vulnerability existed in
the floppy driver in the Linux kernel. A local attacker could use this
to expose sensitive information (kernel memory). (CVE-2018-7755)

It was discovered that a memory leak existed in the SAS driver
subsystem of the Linux kernel. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2018-7757).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3698-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-12154", "CVE-2017-12193", "CVE-2017-15265", "CVE-2018-1130", "CVE-2018-3665", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7755", "CVE-2018-7757");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3698-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-153-generic", pkgver:"3.13.0-153.203")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-153-generic-lpae", pkgver:"3.13.0-153.203")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-153-lowlatency", pkgver:"3.13.0-153.203")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic", pkgver:"3.13.0.153.163")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae", pkgver:"3.13.0.153.163")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency", pkgver:"3.13.0.153.163")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
