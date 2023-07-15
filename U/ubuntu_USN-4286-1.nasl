#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4286-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133799);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14615", "CVE-2019-15217", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-17351", "CVE-2019-19051", "CVE-2019-19056", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108");
  script_xref(name:"USN", value:"4286-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-4286-1)");
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
"It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors.
A local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that a race condition existed in the Softmac USB
Prism54 device driver in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-15220)

Julien Grall discovered that the Xen balloon memory driver in the
Linux kernel did not properly restrict the amount of memory set aside
for page mappings in some situations. An attacker could use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-17351)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel
did not properly deallocate memory in certain situations. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19051)

It was discovered that the Marvell Wi-Fi device driver in the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to possibly cause a denial of service
(kernel memory exhaustion). (CVE-2019-19056)

It was discovered that the Brocade BFA Fibre Channel device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19066)

It was discovered that the Realtek RTL8xxx USB Wi-Fi device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19068)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer
dereference. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2019-19965)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
implementation in the Linux kernel did not properly deallocate memory
in certain error conditions. An attacker could possibly use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-20096)

Mitchell Frank discovered that the Wi-Fi implementation in the Linux
kernel when used as an access point would send IAPP location updates
for stations before client authentication had completed. A physically
proximate attacker could use this to cause a denial of service.
(CVE-2019-5108)

It was discovered that ZR364XX Camera USB device driver for the Linux
kernel did not properly initialize memory. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-15217)

It was discovered that the Line 6 POD USB device driver in the Linux
kernel did not properly validate data size information from the
device. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2019-15221).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4286-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14615");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-14615", "CVE-2019-15217", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-17351", "CVE-2019-19051", "CVE-2019-19056", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4286-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1066-kvm", pkgver:"4.4.0-1066.73")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1102-aws", pkgver:"4.4.0-1102.113")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1129-raspi2", pkgver:"4.4.0-1129.138")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1133-snapdragon", pkgver:"4.4.0-1133.141")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-174-generic", pkgver:"4.4.0-174.204")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-174-generic-lpae", pkgver:"4.4.0-174.204")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-174-lowlatency", pkgver:"4.4.0-174.204")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1102.106")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.174.182")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.174.182")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1066.66")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.174.182")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1129.129")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1133.125")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual", pkgver:"4.4.0.174.182")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
