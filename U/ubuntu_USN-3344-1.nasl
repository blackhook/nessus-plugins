#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3344-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101154);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-1000363", "CVE-2017-7487", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_xref(name:"USN", value:"3344-1");

  script_name(english:"Ubuntu 16.04 LTS : linux, linux-aws, linux-gke, linux-raspi2, linux-snapdragon vulnerabilities (USN-3344-1)");
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
"USN 3328-1 fixed a vulnerability in the Linux kernel. However, that
fix introduced regressions for some Java applications. This update
addresses the issue. We apologize for the inconvenience.

Roee Hay discovered that the parallel port printer driver in the Linux
kernel did not properly bounds check passed arguments. A local
attacker with write access to the kernel command line arguments could
use this to execute arbitrary code. (CVE-2017-1000363)

A reference count bug was discovered in the Linux kernel ipx protocol
stack. A local attacker could exploit this flaw to cause a denial of
service or possibly other unspecified problems. (CVE-2017-7487)

It was discovered that a double-free vulnerability existed in the IPv4
stack of the Linux kernel. An attacker could use this to cause a
denial of service (system crash). (CVE-2017-8890)

Andrey Konovalov discovered an IPv6 out-of-bounds read error in the
Linux kernel's IPv6 stack. A local attacker could cause a denial of
service or potentially other unspecified problems. (CVE-2017-9074)

Andrey Konovalov discovered a flaw in the handling of inheritance in
the Linux kernel's IPv6 stack. A local user could exploit this issue
to cause a denial of service or possibly other unspecified problems.
(CVE-2017-9075)

It was discovered that dccp v6 in the Linux kernel mishandled
inheritance. A local attacker could exploit this issue to cause a
denial of service or potentially other unspecified problems.
(CVE-2017-9076)

It was discovered that the transmission control protocol (tcp) v6 in
the Linux kernel mishandled inheritance. A local attacker could
exploit this issue to cause a denial of service or potentially other
unspecified problems. (CVE-2017-9077)

It was discovered that the IPv6 stack in the Linux kernel was
performing its over write consistency check after the data was
actually overwritten. A local attacker could exploit this flaw to
cause a denial of service (system crash). (CVE-2017-9242).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3344-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-1000363", "CVE-2017-7487", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3344-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1018-gke", pkgver:"4.4.0-1018.18")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1022-aws", pkgver:"4.4.0-1022.31")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1061-raspi2", pkgver:"4.4.0-1061.69")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1063-snapdragon", pkgver:"4.4.0-1063.68")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-83-generic", pkgver:"4.4.0-83.106")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-83-generic-lpae", pkgver:"4.4.0-83.106")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-83-lowlatency", pkgver:"4.4.0-83.106")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1022.25")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.83.89")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.83.89")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.4.0.1018.20")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.83.89")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1061.62")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1063.56")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
