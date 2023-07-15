#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3343-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101153);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2014-9940", "CVE-2017-1000363", "CVE-2017-7294", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_xref(name:"USN", value:"3343-2");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-trusty vulnerabilities (USN-3343-2)");
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
"USN 3343-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 ESM.

USN 3335-2 fixed a vulnerability in the Linux kernel. However, that
fix introduced regressions for some Java applications. This update
addresses the issue. We apologize for the inconvenience.

It was discovered that a use-after-free vulnerability in the core
voltage regulator driver of the Linux kernel. A local attacker could
use this to cause a denial of service or possibly execute arbitrary
code. (CVE-2014-9940)

Roee Hay discovered that the parallel port printer driver in the Linux
kernel did not properly bounds check passed arguments. A local
attacker with write access to the kernel command line arguments could
use this to execute arbitrary code. (CVE-2017-1000363)

Li Qiang discovered that an integer overflow vulnerability existed in
the Direct Rendering Manager (DRM) driver for VMware devices in the
Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-7294)

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
  script_set_attribute(attribute:"solution", value:
"Update the affected packages. Note that the updated packages may not
be immediately available from the package repository or its mirrors.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-123-generic", pkgver:"3.13.0-123.172~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-123-generic-lpae", pkgver:"3.13.0-123.172~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-generic-lpae-lts-trusty", pkgver:"3.13.0.123.114")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-generic-lts-trusty", pkgver:"3.13.0.123.114")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae / etc");
}
