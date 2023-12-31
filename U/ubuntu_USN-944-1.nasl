#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-944-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46731);
  script_version("1.12");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2008-1391", "CVE-2009-4880", "CVE-2010-0296", "CVE-2010-0830");
  script_bugtraq_id(36443, 40063);
  script_xref(name:"USN", value:"944-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : glibc, eglibc vulnerabilities (USN-944-1)");
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
"Maksymilian Arciemowicz discovered that the GNU C library did not
correctly handle integer overflows in the strfmon function. If a user
or automated system were tricked into processing a specially crafted
format string, a remote attacker could crash applications, leading to
a denial of service. (Ubuntu 10.04 was not affected.) (CVE-2008-1391)

Jeff Layton and Dan Rosenberg discovered that the GNU C library did
not correctly handle newlines in the mntent family of functions. If a
local attacker were able to inject newlines into a mount entry through
other vulnerable mount helpers, they could disrupt the system or
possibly gain root privileges. (CVE-2010-0296)

Dan Rosenberg discovered that the GNU C library did not correctly
validate certain ELF program headers. If a user or automated system
were tricked into verifying a specially crafted ELF program, a remote
attacker could execute arbitrary code with user privileges.
(CVE-2010-0830).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/944-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eglibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-sparcv9b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-sparcv9v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2019 Canonical, Inc. / NASL script (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"glibc-doc", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-amd64", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-dbg", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-dev", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-dev-amd64", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-dev-i386", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-i386", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-i686", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-pic", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-prof", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-sparcv9b", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libc6-sparcv9v", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nscd", pkgver:"2.3.6-0ubuntu20.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"glibc-doc", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"glibc-source", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-amd64", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dbg", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dev", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dev-amd64", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dev-i386", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-i386", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-i686", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-pic", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-prof", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-xen", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nscd", pkgver:"2.7-10ubuntu6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"glibc-doc", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"glibc-source", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-amd64", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-dbg", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-dev", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-dev-amd64", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-dev-i386", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-i386", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-i686", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-pic", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-prof", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libc6-xen", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"nscd", pkgver:"2.9-4ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"eglibc-source", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"glibc-doc", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc-bin", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc-dev-bin", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-amd64", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dbg", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dev", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dev-amd64", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dev-i386", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-i386", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-i686", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-pic", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-prof", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-xen", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"nscd", pkgver:"2.10.1-0ubuntu17")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"eglibc-source", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"glibc-doc", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc-bin", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc-dev-bin", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-amd64", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dbg", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dev", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dev-amd64", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dev-i386", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-i386", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-i686", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-pic", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-prof", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-xen", pkgver:"2.11.1-0ubuntu7.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"nscd", pkgver:"2.11.1-0ubuntu7.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eglibc-source / glibc-doc / glibc-source / libc-bin / libc-dev-bin / etc");
}
