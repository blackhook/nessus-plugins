#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1535-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61513);
  script_version("1.9");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-2136", "CVE-2012-2390");
  script_xref(name:"USN", value:"1535-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-1535-1)");
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
"An error was discovered in the Linux kernel's network TUN/TAP device
implementation. A local user with access to the TUN/TAP interface
(which is not available to unprivileged users until granted by a root
user) could exploit this flaw to crash the system or potential gain
administrative privileges. (CVE-2012-2136)

An error was discovered in the Linux kernel's memory subsystem
(hugetlb). An unprivileged local user could exploit this flaw to cause
a denial of service (crash the system). (CVE-2012-2390).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1535-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
release = chomp(release);
if (! preg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2012-2136", "CVE-2012-2390");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1535-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-386", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-generic", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-generic-pae", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-lpia", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-preempt", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-server", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-versatile", pkgver:"2.6.32-42.95")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-42-virtual", pkgver:"2.6.32-42.95")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
