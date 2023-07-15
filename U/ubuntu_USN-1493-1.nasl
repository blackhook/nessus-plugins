#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1493-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59816);
  script_version("1.9");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-2313", "CVE-2012-2319");
  script_xref(name:"USN", value:"1493-1");

  script_name(english:"Ubuntu 8.04 LTS : linux vulnerabilities (USN-1493-1)");
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
"Stephan Mueller reported a flaw in the Linux kernel's dl2k network
driver's handling of ioctls. An unprivileged local user could leverage
this flaw to cause a denial of service. (CVE-2012-2313)

Timo Warns reported multiple flaws in the Linux kernel's hfsplus
filesystem. An unprivileged local user could exploit these flaws to
gain root system priviliges. (CVE-2012-2319).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1493-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/01");
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
if (! preg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2012-2313", "CVE-2012-2319");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1493-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-386", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-generic", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-lpia", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-lpiacompat", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-openvz", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-rt", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-server", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-virtual", pkgver:"2.6.24-31.102")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-31-xen", pkgver:"2.6.24-31.102")) flag++;

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
