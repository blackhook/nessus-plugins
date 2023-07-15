#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1936-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69419);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:29");

  script_cve_id("CVE-2013-1059", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-4125", "CVE-2013-4127", "CVE-2013-4247");
  script_bugtraq_id(61800);
  script_xref(name:"USN", value:"1936-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-raring vulnerabilities (USN-1936-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chanam Park reported a NULL pointer flaw in the Linux kernel's Ceph
client. A remote attacker could exploit this flaw to cause a denial of
service (system crash). (CVE-2013-1059)

An information leak was discovered in the Linux kernel's fanotify
interface. A local user could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2013-2148)

Jonathan Salwan discovered an information leak in the Linux kernel's
cdrom driver. A local user can exploit this leak to obtain sensitive
information from kernel memory if the CD-ROM drive is malfunctioning.
(CVE-2013-2164)

Kees Cook discovered a format string vulnerability in the Linux
kernel's disk block layer. A local user with administrator privileges
could exploit this flaw to gain kernel privileges. (CVE-2013-2851)

Hannes Frederic Sowa discovered that the Linux kernel's IPv6 stack
does not correctly handle Router Advertisement (RA) message in some
cases. A remote attacker could exploit this flaw to cause a denial of
service (system crash). (CVE-2013-4125)

A vulnerability was discovered in the Linux kernel's vhost net driver.
A local user could cause a denial of service (system crash) by
powering on a virtual machine. (CVE-2013-4127)

Marcus Moeller and Ken Fallon discovered that the CIFS incorrectly
built certain paths. A local attacker with access to a CIFS partition
could exploit this to crash the system, leading to a denial of
service. (CVE-2013-4247).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1936-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.8-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.8-generic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2019 Canonical, Inc. / NASL script (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2013-1059", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-4125", "CVE-2013-4127", "CVE-2013-4247");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1936-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.8.0-29-generic", pkgver:"3.8.0-29.42~precise1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.8-generic");
}
