#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2093-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72232);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-6436", "CVE-2013-6457", "CVE-2013-6458", "CVE-2014-0028", "CVE-2014-1447");
  script_bugtraq_id(64549, 64723, 64945, 64963, 65004);
  script_xref(name:"USN", value:"2093-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : libvirt vulnerabilities (USN-2093-1)");
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
"Martin Kletzander discovered that libvirt incorrectly handled reading
memory tunables from LXC guests. A local user could possibly use this
flaw to cause libvirtd to crash, resulting in a denial of service.
This issue only affected Ubuntu 13.10. (CVE-2013-6436)

Dario Faggioli discovered that libvirt incorrectly handled the libxl
driver. A local user could possibly use this flaw to cause libvirtd to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 13.10. (CVE-2013-6457)

It was discovered that libvirt contained multiple race conditions in
block device handling. A remote read-only user could use this flaw to
cause libvirtd to crash, resulting in a denial of service.
(CVE-2013-6458)

Eric Blake discovered that libvirt incorrectly handled certain ACLs.
An attacker could use this flaw to possibly obtain certain sensitive
information. This issue only affected Ubuntu 13.10. (CVE-2014-0028)

Jiri Denemark discovered that libvirt incorrectly handled keepalives.
A remote attacker could possibly use this flaw to cause libvirtd to
crash, resulting in a denial of service. (CVE-2014-1447).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2093-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt-bin and / or libvirt0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libvirt-bin", pkgver:"0.9.8-2ubuntu17.17")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libvirt0", pkgver:"0.9.8-2ubuntu17.17")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libvirt-bin", pkgver:"0.9.13-0ubuntu12.6")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libvirt0", pkgver:"0.9.13-0ubuntu12.6")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libvirt-bin", pkgver:"1.1.1-0ubuntu8.5")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libvirt0", pkgver:"1.1.1-0ubuntu8.5")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt0");
}
