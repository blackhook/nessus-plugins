#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3388-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102424);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-2167", "CVE-2016-8734", "CVE-2017-9800");
  script_xref(name:"USN", value:"3388-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.04 : subversion vulnerabilities (USN-3388-1)");
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
"Joern Schneeweisz discovered that Subversion did not properly handle
host names in 'svn+ssh://' URLs. A remote attacker could use this to
construct a subversion repository that when accessed could run
arbitrary code with the privileges of the user. (CVE-2017-9800)

Daniel Shahaf and James McCoy discovered that Subversion did not
properly verify realms when using Cyrus SASL authentication. A remote
attacker could use this to possibly bypass intended access
restrictions. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2016-2167)

Florian Weimer discovered that Subversion clients did not properly
restrict XML entity expansion when accessing http(s):// URLs. A remote
attacker could use this to cause a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-8734).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3388-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
var release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-svn", pkgver:"1.8.8-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libapache2-svn", pkgver:"1.8.8-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libsvn1", pkgver:"1.8.8-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"subversion", pkgver:"1.8.8-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-svn", pkgver:"1.9.3-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libapache2-svn", pkgver:"1.9.3-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libsvn1", pkgver:"1.9.3-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"subversion", pkgver:"1.9.3-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libsvn1", pkgver:"1.9.5-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"subversion", pkgver:"1.9.5-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-svn / libapache2-svn / libsvn1 / subversion");
}
