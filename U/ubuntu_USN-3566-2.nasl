#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3566-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125352);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2016-10712", "CVE-2017-11362", "CVE-2017-12933", "CVE-2018-20783", "CVE-2019-11036");
  script_xref(name:"USN", value:"3566-2");

  script_name(english:"Ubuntu 14.04 LTS : PHP vulnerabilities (USN-3566-2)");
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
"USN-3566-1 fixed several vulnerabilities in PHP. This update provides
the corresponding update for Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.

It was discovered that PHP incorrectly handled certain files. An
attacker could possibly use this issue to access sensitive
information. (CVE-2018-20783)

It was discovered that PHP incorrectly handled certain files. An
attacker could possibly use this issue to access sensitive information
or possibly cause a crash, resulting in a denial of service.
(CVE-2019-11036)

It was discovered that PHP incorrectly handled memory when
unserializing certain data. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 ESM.
(CVE-2017-12933)

It was discovered that PHP incorrectly handled locale length. A remote
attacker could possibly use this issue to cause PHP to crash,
resulting in a denial of service. This issue only affected Ubuntu
12.04 ESM. (CVE-2017-11362)

It was discovered that PHP incorrectly handled certain stream
metadata. A remote attacker could possibly use this issue to set
arbitrary metadata. This issue only affected Ubuntu 12.04 ESM.
(CVE-2016-10712).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3566-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.29+esm2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.29+esm2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.29+esm2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.29+esm2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-fpm");
}
