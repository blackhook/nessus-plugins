#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4308-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(134758);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-12387", "CVE-2019-12855", "CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515", "CVE-2020-10108", "CVE-2020-10109");
  script_xref(name:"USN", value:"4308-1");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 : Twisted vulnerabilities (USN-4308-1) (Ping Flood) (Reset Flood) (Settings Flood)");
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
"it was discovered that Twisted incorrectly validated or sanitized
certain URIs or HTTP methods. A remote attacker could use this issue
to inject invalid characters and possibly perform header injection
attacks. (CVE-2019-12387)

It was discovered that Twisted incorrectly verified XMPP TLS
certificates. A remote attacker could possibly use this issue to
perform a man-in-the-middle attack and obtain sensitive information.
(CVE-2019-12855)

It was discovered that Twisted incorrectly handled HTTP/2 connections.
A remote attacker could possibly use this issue to cause Twisted to
hang or consume resources, leading to a denial of service. This issue
only affected Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2019-9512,
CVE-2019-9514, CVE-2019-9515)

Jake Miller and ZeddYu Lu discovered that Twisted incorrectly handled
certain content-length headers. A remote attacker could possibly use
this issue to perform HTTP request splitting attacks. (CVE-2020-10108,
CVE-2020-10109).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4308-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10109");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"python-twisted", pkgver:"16.0.0-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python-twisted-bin", pkgver:"16.0.0-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python-twisted-web", pkgver:"16.0.0-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3-twisted", pkgver:"16.0.0-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python-twisted", pkgver:"17.9.0-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python-twisted-bin", pkgver:"17.9.0-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python-twisted-web", pkgver:"17.9.0-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3-twisted", pkgver:"17.9.0-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3-twisted-bin", pkgver:"17.9.0-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python-twisted", pkgver:"18.9.0-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python-twisted-bin", pkgver:"18.9.0-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python-twisted-web", pkgver:"18.9.0-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python3-twisted", pkgver:"18.9.0-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python3-twisted-bin", pkgver:"18.9.0-3ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-twisted / python-twisted-bin / python-twisted-web / etc");
}
