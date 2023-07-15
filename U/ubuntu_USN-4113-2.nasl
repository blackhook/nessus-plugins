#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4113-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128993);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-0197", "CVE-2019-10081", "CVE-2019-10082", "CVE-2019-10092", "CVE-2019-10097", "CVE-2019-10098", "CVE-2019-9517");
  script_xref(name:"USN", value:"4113-2");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 : Apache HTTP Server regression (USN-4113-2) (Internal Data Buffering)");
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
"USN-4113-1 fixed vulnerabilities in the Apache HTTP server.
Unfortunately, that update introduced a regression when proxying
balancer manager connections in some configurations. This update fixes
the problem.

We apologize for the inconvenience.

Stefan Eissing discovered that the HTTP/2 implementation in Apache did
not properly handle upgrade requests from HTTP/1.1 to HTTP/2 in some
situations. A remote attacker could use this to cause a denial of
service (daemon crash). This issue only affected Ubuntu 18.04 LTS and
Ubuntu 19.04. (CVE-2019-0197)

Craig Young discovered that a memory overwrite error existed in Apache
when performing HTTP/2 very early pushes in some situations. A remote
attacker could use this to cause a denial of service (daemon crash).
This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04.
(CVE-2019-10081)

Craig Young discovered that a read-after-free error existed in the
HTTP/2 implementation in Apache during connection shutdown. A remote
attacker could use this to possibly cause a denial of service (daemon
crash) or possibly expose sensitive information. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 19.04. (CVE-2019-10082)

Matei Badanoiu discovered that the mod_proxy component of Apache did
not properly filter URLs when reporting errors in some configurations.
A remote attacker could possibly use this issue to conduct cross-site
scripting (XSS) attacks. (CVE-2019-10092)

Daniel McCarney discovered that mod_remoteip component of Apache
contained a stack buffer overflow when parsing headers from a trusted
intermediary proxy in some situations. A remote attacker controlling a
trusted proxy could use this to cause a denial of service or possibly
execute arbitrary code. This issue only affected Ubuntu 19.04.
(CVE-2019-10097)

Yukitsugu Sasaki discovered that the mod_rewrite component in Apache
was vulnerable to open redirects in some situations. A remote attacker
could use this to possibly expose sensitive information or bypass
intended restrictions. (CVE-2019-10098)

Jonathan Looney discovered that the HTTP/2 implementation in Apache
did not properly limit the amount of buffering for client connections
in some situations. A remote attacker could use this to cause a denial
of service (unresponsive daemon). This issue only affected Ubuntu
18.04 LTS and Ubuntu 19.04. (CVE-2019-9517).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4113-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected apache2 and / or apache2-bin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"apache2", pkgver:"2.4.18-2ubuntu3.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"apache2-bin", pkgver:"2.4.18-2ubuntu3.13")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"apache2", pkgver:"2.4.29-1ubuntu4.11")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"apache2-bin", pkgver:"2.4.29-1ubuntu4.11")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"apache2", pkgver:"2.4.38-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"apache2-bin", pkgver:"2.4.38-2ubuntu2.3")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-bin");
}
