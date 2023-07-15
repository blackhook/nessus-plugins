#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3276-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100248);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-6252", "CVE-2017-2616");
  script_xref(name:"USN", value:"3276-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : shadow regression (USN-3276-2)");
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
"USN-3276-1 intended to fix a vulnerability in su. The solution
introduced a regression in su signal handling. This update modifies
the security fix. We apologize for the inconvenience.

Sebastian Krahmer discovered integer overflows in shadow utilities. A
local attacker could possibly cause them to crash or potentially gain
privileges via crafted input. (CVE-2016-6252)

Tobias Stockmann discovered a race condition in su. A local
attacker could cause su to send SIGKILL to other processes
with root privileges. (CVE-2017-2616).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3276-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected login, passwd and / or uidmap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:passwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uidmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
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
if (! preg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"login", pkgver:"1:4.1.5.1-1ubuntu9.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"passwd", pkgver:"1:4.1.5.1-1ubuntu9.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"uidmap", pkgver:"1:4.1.5.1-1ubuntu9.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"login", pkgver:"1:4.2-3.1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"passwd", pkgver:"1:4.2-3.1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"uidmap", pkgver:"1:4.2-3.1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"login", pkgver:"1:4.2-3.2ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"passwd", pkgver:"1:4.2-3.2ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"uidmap", pkgver:"1:4.2-3.2ubuntu1.16.10.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"login", pkgver:"1:4.2-3.2ubuntu1.17.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"passwd", pkgver:"1:4.2-3.2ubuntu1.17.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"uidmap", pkgver:"1:4.2-3.2ubuntu1.17.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "login / passwd / uidmap");
}
