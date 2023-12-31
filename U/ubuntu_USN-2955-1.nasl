#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2955-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90826);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-1578", "CVE-2016-1646", "CVE-2016-1647", "CVE-2016-1649", "CVE-2016-1653", "CVE-2016-1654", "CVE-2016-1655", "CVE-2016-1659", "CVE-2016-3679");
  script_xref(name:"USN", value:"2955-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 / 16.04 LTS : oxide-qt vulnerabilities (USN-2955-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A use-after-free was discovered when responding synchronously to
permission requests. An attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2016-1578)

An out-of-bounds read was discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash.
(CVE-2016-1646)

A use-after-free was discovered in the navigation implementation in
Chromium in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2016-1647)

A buffer overflow was discovered in ANGLE. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2016-1649)

An out-of-bounds write was discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed renderer
process. (CVE-2016-1653)

An invalid read was discovered in the media subsystem in Chromium. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash. (CVE-2016-1654)

It was discovered that frame removal during callback execution could
trigger a use-after-free in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed renderer
process. (CVE-2016-1655)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2016-1659)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2016-3679).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2955-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1659");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2023 Canonical, Inc. / NASL script (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.14.7-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"liboxideqtcore0", pkgver:"1.14.7-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"liboxideqtcore0", pkgver:"1.14.7-0ubuntu1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0");
}
