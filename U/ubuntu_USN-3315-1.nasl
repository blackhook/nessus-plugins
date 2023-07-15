#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3315-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100835);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-5470", "CVE-2017-5471", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7762", "CVE-2017-7764", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778");
  script_xref(name:"USN", value:"3315-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : firefox vulnerabilities (USN-3315-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, read
uninitialized memory, obtain sensitive information, spoof the
addressbar contents, or execute arbitrary code. (CVE-2017-5470,
CVE-2017-5471, CVE-2017-5472, CVE-2017-7749, CVE-2017-7750,
CVE-2017-7751, CVE-2017-7752, CVE-2017-7754, CVE-2017-7756,
CVE-2017-7757, CVE-2017-7758, CVE-2017-7762, CVE-2017-7764)

Multiple security issues were discovered in the Graphite 2 library
used by Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service, read uninitialized memory, or execute arbitrary
code. (CVE-2017-7771, CVE-2017-7772, CVE-2017-7773, CVE-2017-7774,
CVE-2017-7775, CVE-2017-7776, CVE-2017-7777, CVE-2017-7778).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3315-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");
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

if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"54.0+build3-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"54.0+build3-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"firefox", pkgver:"54.0+build3-0ubuntu0.16.10.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"firefox", pkgver:"54.0+build3-0ubuntu0.17.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
