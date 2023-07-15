#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4122-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128521);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-11734", "CVE-2019-11735", "CVE-2019-11737", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11741", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11752", "CVE-2019-5849", "CVE-2019-9812");
  script_xref(name:"USN", value:"4122-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 : firefox vulnerabilities (USN-4122-1)");
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
potentially exploit these to obtain sensitive information, bypass
Content Security Policy (CSP) protections, bypass same-origin
restrictions, conduct cross-site scripting (XSS) attacks, cause a
denial of service, or execute arbitrary code. (CVE-2019-5849,
CVE-2019-11734, CVE-2019-11735, CVE-2019-11737, CVE-2019-11738,
CVE-2019-11740, CVE-2019-11742, CVE-2019-11743, CVE-2019-11744,
CVE-2019-11746, CVE-2019-11748, CVE-2019-11749, CVE-2019-11750,
CVE-2019-11752)

It was discovered that a compromised content process could log in to a
malicious Firefox Sync account. An attacker could potentially exploit
this, in combination with another vulnerability, to disable the
sandbox. (CVE-2019-9812)

It was discovered that addons.mozilla.org and accounts.firefox.com
could be loaded in to the same content process. An attacker could
potentially exploit this, in combination with another vulnerability
that allowed a cross-site scripting (XSS) attack, to modify browser
settings. (CVE-2019-11741)

It was discovered that the 'Forget about this site' feature in the
history pane removes HTTP Strict Transport Security (HSTS) settings
for sites on the pre-load list. An attacker could potentially exploit
this to bypass the protections offered by HSTS. (CVE-2019-11747).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4122-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");
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

if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"69.0+build2-0ubuntu0.16.04.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"firefox", pkgver:"69.0+build2-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"firefox", pkgver:"69.0+build2-0ubuntu0.19.04.1")) flag++;

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
