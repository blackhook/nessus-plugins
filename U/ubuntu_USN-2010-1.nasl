#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2010-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70725);
  script_version("1.19");
  script_cvs_date("Date: 2019/09/19 12:54:29");

  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604");
  script_bugtraq_id(62966, 63415, 63416, 63417, 63420, 63421, 63422, 63423, 63424, 63427, 63428, 63429, 63430);
  script_xref(name:"USN", value:"2010-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 / 13.10 : thunderbird vulnerabilities (USN-2010-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple memory safety issues were discovered in Thunderbird. If a
user were tricked in to opening a specially crafted message with
scripting enabled, an attacker could possibly exploit these to cause a
denial of service via application crash, or potentially execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-1739, CVE-2013-5590, CVE-2013-5591)

Jordi Chancel discovered that HTML select elements could display
arbitrary content. If a user had scripting enabled, an attacker could
potentially exploit this to conduct URL spoofing or clickjacking
attacks. (CVE-2013-5593)

Abhishek Arya discovered a crash when processing XSLT data in some
circumstances. If a user had scripting enabled, an attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-5604)

Dan Gohman discovered a flaw in the JavaScript engine. If a user had
enabled scripting, when combined with other vulnerabilities an
attacker could possibly exploit this to execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-5595)

Ezra Pool discovered a crash on extremely large pages. If a user had
scripting enabled, an attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5596)

Byoungyoung Lee discovered a use-after-free when updating the offline
cache. If a user had scripting enabled, an attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5597)

Multiple use-after-free flaws were discovered in Thunderbird. If a
user had scripting enabled, an attacker could potentially exploit
these to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-5599, CVE-2013-5600, CVE-2013-5601)

A memory corruption flaw was discovered in the JavaScript engine when
using workers with direct proxies. If a user had scripting enabled, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2013-5602)

Abhishek Arya discovered a use-after-free when interacting with HTML
document templates. If a user had scripting enabled, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2013-5603).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2010-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2019 Canonical, Inc. / NASL script (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04|12\.10|13\.04|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:24.1.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"thunderbird", pkgver:"1:24.1.0+build1-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"thunderbird", pkgver:"1:24.1.0+build1-0ubuntu0.13.04.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"thunderbird", pkgver:"1:24.1.0+build1-0ubuntu0.13.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
