#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1251-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56775);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2011-3004", "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_bugtraq_id(50589, 50593, 50595);
  script_xref(name:"USN", value:"1251-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : firefox, xulrunner-1.9.2 vulnerabilities (USN-1251-1)");
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
"It was discovered that CVE-2011-3004, which addressed possible
privilege escalation in addons, also affected Firefox 3.6. An attacker
could potentially exploit Firefox when an add-on was installed that
used loadSubscript in vulnerable ways. (CVE-2011-3647)

Yosuke Hasegawa discovered that the Mozilla browser engine mishandled
invalid sequences in the Shift-JIS encoding. A malicious website could
possibly use this flaw this to steal data or inject malicious scripts
into web content. (CVE-2011-3648)

Marc Schoenefeld discovered that using Firebug to profile a JavaScript
file with many functions would cause Firefox to crash. An attacker
might be able to exploit this without using the debugging APIs which
would potentially allow an attacker to remotely crash the browser.
(CVE-2011-3650).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1251-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner-1.9.2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"3.6.24+build2+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.24+build2+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox", pkgver:"3.6.24+build2+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.24+build2+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner-1.9.2");
}
