#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1277-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56945);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2011-3648", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3654", "CVE-2011-3655");
  script_bugtraq_id(50593, 50594, 50595, 50597, 50600, 50602);
  script_xref(name:"USN", value:"1277-2");

  script_name(english:"Ubuntu 11.04 / 11.10 : mozvoikko, ubufox update (USN-1277-2)");
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
"USN-1277-1 fixed vulnerabilities in Firefox. This update provides
updated Mozvoikko and ubufox packages for use with Firefox 8.

Yosuke Hasegawa discovered that the Mozilla browser engine mishandled
invalid sequences in the Shift-JIS encoding. It may be possible to
trigger this crash without the use of debugging APIs, which might
allow malicious websites to exploit this vulnerability. An attacker
could possibly use this flaw this to steal data or inject malicious
scripts into web content. (CVE-2011-3648)

Marc Schoenefeld discovered that using Firebug to profile a
JavaScript file with many functions would cause Firefox to
crash. An attacker might be able to exploit this without
using the debugging APIs, which could potentially remotely
crash the browser, resulting in a denial of service.
(CVE-2011-3650)

Jason Orendorff, Boris Zbarsky, Gregg Tavares, Mats
Palmgren, Christian Holler, Jesse Ruderman, Simona Marcu,
Bob Clary, and William McCloskey discovered multiple memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. An attacker might be able to use
these flaws to execute arbitrary code with the privileges of
the user invoking Firefox or possibly crash the browser
resulting in a denial of service. (CVE-2011-3651)

It was discovered that Firefox could be caused to crash
under certain conditions, due to an unchecked allocation
failure, resulting in a denial of service. It might also be
possible to execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2011-3652)

Aki Helin discovered that Firefox does not properly handle
links from SVG mpath elements to non-SVG elements. An
attacker could use this vulnerability to crash Firefox,
resulting in a denial of service, or possibly execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2011-3654)

It was discovered that an internal privilege check failed to
respect the NoWaiverWrappers introduced with Firefox 4. An
attacker could possibly use this to gain elevated privileges
within the browser for web content. (CVE-2011-3655).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1277-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected xul-ext-mozvoikko and / or xul-ext-ubufox
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/26");
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
if (! preg(pattern:"^(11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-mozvoikko", pkgver:"1.10.0-0ubuntu0.11.04.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-ubufox", pkgver:"0.9.2-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-mozvoikko", pkgver:"1.10.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-ubufox", pkgver:"1.0-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-mozvoikko / xul-ext-ubufox");
}
