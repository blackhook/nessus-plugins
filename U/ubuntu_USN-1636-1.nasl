#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1636-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63023);
  script_version("1.14");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4217", "CVE-2012-4218", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");
  script_bugtraq_id(56628, 56633);
  script_xref(name:"USN", value:"1636-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : thunderbird vulnerabilities (USN-1636-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gary Kwong, Jesse Ruderman, Christian Holler, Bob Clary, Kyle Huey, Ed
Morley, Chris Lord, Boris Zbarsky, Julian Seward, Bill McCloskey, and
Andrew McCreight discovered several memory corruption flaws in
Thunderbird. If a user were tricked into opening a malicious website
and had JavaScript enabled, an attacker could exploit these to execute
arbitrary JavaScript code within the context of another website or
arbitrary code as the user invoking the program. (CVE-2012-5842,
CVE-2012-5843)

Atte Kettunen discovered a buffer overflow while rendering GIF format
images. An attacker could exploit this to possibly execute arbitrary
code as the user invoking Thunderbird. (CVE-2012-4202)

It was discovered that the evalInSandbox function's JavaScript sandbox
context could be circumvented. An attacker could exploit this to
perform a cross-site scripting (XSS) attack or steal a copy of a local
file if the user has installed an add-on vulnerable to this attack.
With cross-site scripting vulnerabilities, if a user were tricked into
viewing a specially crafted page and had JavaScript enabled, a remote
attacker could exploit this to modify the contents, or steal
confidential data, within the same domain. (CVE-2012-4201)

Jonathan Stephens discovered that combining vectors involving the
setting of Cascading Style Sheets (CSS) properties in conjunction with
SVG text could cause Thunderbird to crash. If a user were tricked into
opening a malicious E-Mail, an attacker could cause a denial of
service via application crash or execute arbitrary code with the
privliges of the user invoking the program. (CVE-2012-5836)

Scott Bell discovered a memory corruption issue in the JavaScript
engine. If a user were tricked into opening a malicious website and
had JavaScript enabled, an attacker could exploit this to execute
arbitrary JavaScript code within the context of another website or
arbitrary code as the user invoking the program. (CVE-2012-4204)

Gabor Krizsanits discovered that XMLHttpRequest objects created within
sandboxes have the system principal instead of the sandbox principal.
This can lead to cross-site request forgery (CSRF) or information
theft via an add-on running untrusted code in a sandbox.
(CVE-2012-4205)

Peter Van der Beken discovered XrayWrapper implementation in Firefox
does not consider the compartment during property filtering. If
JavaScript were enabled, an attacker could use this to bypass intended
chrome-only restrictions on reading DOM object properties via a
crafted website. (CVE-2012-4208)

Bobby Holley discovered that cross-origin wrappers were allowing write
actions on objects when only read actions should have been properly
allowed. This can lead to cross-site scripting (XSS) attacks. With
cross-site scripting vulnerabilities, if a user were tricked into
viewing a specially crafted page and had JavaScript enabled, a remote
attacker could exploit this to modify the contents, or steal
confidential data, within the same domain. (CVE-2012-5841)

Masato Kinugawa discovered that when HZ-GB-2312 charset encoding is
used for text, the '~' character will destroy another character near
the chunk delimiter. This can lead to a cross-site scripting (XSS)
attack in pages encoded in HZ-GB-2312. With cross-site scripting
vulnerabilities, if a user were tricked into viewing a specially
crafted page and had JavaScript enabled, a remote attacker could
exploit these to modify the contents, or steal confidential data,
within the same domain. (CVE-2012-4207)

Mariusz Mlynski discovered that the location property can be accessed
by binary plugins through top.location with a frame whose name
attribute's value is set to 'top'. This can allow for possible
cross-site scripting (XSS) attacks through plugins. With cross-site
scripting vulnerabilities, if a user were tricked into viewing a
specially crafted page and had JavaScript enabled, a remote attacker
could exploit this to modify the contents, or steal confidential data,
within the same domain. (CVE-2012-4209)

Abhishek Arya discovered multiple use-after-free and buffer overflow
issues in Thunderbird. If a user were tricked into opening a malicious
website and had JavaScript enabled, an attacker could exploit these to
execute arbitrary JavaScript code within the context of another
website or arbitrary code as the user invoking the program.
(CVE-2012-4214, CVE-2012-4215, CVE-2012-4216, CVE-2012-5829,
CVE-2012-5839, CVE-2012-5840, CVE-2012-4212, CVE-2012-4213,
CVE-2012-4217, CVE-2012-4218)

Several memory corruption flaws were discovered in Thunderbird. If a
user were tricked into opening a malicious website and had JavaScript
enabled, an attacker could exploit these to execute arbitrary
JavaScript code within the context of another website or arbitrary
code as the user invoking the program. (CVE-2012-5830, CVE-2012-5833,
CVE-2012-5835, CVE-2012-5838).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1636-1/"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"17.0+build2-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"thunderbird", pkgver:"17.0+build2-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"17.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"thunderbird", pkgver:"17.0+build2-0ubuntu0.12.10.1")) flag++;

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
