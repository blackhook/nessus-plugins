#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1551-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62382);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-1956", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3975", "CVE-2012-3978", "CVE-2012-3980");
  script_bugtraq_id(55257, 55260, 55264, 55266, 55274, 55276, 55277, 55278, 55292, 55304, 55306, 55310, 55314, 55316, 55317, 55318, 55319, 55320, 55321, 55322, 55323, 55324, 55325, 55340, 55341, 55342);
  script_xref(name:"USN", value:"1551-2");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : thunderbird regressions (USN-1551-2)");
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
"USN-1551-1 fixed vulnerabilities in Thunderbird. The new package
caused a regression in the message editor and certain performance
regressions as well. This update fixes the problems.

Gary Kwong, Christian Holler, Jesse Ruderman, Steve Fink, Bob Clary,
Andrew Sutherland, Jason Smith, John Schoenick, Vladimir Vukicevic and
Daniel Holbert discovered memory safety issues affecting Thunderbird.
If the user were tricked into opening a specially crafted E-Mail, an
attacker could exploit these to cause a denial of service via
application crash, or potentially execute code with the privileges of
the user invoking Thunderbird. (CVE-2012-1970, CVE-2012-1971)

Abhishek Arya discovered multiple use-after-free
vulnerabilities. If the user were tricked into opening a
specially crafted E-Mail, an attacker could exploit these to
cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Thunderbird. (CVE-2012-1972, CVE-2012-1973,
CVE-2012-1974, CVE-2012-1975, CVE-2012-1976, CVE-2012-3956,
CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

Mariusz Mlynsk discovered that it is possible to shadow the
location object using Object.defineProperty. This could
potentially result in a cross-site scripting (XSS) attack
against plugins. With cross-site scripting vulnerabilities,
if a user were tricked into viewing a specially crafted
E-Mail, a remote attacker could exploit this to modify the
contents or steal confidential data within the same domain.
(CVE-2012-1956)

Frederic Hoguin discovered that bitmap format images with
a negative height could potentially result in memory
corruption. If the user were tricked into opening a
specially crafted image, an attacker could exploit this to
cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Thunderbird. (CVE-2012-3966)

It was discovered that Thunderbird's WebGL implementation
was vulnerable to multiple memory safety issues. If the user
were tricked into opening a specially crafted E-Mail, an
attacker could exploit these to cause a denial of service
via application crash, or potentially execute code with the
privileges of the user invoking Thunderbird. (CVE-2012-3967,
CVE-2012-3968)

Arthur Gerkis discovered multiple memory safety issues in
Thunderbird's Scalable Vector Graphics (SVG) implementation.
If the user were tricked into opening a specially crafted
image, an attacker could exploit these to cause a denial of
service via application crash, or potentially execute code
with the privileges of the user invoking Thunderbird.
(CVE-2012-3969, CVE-2012-3970)

Christoph Diehl discovered multiple memory safety issues in
the bundled Graphite 2 library. If the user were tricked
into opening a specially crafted E-Mail, an attacker could
exploit these to cause a denial of service via application
crash, or potentially execute code with the privileges of
the user invoking Thunderbird. (CVE-2012-3971)

Nicolas Gregoire discovered an out-of-bounds read in the
format-number feature of XSLT. This could potentially cause
inaccurate formatting of numbers and information leakage.
(CVE-2012-3972)

It was discovered that when the DOMParser is used to parse
text/html data in a Thunderbird extension, linked resources
within this HTML data will be loaded. If the data being
parsed in the extension is untrusted, it could lead to
information leakage and potentially be combined with other
attacks to become exploitable. (CVE-2012-3975)

It was discovered that, in some instances, certain security
checks in the location object could be bypassed. This could
allow for the loading of restricted content and can
potentially be combined with other issues to become
exploitable. (CVE-2012-3978)

Colby Russell discovered that eval in the web console can
execute injected code with chrome privileges, leading to the
running of malicious code in a privileged context. If the
user were tricked into opening a specially crafted E-Mail,
an attacker could exploit this to cause a denial of service
via application crash, or potentially execute code with the
privileges of the user invoking Thunderbird. (CVE-2012-3980).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1551-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-globalmenu
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-globalmenu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/29");
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
if (! preg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"15.0.1+build1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"thunderbird", pkgver:"15.0.1+build1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"thunderbird-globalmenu", pkgver:"15.0.1+build1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"thunderbird", pkgver:"15.0.1+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"thunderbird-globalmenu", pkgver:"15.0.1+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"15.0.1+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"thunderbird-globalmenu", pkgver:"15.0.1+build1-0ubuntu0.12.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-globalmenu");
}
