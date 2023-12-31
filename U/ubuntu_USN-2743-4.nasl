#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2743-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86291);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4504", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_xref(name:"USN", value:"2743-4");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : firefox regression (USN-2743-4)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2743-1 fixed vulnerabilities in Firefox. After upgrading, some
users reported problems with bookmark creation and crashes in some
circumstances. This update fixes the problem.

We apologize for the inconvenience.

Andrew Osmond, Olli Pettay, Andrew Sutherland, Christian Holler, David
Major, Andrew McCreight, Cameron McCormack, Bob Clary and Randell
Jesup discovered multiple memory safety issues in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-4500, CVE-2015-4501)

Andre Bargull discovered that when a web page creates a
scripted proxy for the window with a handler defined a
certain way, a reference to the inner window will be passed,
rather than that of the outer window. (CVE-2015-4502)

Felix Grobert discovered an out-of-bounds read in the QCMS
color management library in some circumstances. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of
service via application crash, or obtain sensitive
information. (CVE-2015-4504)

Khalil Zhani discovered a buffer overflow when parsing VP9
content in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4506)

Spandan Veggalam discovered a crash while using the debugger
API in some circumstances. If a user were tricked in to
opening a specially crafted website whilst using the
debugger, an attacker could potentially exploit this to
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2015-4507)

Juho Nurminen discovered that the URL bar could display the
wrong URL in reader mode in some circumstances. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to conduct URL
spoofing attacks. (CVE-2015-4508)

A use-after-free was discovered when manipulating HTML media
content in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4509)

Looben Yang discovered a use-after-free when using a shared
worker with IndexedDB in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2015-4510)

Francisco Alonso discovered an out-of-bounds read during 2D
canvas rendering in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to obtain sensitive
information. (CVE-2015-4512)

Jeff Walden discovered that changes could be made to
immutable properties in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to execute arbitrary
script in a privileged scope. (CVE-2015-4516)

Ronald Crane reported multiple vulnerabilities. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2015-4517, CVE-2015-4521, CVE-2015-4522, CVE-2015-7174,
CVE-2015-7175, CVE-2015-7176, CVE-2015-7177, CVE-2015-7180)

Mario Gomes discovered that dragging and dropping an image
after a redirect exposes the redirected URL to scripts. An
attacker could potentially exploit this to obtain sensitive
information. (CVE-2015-4519)

Ehsan Akhgari discovered 2 issues with CORS preflight
requests. An attacker could potentially exploit these to
bypass CORS restrictions. (CVE-2015-4520).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2743-4/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04|14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"41.0.1+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"41.0.1+build2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"firefox", pkgver:"41.0.1+build2-0ubuntu0.15.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
