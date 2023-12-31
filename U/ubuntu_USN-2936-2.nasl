#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2936-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90855);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-2804", "CVE-2016-2806", "CVE-2016-2807", "CVE-2016-2808", "CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2814", "CVE-2016-2816", "CVE-2016-2817", "CVE-2016-2820");
  script_xref(name:"USN", value:"2936-2");

  script_name(english:"Ubuntu 12.04 LTS : oxygen-gtk3 update (USN-2936-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"USN-2936-1 fixed vulnerabilities in Firefox. The update caused Firefox
to crash on startup with the Oxygen GTK theme due to a pre-existing
bug in the Oxygen-GTK3 theme engine. This update fixes the problem.

We apologize for the inconvenience.

Christian Holler, Tyson Smith, Phil Ringalda, Gary Kwong, Jesse
Ruderman, Mats Palmgren, Carsten Book, Boris Zbarsky, David Bolter,
Randell Jesup, Andrew McCreight, and Steve Fink discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2016-2804, CVE-2016-2806, CVE-2016-2807)

An invalid write was discovered when using the JavaScript
.watch() method in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2016-2808)

Looben Yang discovered a use-after-free and buffer overflow
in service workers. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-2811, CVE-2016-2812)

Sascha Just discovered a buffer overflow in libstagefright
in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-2814)

Muneaki Nishimura discovered that CSP is not applied
correctly to web content sent with the
multipart/x-mixed-replace MIME type. An attacker could
potentially exploit this to conduct cross-site scripting
(XSS) attacks when they would otherwise be prevented.
(CVE-2016-2816)

Muneaki Nishimura discovered that the chrome.tabs.update API
for web extensions allows for navigation to javascript:
URLs. A malicious extension could potentially exploit this
to conduct cross-site scripting (XSS) attacks.
(CVE-2016-2817)

Mark Goodwin discovered that about:healthreport accepts
certain events from any content present in the remote-report
iframe. If another vulnerability allowed the injection of
web content in the remote-report iframe, an attacker could
potentially exploit this to change the user's sharing
preferences. (CVE-2016-2820).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2936-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gtk3-engines-oxygen package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk3-engines-oxygen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
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
if (! preg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"gtk3-engines-oxygen", pkgver:"1.0.2-0ubuntu3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk3-engines-oxygen");
}
