#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-181-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20592);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2005-2871");
  script_xref(name:"USN", value:"181-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : mozilla, mozilla-thunderbird, mozilla-firefox vulnerabilities (USN-181-1)");
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
"Tom Ferris discovered a buffer overflow in the Mozilla products
(Mozilla browser, Firefox, Thunderbird). By tricking an user to click
on a Hyperlink with a specially crafted destination URL, a remote
attacker could crash the application. It might even be possible to
exploit this vulnerability to execute arbitrary code, but this has not
yet been confirmed.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-chatzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-mailnews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-offline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2019 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libnspr-dev", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libnspr4", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libnss-dev", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libnss3", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-browser", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-calendar", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-chatzilla", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-dev", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-dom-inspector", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox", pkgver:"1.0.6-0ubuntu0.0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-dev", pkgver:"1.0.6-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"1.0.6-0ubuntu0.0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-gnome-support", pkgver:"1.0.6-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-js-debugger", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-mailnews", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-psm", pkgver:"1.7.10-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird", pkgver:"1.0.6-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.6-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.6-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.6-0ubuntu04.10.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.6-0ubuntu04.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnspr-dev / libnspr4 / libnss-dev / libnss3 / mozilla / etc");
}
