#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-811-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40492);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-2654");
  script_bugtraq_id(35803);
  script_xref(name:"USN", value:"811-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : firefox-3.0, xulrunner-1.9 vulnerability (USN-811-1)");
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
"Juan Pablo Lopez Yacubian discovered that Firefox did not properly
display invalid URLs. If a user were tricked into accessing a
malicious website, an attacker could exploit this to spoof the
location bar, such as in a phishing attack. Furthermore, if the
malicious website had a valid SSL certificate, Firefox would display
the spoofed page as trusted.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/811-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2019 Canonical, Inc. / NASL script (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"firefox", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-venkman", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-libthai", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-venkman", pkgver:"3.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-dev", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-dom-inspector", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-gnome-support", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-venkman", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"abrowser", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"abrowser-3.0-branding", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-branding", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-venkman", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-libthai", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-venkman", pkgver:"3.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-dev", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-dom-inspector", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-gnome-support", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-venkman", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-dev", pkgver:"1.9.0.13+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"abrowser", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"abrowser-3.0-branding", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-branding", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-venkman", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-libthai", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-dev", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-dom-inspector", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-venkman", pkgver:"3.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9", pkgver:"1.9.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-dev", pkgver:"1.9.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-dom-inspector", pkgver:"1.9.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-gnome-support", pkgver:"1.9.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-venkman", pkgver:"1.9.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-dev", pkgver:"1.9.0.13+nobinonly-0ubuntu0.9.04.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrowser / abrowser-3.0-branding / firefox / firefox-3.0 / etc");
}
