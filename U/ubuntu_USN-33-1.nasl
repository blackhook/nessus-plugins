#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-33-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20649);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2004-0941", "CVE-2004-0990");
  script_xref(name:"USN", value:"33-1");

  script_name(english:"Ubuntu 4.10 : libgd vulnerabilities (USN-33-1)");
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
"CAN-2004-0990 described several buffer overflows which had been
discovered in libgd's PNG handling functions. Another update is
required because the update from USN-21-1 was not sufficient to
prevent every possible attack.

If an attacker tricks a user into loading a malicious PNG or XPM
image, they could leverage this into executing arbitrary code in the
context of the user opening image.

This vulnerability might lead to privilege escalation in customized
systems that use server applications which link libgd. However, Warty
does not ship such server applications (PHP in Warty uses libgd2 which
was already fixed in USN-25-1).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd-noxpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd-xpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd1-noxpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd1-xpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2004-2019 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libgd-dev", pkgver:"1.8.4-36ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgd-noxpm-dev", pkgver:"1.8.4-36ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgd-xpm-dev", pkgver:"1.8.4-36ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgd1", pkgver:"1.8.4-36ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgd1-noxpm", pkgver:"1.8.4-36ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgd1-xpm", pkgver:"1.8.4-36ubuntu0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgd-dev / libgd-noxpm-dev / libgd-xpm-dev / libgd1 / libgd1-noxpm / etc");
}
