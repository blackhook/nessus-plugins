#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-437-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28033);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-0002", "CVE-2007-1466");
  script_bugtraq_id(23006);
  script_xref(name:"USN", value:"437-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : libwpd vulnerability (USN-437-1)");
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
"Sean Larsson of iDefense Labs discovered that libwpd was vulnerable to
integer overflows. If a user were tricked into opening a specially
crafted WordPerfect document with an application that used libwpd, an
attacker could execute arbitrary code with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/437-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd-stream8c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd-stream8c2a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd8-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd8c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwpd8c2a");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"libwpd-stream8c2", pkgver:"0.8.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libwpd-tools", pkgver:"0.8.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libwpd8-dev", pkgver:"0.8.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libwpd8-doc", pkgver:"0.8.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libwpd8c2", pkgver:"0.8.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libwpd-stream8c2a", pkgver:"0.8.4-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libwpd-tools", pkgver:"0.8.4-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libwpd8-dev", pkgver:"0.8.4-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libwpd8-doc", pkgver:"0.8.4-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libwpd8c2a", pkgver:"0.8.4-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libwpd-stream8c2a", pkgver:"0.8.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libwpd-tools", pkgver:"0.8.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libwpd8-dev", pkgver:"0.8.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libwpd8-doc", pkgver:"0.8.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libwpd8c2a", pkgver:"0.8.6-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwpd-stream8c2 / libwpd-stream8c2a / libwpd-tools / libwpd8-dev / etc");
}
