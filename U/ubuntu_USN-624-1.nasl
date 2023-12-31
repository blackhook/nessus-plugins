#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-624-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33504);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-2371");
  script_xref(name:"USN", value:"624-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : pcre3 vulnerability (USN-624-1)");
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
"Tavis Ormandy discovered that the PCRE library did not correctly
handle certain in-pattern options. An attacker could cause
applications linked against pcre3 to crash, leading to a denial of
service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/624-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcre3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcre3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcre3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcrecpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcregrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pgrep");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.6.06.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.6.06.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.6.06.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.6.06.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"pgrep", pkgver:"7.4-0ubuntu0.6.06.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.7.04.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.7.04.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.7.04.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.7.04.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.7.10.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.7.10.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.7.10.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.7.10.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpcre3", pkgver:"7.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpcre3-dbg", pkgver:"7.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpcre3-dev", pkgver:"7.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpcrecpp0", pkgver:"7.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pcregrep", pkgver:"7.4-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcre3 / libpcre3-dbg / libpcre3-dev / libpcrecpp0 / pcregrep / etc");
}
