#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2814-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86944);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-7869");
  script_xref(name:"USN", value:"2814-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 / 15.04 / 15.10 : nvidia-graphics-drivers vulnerability (USN-2814-1)");
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
"It was discovered that the NVIDIA graphics drivers incorrectly
sanitized user mode inputs. A local attacker could use this issue to
possibly gain root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2814-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-352");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-352-updates");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
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
if (! preg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"nvidia-304", pkgver:"304.131-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-304-updates", pkgver:"304.131-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-331-updates", pkgver:"340.96-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-340", pkgver:"340.96-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-340-updates", pkgver:"340.96-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-304", pkgver:"304.131-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-304-updates", pkgver:"304.131-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-331", pkgver:"340.96-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-331-updates", pkgver:"340.96-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-340", pkgver:"340.96-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-340-updates", pkgver:"340.96-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-346", pkgver:"352.63-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-346-updates", pkgver:"352.63-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-352", pkgver:"352.63-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-352-updates", pkgver:"352.63-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-304", pkgver:"304.131-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-304-updates", pkgver:"304.131-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-331", pkgver:"340.96-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-331-updates", pkgver:"340.96-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-340", pkgver:"340.96-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-340-updates", pkgver:"340.96-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-346", pkgver:"352.63-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-346-updates", pkgver:"352.63-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-352", pkgver:"352.63-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-352-updates", pkgver:"352.63-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-304", pkgver:"304.131-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-304-updates", pkgver:"304.131-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-331", pkgver:"340.96-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-331-updates", pkgver:"340.96-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-340", pkgver:"340.96-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-340-updates", pkgver:"340.96-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-346", pkgver:"352.63-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-346-updates", pkgver:"352.63-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-352", pkgver:"352.63-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nvidia-352-updates", pkgver:"352.63-0ubuntu0.15.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nvidia-304 / nvidia-304-updates / nvidia-331 / nvidia-331-updates / etc");
}
