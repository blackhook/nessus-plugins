#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4271-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133549);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-5068");
  script_xref(name:"USN", value:"4271-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 : mesa vulnerability (USN-4271-1)");
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
"Tim Brown discovered that Mesa incorrectly handled shared memory
permissions. A local attacker could use this issue to obtain and
possibly alter sensitive information belonging to another user.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4271-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libd3dadapter9-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegl-mesa0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegl1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgl1-mesa-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglapi-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgles2-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglx-mesa0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libosmesa6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-egl1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxatracker2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mesa-opencl-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mesa-va-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"libd3dadapter9-mesa", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libegl-mesa0", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libegl1-mesa", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libgbm1", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libgl1-mesa-dri", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libgl1-mesa-glx", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libglapi-mesa", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libgles2-mesa", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libglx-mesa0", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libosmesa6", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libwayland-egl1-mesa", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libxatracker2", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mesa-opencl-icd", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mesa-va-drivers", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mesa-vdpau-drivers", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mesa-vulkan-drivers", pkgver:"19.2.8-0ubuntu0~18.04.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libd3dadapter9-mesa", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libegl-mesa0", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libegl1-mesa", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libgbm1", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libgl1-mesa-dri", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libgl1-mesa-glx", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libglapi-mesa", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libgles2-mesa", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libglx-mesa0", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libosmesa6", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libwayland-egl1-mesa", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libxatracker2", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mesa-opencl-icd", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mesa-va-drivers", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mesa-vdpau-drivers", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mesa-vulkan-drivers", pkgver:"19.2.8-0ubuntu0~19.10.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libd3dadapter9-mesa / libegl-mesa0 / libegl1-mesa / libgbm1 / etc");
}
