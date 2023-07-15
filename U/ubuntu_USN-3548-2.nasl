#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3548-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106373);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");
  script_xref(name:"USN", value:"3548-2");

  script_name(english:"Ubuntu 16.04 LTS : linux-hwe, linux-azure, linux-gcp, linux-oem vulnerability (USN-3548-2)");
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
"USN-3548-1 fixed vulnerabilities in the Linux kernel for Ubuntu 17.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu 16.04 LTS.

Jay Vosburgh discovered a logic error in the x86-64 syscall entry
implementation in the Linux kernel, introduced as part of the
mitigations for the Spectre vulnerability. A local attacker could use
this to cause a denial of service or possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3548-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-1007-azure", pkgver:"4.13.0-1007.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-1008-gcp", pkgver:"4.13.0-1008.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-1019-oem", pkgver:"4.13.0-1019.20")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-32-generic", pkgver:"4.13.0-32.35~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-32-lowlatency", pkgver:"4.13.0-32.35~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-azure", pkgver:"4.13.0.1007.8")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gcp", pkgver:"4.13.0.1008.10")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.13.0.32.52")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.13.0.1008.10")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.13.0.32.52")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oem", pkgver:"4.13.0.1019.23")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.13-azure / linux-image-4.13-gcp / etc");
}
