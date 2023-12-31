#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-416-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28006);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_bugtraq_id(20920, 20955, 21663, 21883, 22316);
  script_xref(name:"USN", value:"416-2");

  script_name(english:"Ubuntu 6.10 : linux-restricted-modules-2.6.17 regression (USN-416-2)");
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
"USN-416-1 fixed various vulnerabilities in the Linux kernel.
Unfortunately that update caused the 'nvidia-glx-config' script to not
work any more. The new version fixes the problem.

We apologize for the inconvenience.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/416-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.17-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-player-kernel-modules-2.6.17-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/01");
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
if (! ereg(pattern:"^(6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-firmware-2.6.17-11", pkgver:"3.11+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"fglrx-control", pkgver:"8.28.8+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"fglrx-kernel-source", pkgver:"8.28.8+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-2.6.17-11-386", pkgver:"2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-2.6.17-11-generic", pkgver:"2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-common", pkgver:"2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx", pkgver:"2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7184+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7184+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7184+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vmware-player-kernel-modules-2.6.17-11", pkgver:"2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.28.8+2.6.17.7-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.28.8+2.6.17.7-11.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware-2.6.17-11 / avm-fritz-kernel-source / etc");
}
