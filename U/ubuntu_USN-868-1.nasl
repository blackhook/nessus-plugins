#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-868-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65119);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-4128");
  script_xref(name:"USN", value:"868-1");

  script_name(english:"Ubuntu 9.10 : grub2 vulnerability (USN-868-1)");
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
"It was discovered that GRUB 2 did not properly validate passwords. An
attacker with physical access could conduct a brute-force attack and
bypass authentication by submitting a 1 character password.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/868-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-coreboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-firmware-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-ieee1275");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-linuxbios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-rescue-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"grub-common", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-coreboot", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-efi", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-efi-amd64", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-efi-ia32", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-emu", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-firmware-qemu", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-ieee1275", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-linuxbios", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-pc", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub-rescue-pc", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"grub2", pkgver:"1.97~beta4-1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub-common / grub-coreboot / grub-efi / grub-efi-amd64 / etc");
}
