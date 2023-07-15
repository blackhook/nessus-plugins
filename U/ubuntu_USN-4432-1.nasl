#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4432-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139179);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-15705", "CVE-2020-15706", "CVE-2020-15707");
  script_xref(name:"USN", value:"4432-1");
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 : GRUB 2 vulnerabilities (USN-4432-1)");
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
"Jesse Michael and Mickey Shkatov discovered that the configuration
parser in GRUB2 did not properly exit when errors were discovered,
resulting in heap-based buffer overflows. A local attacker could use
this to execute arbitrary code and bypass UEFI Secure Boot
restrictions. (CVE-2020-10713) Chris Coulson discovered that the GRUB2
function handling code did not properly handle a function being
redefined, leading to a use-after-free vulnerability. A local attacker
could use this to execute arbitrary code and bypass UEFI Secure Boot
restrictions. (CVE-2020-15706) Chris Coulson discovered that multiple
integer overflows existed in GRUB2 when handling certain filesystems
or font files, leading to heap-based buffer overflows. A local
attacker could use these to execute arbitrary code and bypass UEFI
Secure Boot restrictions. (CVE-2020-14309, CVE-2020-14310,
CVE-2020-14311) It was discovered that the memory allocator for GRUB2
did not validate allocation size, resulting in multiple integer
overflows and heap-based buffer overflows when handling certain
filesystems, PNG images or disk metadata. A local attacker could use
this to execute arbitrary code and bypass UEFI Secure Boot
restrictions. (CVE-2020-14308) Mathieu Trudel-Lapierre discovered that
in certain situations, GRUB2 failed to validate kernel signatures. A
local attacker could use this to bypass Secure Boot restrictions.
(CVE-2020-15705) Colin Watson and Chris Coulson discovered that an
integer overflow existed in GRUB2 when handling the initrd command,
leading to a heap-based buffer overflow. A local attacker could use
this to execute arbitrary code and bypass UEFI Secure Boot
restrictions. (CVE-2020-15707).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4432-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-amd64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-arm64-signed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:grub-efi-ia32-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"grub-efi-amd64-bin", pkgver:"2.02~beta2-36ubuntu3.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"grub-efi-amd64-signed", pkgver:"1.66.26+2.02~beta2-36ubuntu3.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"grub-efi-arm-bin", pkgver:"2.02~beta2-36ubuntu3.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"grub-efi-arm64-bin", pkgver:"2.02~beta2-36ubuntu3.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"grub-efi-arm64-signed", pkgver:"1.66.26+2.02~beta2-36ubuntu3.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"grub-efi-ia32-bin", pkgver:"2.02~beta2-36ubuntu3.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"grub-efi-amd64-bin", pkgver:"2.02-2ubuntu8.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"grub-efi-amd64-signed", pkgver:"1.93.18+2.02-2ubuntu8.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"grub-efi-arm-bin", pkgver:"2.02-2ubuntu8.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"grub-efi-arm64-bin", pkgver:"2.02-2ubuntu8.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"grub-efi-arm64-signed", pkgver:"1.93.18+2.02-2ubuntu8.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"grub-efi-ia32-bin", pkgver:"2.02-2ubuntu8.16")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"grub-efi-amd64-bin", pkgver:"2.04-1ubuntu26.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"grub-efi-amd64-signed", pkgver:"1.142.3+2.04-1ubuntu26.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"grub-efi-arm-bin", pkgver:"2.04-1ubuntu26.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"grub-efi-arm64-bin", pkgver:"2.04-1ubuntu26.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"grub-efi-arm64-signed", pkgver:"1.142.3+2.04-1ubuntu26.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"grub-efi-ia32-bin", pkgver:"2.04-1ubuntu26.1")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub-efi-amd64-bin / grub-efi-amd64-signed / grub-efi-arm-bin / etc");
}
