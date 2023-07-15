#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4411-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138136);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-10711", "CVE-2020-10732", "CVE-2020-12768", "CVE-2020-12770", "CVE-2020-13143");
  script_xref(name:"USN", value:"4411-1");

  script_name(english:"Ubuntu 20.04 : Linux kernel vulnerabilities (USN-4411-1)");
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
"It was discovered that the elf handling code in the Linux kernel did
not initialize memory before using it in certain situations. A local
attacker could use this to possibly expose sensitive information
(kernel memory). (CVE-2020-10732) Matthew Sheets discovered that the
SELinux network label handling implementation in the Linux kernel
could be coerced into de-referencing a NULL pointer. A remote attacker
could use this to cause a denial of service (system crash).
(CVE-2020-10711) It was discovered that the SCSI generic (sg) driver
in the Linux kernel did not properly handle certain error conditions
correctly. A local privileged attacker could use this to cause a
denial of service (system crash). (CVE-2020-12770) It was discovered
that the USB Gadget device driver in the Linux kernel did not validate
arguments passed from configfs in some situations. A local attacker
could possibly use this to cause a denial of service (system crash) or
possibly expose sensitive information. (CVE-2020-13143) It was
discovered that the KVM implementation in the Linux kernel did not
properly deallocate memory on initialization for some processors. A
local attacker could possibly use this to cause a denial of service.
(CVE-2020-12768).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4411-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2020-10711", "CVE-2020-10732", "CVE-2020-12768", "CVE-2020-12770", "CVE-2020-13143");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4411-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1013-raspi", pkgver:"5.4.0-1013.13")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1018-aws", pkgver:"5.4.0-1018.18")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1019-gcp", pkgver:"5.4.0-1019.19")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1019-oracle", pkgver:"5.4.0-1019.19")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1020-azure", pkgver:"5.4.0-1020.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-28-generic", pkgver:"5.4.0-28.32")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-40-generic", pkgver:"5.4.0-40.44")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-40-generic-lpae", pkgver:"5.4.0-40.44")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-40-lowlatency", pkgver:"5.4.0-40.44")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-aws", pkgver:"5.4.0.1018.19")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1019.17")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic", pkgver:"5.4.0.28.35")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-lpae", pkgver:"5.4.0.40.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gke", pkgver:"5.4.0.1019.17")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-kvm", pkgver:"5.4.0.1018.17")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-lowlatency", pkgver:"5.4.0.40.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem", pkgver:"5.4.0.40.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem-osp1", pkgver:"5.4.0.40.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1019.17")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-virtual", pkgver:"5.4.0.28.35")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.4-aws / linux-image-5.4-azure / linux-image-5.4-gcp / etc");
}
