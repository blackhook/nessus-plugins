#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3821-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118971);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-10880", "CVE-2018-13053", "CVE-2018-13096", "CVE-2018-14609", "CVE-2018-14617", "CVE-2018-17972", "CVE-2018-18021");
  script_xref(name:"USN", value:"3821-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-3821-1)");
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
"Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly ensure that xattr information remained in
inode bodies. An attacker could use this to construct a malicious ext4
image that, when mounted, could cause a denial of service (system
crash). (CVE-2018-10880)

It was discovered that the alarmtimer implementation in the Linux
kernel contained an integer overflow vulnerability. A local attacker
could use this to cause a denial of service. (CVE-2018-13053)

Wen Xu discovered that the f2fs filesystem implementation in the Linux
kernel did not properly validate metadata. An attacker could use this
to construct a malicious f2fs image that, when mounted, could cause a
denial of service (system crash). (CVE-2018-13096)

Wen Xu and Po-Ning Tseng discovered that the btrfs filesystem
implementation in the Linux kernel did not properly handle relocations
in some situations. An attacker could use this to construct a
malicious btrfs image that, when mounted, could cause a denial of
service (system crash). (CVE-2018-14609)

Wen Xu discovered that the HFS+ filesystem implementation in the Linux
kernel did not properly handle malformed catalog data in some
situations. An attacker could use this to construct a malicious HFS+
image that, when mounted, could cause a denial of service (system
crash). (CVE-2018-14617)

Jann Horn discovered that the procfs file system implementation in the
Linux kernel did not properly restrict the ability to inspect the
kernel stack of an arbitrary task. A local attacker could use this to
expose sensitive information. (CVE-2018-17972)

It was discovered that the KVM implementation in the Linux kernel on
ARM 64bit processors did not properly handle some ioctls. An attacker
with the privilege to create KVM-based virtual machines could use this
to cause a denial of service (host system crash) or execute arbitrary
code in the host. (CVE-2018-18021).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3821-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17972");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-10880", "CVE-2018-13053", "CVE-2018-13096", "CVE-2018-14609", "CVE-2018-14617", "CVE-2018-17972", "CVE-2018-18021");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3821-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1037-kvm", pkgver:"4.4.0-1037.43")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1072-aws", pkgver:"4.4.0-1072.82")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1100-raspi2", pkgver:"4.4.0-1100.108")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1104-snapdragon", pkgver:"4.4.0-1104.109")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-139-generic", pkgver:"4.4.0-139.165")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-139-generic-lpae", pkgver:"4.4.0-139.165")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-139-lowlatency", pkgver:"4.4.0-139.165")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1072.74")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.139.145")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.139.145")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1037.36")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.139.145")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1100.100")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1104.96")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
