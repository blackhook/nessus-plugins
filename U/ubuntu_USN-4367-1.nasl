#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4367-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136732);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-19377", "CVE-2020-11565", "CVE-2020-12657", "CVE-2020-12826");
  script_xref(name:"USN", value:"4367-1");

  script_name(english:"Ubuntu 20.04 : Linux kernel vulnerabilities (USN-4367-1)");
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
"It was discovered that the btrfs implementation in the Linux kernel
did not properly detect that a block was marked dirty in some
situations. An attacker could use this to specially craft a file
system image that, when unmounted, could cause a denial of service
(system crash). (CVE-2019-19377)

It was discovered that the linux kernel did not properly validate
certain mount options to the tmpfs virtual memory file system. A local
attacker with the ability to specify mount options could use this to
cause a denial of service (system crash). (CVE-2020-11565)

It was discovered that the block layer in the Linux kernel contained a
race condition leading to a use-after-free vulnerability. A local
attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2020-12657).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4367-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19377");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/20");
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
  cve_list = make_list("CVE-2019-19377", "CVE-2020-11565", "CVE-2020-12657", "CVE-2020-12826");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4367-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1011-aws", pkgver:"5.4.0-1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1011-gcp", pkgver:"5.4.0-1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1011-kvm", pkgver:"5.4.0-1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1011-oracle", pkgver:"5.4.0-1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1011-raspi", pkgver:"5.4.0-1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1012-azure", pkgver:"5.4.0-1012.12")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-26-generic", pkgver:"5.4.0-26.30")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-31-generic", pkgver:"5.4.0-31.35")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-31-generic-lpae", pkgver:"5.4.0-31.35")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-31-lowlatency", pkgver:"5.4.0-31.35")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-aws", pkgver:"5.4.0.1011.14")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-azure", pkgver:"5.4.0.1012.14")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1011.12")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic", pkgver:"5.4.0.26.33")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-lpae", pkgver:"5.4.0.31.36")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gke", pkgver:"5.4.0.1011.12")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-kvm", pkgver:"5.4.0.1011.12")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-lowlatency", pkgver:"5.4.0.31.36")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem", pkgver:"5.4.0.31.36")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem-osp1", pkgver:"5.4.0.31.36")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1011.12")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-raspi", pkgver:"5.4.0.1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-raspi2", pkgver:"5.4.0.1011.11")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-virtual", pkgver:"5.4.0.26.33")) flag++;

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