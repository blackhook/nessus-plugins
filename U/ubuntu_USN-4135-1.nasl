#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4135-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129049);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031");
  script_xref(name:"USN", value:"4135-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 : Linux kernel vulnerabilities (USN-4135-1)");
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
"Peter Pi discovered a buffer overflow in the virtio network backend
(vhost_net) implementation in the Linux kernel. An attacker in a guest
may be able to use this to cause a denial of service (host OS crash)
or possibly execute arbitrary code in the host OS. (CVE-2019-14835)

It was discovered that the Linux kernel on PowerPC architectures did
not properly handle Facility Unavailable exceptions in some
situations. A local attacker could use this to expose sensitive
information. (CVE-2019-15030)

It was discovered that the Linux kernel on PowerPC architectures did
not properly handle exceptions on interrupts in some situations. A
local attacker could use this to expose sensitive information.
(CVE-2019-15031).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4135-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-4.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4135-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1025-oracle", pkgver:"4.15.0-1025.28~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1044-gcp", pkgver:"4.15.0-1044.46")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1050-aws", pkgver:"4.15.0-1050.52~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1059-azure", pkgver:"4.15.0-1059.64")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-64-generic", pkgver:"4.15.0-64.73~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-64-generic-lpae", pkgver:"4.15.0-64.73~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-64-lowlatency", pkgver:"4.15.0-64.73~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1058-kvm", pkgver:"4.4.0-1058.65")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1094-aws", pkgver:"4.4.0-1094.105")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1122-raspi2", pkgver:"4.4.0-1122.131")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1126-snapdragon", pkgver:"4.4.0-1126.132")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-164-generic", pkgver:"4.4.0-164.192")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-164-generic-lpae", pkgver:"4.4.0-164.192")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-164-lowlatency", pkgver:"4.4.0-164.192")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1094.98")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws-hwe", pkgver:"4.15.0.1050.50")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-azure", pkgver:"4.15.0.1059.62")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1044.58")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.164.172")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.15.0.64.84")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.164.172")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.15.0.64.84")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1044.58")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1058.58")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.164.172")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.15.0.64.84")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oem", pkgver:"4.15.0.64.84")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1025.18")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1122.122")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1126.118")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual", pkgver:"4.4.0.164.172")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual-hwe-16.04", pkgver:"4.15.0.64.84")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1025-oracle", pkgver:"4.15.0-1025.28")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1044-gcp", pkgver:"4.15.0-1044.70")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1044-gke", pkgver:"4.15.0-1044.46")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1046-kvm", pkgver:"4.15.0-1046.46")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1047-raspi2", pkgver:"4.15.0-1047.51")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1050-aws", pkgver:"4.15.0-1050.52")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1056-oem", pkgver:"4.15.0-1056.65")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1064-snapdragon", pkgver:"4.15.0-1064.71")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-64-generic", pkgver:"4.15.0-64.73")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-64-generic-lpae", pkgver:"4.15.0-64.73")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-64-lowlatency", pkgver:"4.15.0-64.73")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1017-gke", pkgver:"5.0.0-1017.17~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1020-azure", pkgver:"5.0.0-1020.21~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-29-generic", pkgver:"5.0.0-29.31~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-29-generic-lpae", pkgver:"5.0.0-29.31~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-29-lowlatency", pkgver:"5.0.0-29.31~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws", pkgver:"4.15.0.1050.49")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1020.30")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1044.70")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic", pkgver:"4.15.0.64.66")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.0.0.29.86")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae", pkgver:"4.15.0.64.66")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.0.0.29.86")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1044.47")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-4.15", pkgver:"4.15.0.1044.47")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1017.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-kvm", pkgver:"4.15.0.1046.46")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency", pkgver:"4.15.0.64.66")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.0.0.29.86")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem", pkgver:"4.15.0.1056.60")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1025.28")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2", pkgver:"4.15.0.1047.45")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon", pkgver:"4.15.0.1064.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.0.0.29.86")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual", pkgver:"4.15.0.64.66")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.0.0.29.86")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1016-aws", pkgver:"5.0.0-1016.18")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1017-gcp", pkgver:"5.0.0-1017.17")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1017-kvm", pkgver:"5.0.0-1017.18")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1017-raspi2", pkgver:"5.0.0-1017.17")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1020-azure", pkgver:"5.0.0-1020.21")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1021-snapdragon", pkgver:"5.0.0-1021.22")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-29-generic", pkgver:"5.0.0-29.31")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-29-generic-lpae", pkgver:"5.0.0-29.31")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-29-lowlatency", pkgver:"5.0.0-29.31")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-aws", pkgver:"5.0.0.1016.17")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1020.19")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-gcp", pkgver:"5.0.0.1017.43")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-generic", pkgver:"5.0.0.29.30")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-generic-lpae", pkgver:"5.0.0.29.30")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-gke", pkgver:"5.0.0.1017.43")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-kvm", pkgver:"5.0.0.1017.17")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-lowlatency", pkgver:"5.0.0.29.30")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-raspi2", pkgver:"5.0.0.1017.14")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-snapdragon", pkgver:"5.0.0.1021.14")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-virtual", pkgver:"5.0.0.29.30")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.15-aws / linux-image-4.15-azure / etc");
}
