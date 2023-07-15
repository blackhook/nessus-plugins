#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4489-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140450);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-14386");
  script_xref(name:"USN", value:"4489-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 : Linux kernel vulnerability (USN-4489-1)");
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
"Or Cohen discovered that the AF_PACKET implementation in the Linux
kernel did not properly perform bounds checking in some situations. A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4489-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-4.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/09");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2020-14386");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4489-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1053-oracle", pkgver:"4.15.0-1053.57~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1082-aws", pkgver:"4.15.0-1082.86~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1083-gcp", pkgver:"4.15.0-1083.94~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1095-azure", pkgver:"4.15.0-1095.105~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-117-generic", pkgver:"4.15.0-117.118~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-117-generic-lpae", pkgver:"4.15.0-117.118~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-117-lowlatency", pkgver:"4.15.0-117.118~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws-hwe", pkgver:"4.15.0.1082.78")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-azure", pkgver:"4.15.0.1095.89")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1083.84")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.15.0.117.118")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.15.0.117.118")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1083.84")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.15.0.117.118")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oem", pkgver:"4.15.0.117.118")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1053.43")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual-hwe-16.04", pkgver:"4.15.0.117.118")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1053-oracle", pkgver:"4.15.0-1053.57")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1069-gke", pkgver:"4.15.0-1069.72")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1070-raspi2", pkgver:"4.15.0-1070.74")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1074-kvm", pkgver:"4.15.0-1074.75")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1082-aws", pkgver:"4.15.0-1082.86")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1083-gcp", pkgver:"4.15.0-1083.94")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1086-snapdragon", pkgver:"4.15.0-1086.94")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1095-azure", pkgver:"4.15.0-1095.105")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1096-oem", pkgver:"4.15.0-1096.106")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-117-generic", pkgver:"4.15.0-117.118")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-117-generic-lpae", pkgver:"4.15.0-117.118")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-117-lowlatency", pkgver:"4.15.0-117.118")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1047-gke", pkgver:"5.0.0-1047.48")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1068-oem-osp1", pkgver:"5.0.0-1068.73")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1033-raspi2", pkgver:"5.3.0-1033.35")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1035-aws", pkgver:"5.3.0-1035.37")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1036-gke", pkgver:"5.3.0-1036.38")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-67-generic", pkgver:"5.3.0-67.61")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-67-lowlatency", pkgver:"5.3.0-67.61")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1018-raspi", pkgver:"5.4.0-1018.20~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1024-aws", pkgver:"5.4.0-1024.24~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1024-gcp", pkgver:"5.4.0-1024.24~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1024-oracle", pkgver:"5.4.0-1024.24~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1025-azure", pkgver:"5.4.0-1025.25~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-47-generic", pkgver:"5.4.0-47.51~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-47-generic-lpae", pkgver:"5.4.0-47.51~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-47-lowlatency", pkgver:"5.4.0-47.51~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws", pkgver:"5.3.0.1035.34")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws-lts-18.04", pkgver:"4.15.0.1082.84")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.4.0.1025.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure-lts-18.04", pkgver:"4.15.0.1095.68")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1024.11")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp-lts-18.04", pkgver:"4.15.0.1083.101")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic", pkgver:"4.15.0.117.104")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.4.0.47.51~18.04.40")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae", pkgver:"4.15.0.117.104")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.4.0.47.51~18.04.40")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1069.73")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-4.15", pkgver:"4.15.0.1069.73")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1047.32")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.3", pkgver:"5.3.0.1036.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.4", pkgver:"5.4.0.1024.11")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gkeop-5.3", pkgver:"5.3.0.67.124")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gkeop-5.4", pkgver:"5.4.0.47.51~18.04.40")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-kvm", pkgver:"4.15.0.1074.70")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency", pkgver:"4.15.0.117.104")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.4.0.47.51~18.04.40")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem", pkgver:"4.15.0.1096.100")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem-osp1", pkgver:"5.0.0.1068.66")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1024.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle-lts-18.04", pkgver:"4.15.0.1053.63")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi-hwe-18.04", pkgver:"5.4.0.1018.22")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2", pkgver:"4.15.0.1070.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2-hwe-18.04", pkgver:"5.3.0.1033.23")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon", pkgver:"4.15.0.1086.89")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.4.0.47.51~18.04.40")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual", pkgver:"4.15.0.117.104")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.4.0.47.51~18.04.40")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1018-raspi", pkgver:"5.4.0-1018.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1024-aws", pkgver:"5.4.0-1024.24")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1024-gcp", pkgver:"5.4.0-1024.24")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1024-oracle", pkgver:"5.4.0-1024.24")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1025-azure", pkgver:"5.4.0-1025.25")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-47-generic", pkgver:"5.4.0-47.51")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-47-generic-lpae", pkgver:"5.4.0-47.51")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-47-lowlatency", pkgver:"5.4.0-47.51")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-aws", pkgver:"5.4.0.1024.25")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-azure", pkgver:"5.4.0.1025.24")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1024.21")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic", pkgver:"5.4.0.47.50")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-lpae", pkgver:"5.4.0.47.50")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gke", pkgver:"5.4.0.1024.21")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-kvm", pkgver:"5.4.0.1023.21")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-lowlatency", pkgver:"5.4.0.47.50")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem", pkgver:"5.4.0.47.50")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem-osp1", pkgver:"5.4.0.47.50")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1024.21")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-raspi", pkgver:"5.4.0.1018.53")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-raspi2", pkgver:"5.4.0.1018.53")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-virtual", pkgver:"5.4.0.47.50")) flag++;

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
