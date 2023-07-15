#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4404-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137849);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-5963", "CVE-2020-5967", "CVE-2020-5973");
  script_xref(name:"USN", value:"4404-2");
  script_xref(name:"IAVA", value:"2020-A-0290-S");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 / 20.04 : Linux kernel vulnerabilities (USN-4404-2)");
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
"USN-4404-1 fixed vulnerabilities in the NVIDIA graphics drivers. This
update provides the corresponding updates for the NVIDIA Linux DKMS
kernel modules.

Thomas E. Carroll discovered that the NVIDIA Cuda grpahics driver did
not properly perform access control when performing IPC. An attacker
could use this to cause a denial of service or possibly execute
arbitrary code. (CVE-2020-5963) It was discovered that the UVM driver
in the NVIDIA graphics driver contained a race condition. A local
attacker could use this to cause a denial of service. (CVE-2020-5967)
It was discovered that the NVIDIA virtual GPU guest drivers contained
an unspecified vulnerability that could potentially lead to privileged
operation execution. An attacker could use this to cause a denial of
service. (CVE-2020-5973).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4404-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5963");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2020-5963", "CVE-2020-5967", "CVE-2020-5973");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4404-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1047-oracle", pkgver:"4.15.0-1047.51")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1076-aws", pkgver:"4.15.0-1076.80")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-108-generic", pkgver:"4.15.0-108.109")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-108-generic-lpae", pkgver:"4.15.0-108.109")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-108-lowlatency", pkgver:"4.15.0-108.109")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1090-oem", pkgver:"4.15.0-1090.100")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1062-oem-osp1", pkgver:"5.0.0-1062.67")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1027-oracle", pkgver:"5.3.0-1027.29~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1028-aws", pkgver:"5.3.0-1028.30~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1029-gcp", pkgver:"5.3.0-1029.31~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1031-azure", pkgver:"5.3.0-1031.32~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-61-generic", pkgver:"5.3.0-61.55~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-61-generic-lpae", pkgver:"5.3.0-61.55~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-61-lowlatency", pkgver:"5.3.0-61.55~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws", pkgver:"5.3.0.1028.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws-lts-18.04", pkgver:"4.15.0.1076.78")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.3.0.1031.27")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.3.0.1029.23")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic", pkgver:"4.15.0.108.96")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.3.0.61.114")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae", pkgver:"4.15.0.108.96")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.3.0.61.114")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gkeop-5.3", pkgver:"5.3.0.61.114")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency", pkgver:"4.15.0.108.96")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.3.0.61.114")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem", pkgver:"4.15.0.1090.93")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem-osp1", pkgver:"5.0.0.1062.60")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"5.3.0.1027.24")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle-edge", pkgver:"5.3.0.1027.24")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle-lts-18.04", pkgver:"4.15.0.1047.56")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.3.0.61.114")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual", pkgver:"4.15.0.108.96")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.3.0.61.114")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1027-oracle", pkgver:"5.3.0-1027.29")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1028-aws", pkgver:"5.3.0-1028.30")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1029-gcp", pkgver:"5.3.0-1029.31")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-61-generic", pkgver:"5.3.0-61.55")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-61-generic-lpae", pkgver:"5.3.0-61.55")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-61-lowlatency", pkgver:"5.3.0-61.55")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-61-snapdragon", pkgver:"5.3.0-61.55")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-aws", pkgver:"5.3.0.1028.38")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gcp", pkgver:"5.3.0.1029.39")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic", pkgver:"5.3.0.61.51")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic-lpae", pkgver:"5.3.0.61.51")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gke", pkgver:"5.3.0.1029.39")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-lowlatency", pkgver:"5.3.0.61.51")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-oracle", pkgver:"5.3.0.1027.42")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-snapdragon", pkgver:"5.3.0.61.51")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-virtual", pkgver:"5.3.0.61.51")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1017-aws", pkgver:"5.4.0-1017.17")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1018-gcp", pkgver:"5.4.0-1018.18")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1018-oracle", pkgver:"5.4.0-1018.18")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1019-azure", pkgver:"5.4.0-1019.19")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-39-generic", pkgver:"5.4.0-39.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-39-generic-lpae", pkgver:"5.4.0-39.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-39-lowlatency", pkgver:"5.4.0-39.43")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-aws", pkgver:"5.4.0.1017.18")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-azure", pkgver:"5.4.0.1019.18")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1018.16")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-hwe-20.04", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-lpae", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-lpae-hwe-20.04", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gke", pkgver:"5.4.0.1018.16")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-lowlatency", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-lowlatency-hwe-20.04", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem-osp1", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1018.16")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-virtual", pkgver:"5.4.0.39.42")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-virtual-hwe-20.04", pkgver:"5.4.0.39.42")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.15-aws / linux-image-4.15-generic / etc");
}
