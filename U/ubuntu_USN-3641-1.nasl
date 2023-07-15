#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3641-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109650);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-1000199", "CVE-2018-1087", "CVE-2018-8897");
  script_xref(name:"USN", value:"3641-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : linux, linux-aws, linux-azure, linux-euclid, linux-gcp, linux-hwe, (USN-3641-1)");
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
"Nick Peterson discovered that the Linux kernel did not properly handle
debug exceptions following a MOV/POP to SS instruction. A local
attacker could use this to cause a denial of service (system crash).
This issue only affected the amd64 architecture. (CVE-2018-8897)

Andy Lutomirski discovered that the KVM subsystem of the Linux kernel
did not properly emulate the ICEBP instruction following a MOV/POP to
SS instruction. A local attacker in a KVM virtual machine could use
this to cause a denial of service (guest VM crash) or possibly
escalate privileges inside of the virtual machine. This issue only
affected the i386 and amd64 architectures. (CVE-2018-1087)

Andy Lutomirski discovered that the Linux kernel did not properly
perform error handling on virtualized debug registers. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-1000199).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3641-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-euclid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-euclid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/09");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-1000199", "CVE-2018-1087", "CVE-2018-8897");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3641-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-147-generic", pkgver:"3.13.0-147.196")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-147-generic-lpae", pkgver:"3.13.0-147.196")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-147-lowlatency", pkgver:"3.13.0-147.196")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-1019-aws", pkgver:"4.4.0-1019.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-124-generic", pkgver:"4.4.0-124.148~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-124-generic-lpae", pkgver:"4.4.0-124.148~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-124-lowlatency", pkgver:"4.4.0-124.148~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1019.19")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic", pkgver:"3.13.0.147.157")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae", pkgver:"3.13.0.147.157")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae-lts-xenial", pkgver:"4.4.0.124.104")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lts-xenial", pkgver:"4.4.0.124.104")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-pae", pkgver:"3.13.0.147.157")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency", pkgver:"3.13.0.147.157")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency-lts-xenial", pkgver:"4.4.0.124.104")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-1015-gcp", pkgver:"4.13.0-1015.19")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-1016-azure", pkgver:"4.13.0-1016.19")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-1026-oem", pkgver:"4.13.0-1026.29")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-41-generic", pkgver:"4.13.0-41.46~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-41-generic-lpae", pkgver:"4.13.0-41.46~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.13.0-41-lowlatency", pkgver:"4.13.0-41.46~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1023-kvm", pkgver:"4.4.0-1023.28")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1057-aws", pkgver:"4.4.0-1057.66")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1089-raspi2", pkgver:"4.4.0-1089.97")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1092-snapdragon", pkgver:"4.4.0-1092.97")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-124-generic", pkgver:"4.4.0-124.148")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-124-generic-lpae", pkgver:"4.4.0-124.148")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-124-lowlatency", pkgver:"4.4.0-124.148")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-9027-euclid", pkgver:"4.4.0-9027.29")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1057.59")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-azure", pkgver:"4.13.0.1016.17")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-euclid", pkgver:"4.4.0.9027.28")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gcp", pkgver:"4.13.0.1015.17")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.124.130")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.13.0.41.60")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.124.130")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.13.0.41.60")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.13.0.1015.17")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1023.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.124.130")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.13.0.41.60")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oem", pkgver:"4.13.0.1026.30")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1089.89")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1092.84")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-1019-raspi2", pkgver:"4.13.0-1019.20")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-41-generic", pkgver:"4.13.0-41.46")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-41-generic-lpae", pkgver:"4.13.0-41.46")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-41-lowlatency", pkgver:"4.13.0-41.46")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-generic", pkgver:"4.13.0.41.44")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-generic-lpae", pkgver:"4.13.0.41.44")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-lowlatency", pkgver:"4.13.0.41.44")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-raspi2", pkgver:"4.13.0.1019.17")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae / etc");
}
