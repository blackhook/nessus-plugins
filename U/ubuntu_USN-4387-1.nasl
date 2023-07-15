#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4387-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137297);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-0067", "CVE-2020-0543", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12659");
  script_xref(name:"USN", value:"4387-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 : Linux kernel vulnerabilities (USN-4387-1)");
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
"It was discovered that the F2FS file system implementation in the
Linux kernel did not properly perform bounds checking on xattrs in
some situations. A local attacker could possibly use this to expose
sensitive information (kernel memory). (CVE-2020-0067)

It was discovered that memory contents previously stored in
microarchitectural special registers after RDRAND, RDSEED, and SGX
EGETKEY read operations on Intel client and Xeon E3 processors may be
briefly exposed to processes on the same or different processor cores.
A local attacker could use this to expose sensitive information.
(CVE-2020-0543)

Piotr Krysiuk discovered that race conditions existed in the file
system implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash). (CVE-2020-12114)

It was discovered that the USB susbsystem's scatter-gather
implementation in the Linux kernel did not properly take data
references in some situations, leading to a use-after-free. A
physically proximate attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2020-12464)

Bui Quang Minh discovered that the XDP socket implementation in the
Linux kernel did not properly validate meta-data passed from user
space, leading to an out-of-bounds write vulnerability. A local
attacker with the CAP_NET_ADMIN capability could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2020-12659).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4387-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/10");
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
if (! preg(pattern:"^(18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2020-0067", "CVE-2020-0543", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12659");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4387-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1023-aws", pkgver:"5.3.0-1023.25~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1024-oracle", pkgver:"5.3.0-1024.26~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1026-gcp", pkgver:"5.3.0-1026.28~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1026-gke", pkgver:"5.3.0-1026.28~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1026-raspi2", pkgver:"5.3.0-1027.29~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1028-azure", pkgver:"5.3.0-1028.29~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-59-generic", pkgver:"5.3.0-59.53~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-59-generic-lpae", pkgver:"5.3.0-59.53~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-59-lowlatency", pkgver:"5.3.0-59.53~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws", pkgver:"5.3.0.1023.23")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.3.0.1028.25")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.3.0.1026.21")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.3.0.59.113")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.3.0.59.113")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.3", pkgver:"5.3.0.1026.13")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gkeop-5.3", pkgver:"5.3.0.59.113")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.3.0.59.113")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"5.3.0.1024.22")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2-hwe-18.04", pkgver:"5.3.0.1027.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.3.0.59.113")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.3.0.59.113")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1023-aws", pkgver:"5.3.0-1023.25")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1023-kvm", pkgver:"5.3.0-1023.25")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1024-oracle", pkgver:"5.3.0-1024.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1026-gcp", pkgver:"5.3.0-1026.28")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1026-raspi2", pkgver:"5.3.0-1027.29")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1028-azure", pkgver:"5.3.0-1028.29")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-59-generic", pkgver:"5.3.0-59.53")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-59-generic-lpae", pkgver:"5.3.0-59.53")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-59-lowlatency", pkgver:"5.3.0-59.53")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-59-snapdragon", pkgver:"5.3.0-59.53")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-aws", pkgver:"5.3.0.1023.34")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-azure", pkgver:"5.3.0.1028.47")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gcp", pkgver:"5.3.0.1026.37")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic", pkgver:"5.3.0.59.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic-lpae", pkgver:"5.3.0.59.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gke", pkgver:"5.3.0.1026.37")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-kvm", pkgver:"5.3.0.1023.21")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-lowlatency", pkgver:"5.3.0.59.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-oracle", pkgver:"5.3.0.1024.40")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-raspi2", pkgver:"5.3.0.1027.25")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-snapdragon", pkgver:"5.3.0.59.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-virtual", pkgver:"5.3.0.59.49")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.3-aws / linux-image-5.3-azure / linux-image-5.3-gcp / etc");
}
