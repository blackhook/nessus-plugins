#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4301-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(134659);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-19053", "CVE-2019-19056", "CVE-2019-19058", "CVE-2019-19059", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-3016", "CVE-2020-2732");
  script_xref(name:"USN", value:"4301-1");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-4301-1)");
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
"It was discovered that the KVM implementation in the Linux kernel,
when paravirtual TLB flushes are enabled in guests, the hypervisor in
some situations could miss deferred TLB flushes or otherwise mishandle
them. An attacker in a guest VM could use this to expose sensitive
information (read memory from another guest VM). (CVE-2019-3016)

Paulo Bonzini discovered that the KVM hypervisor implementation in the
Linux kernel could improperly let a nested (level 2) guest access the
resources of a parent (level 1) guest in certain situations. An
attacker could use this to expose sensitive information.
(CVE-2020-2732)

It was discovered that the RPMSG character device interface in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19053)

It was discovered that the Marvell Wi-Fi device driver in the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to possibly cause a denial of service
(kernel memory exhaustion). (CVE-2019-19056)

It was discovered that the Intel Wi-Fi device driver in the Linux
kernel device driver in the Linux kernel did not properly deallocate
memory in certain error conditions. A local attacker could possibly
use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19058, CVE-2019-19059)

It was discovered that the Brocade BFA Fibre Channel device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19066)

It was discovered that the Realtek RTL8xxx USB Wi-Fi device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19068).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4301-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2732");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/18");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-19053", "CVE-2019-19056", "CVE-2019-19058", "CVE-2019-19059", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-3016", "CVE-2020-2732");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4301-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1013-oracle", pkgver:"5.0.0-1013.18")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1027-aws", pkgver:"5.0.0-1027.30")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1032-gke", pkgver:"5.0.0-1032.33")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1033-gcp", pkgver:"5.0.0-1033.34")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1035-azure", pkgver:"5.0.0-1035.37")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1043-oem-osp1", pkgver:"5.0.0-1043.48")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws-edge", pkgver:"5.0.0.1027.41")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1035.46")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.0.0.1033.37")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1032.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem-osp1", pkgver:"5.0.0.1043.48")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"5.0.0.1013.13")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.0-aws / linux-image-5.0-azure / linux-image-5.0-gcp / etc");
}
