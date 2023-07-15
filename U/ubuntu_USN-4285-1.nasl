#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4285-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133798);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14615", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18786", "CVE-2019-18809", "CVE-2019-19057", "CVE-2019-19063", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108", "CVE-2020-7053");
  script_xref(name:"USN", value:"4285-1");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-4285-1)");
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
"It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors.
A local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that the HSA Linux kernel driver for AMD GPU devices
did not properly check for errors in certain situations, leading to a
NULL pointer dereference. A local attacker could possibly use this to
cause a denial of service. (CVE-2019-16229)

It was discovered that the Marvell 8xxx Libertas WLAN device driver in
the Linux kernel did not properly check for errors in certain
situations, leading to a NULL pointer dereference. A local attacker
could possibly use this to cause a denial of service. (CVE-2019-16232)

It was discovered that the Renesas Digital Radio Interface (DRIF)
driver in the Linux kernel did not properly initialize data. A local
attacker could possibly use this to expose sensitive information
(kernel memory). (CVE-2019-18786).

It was discovered that the Afatech AF9005 DVB-T USB device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-18809)

It was discovered that multiple memory leaks existed in the Marvell
WiFi-Ex Driver for the Linux kernel. A local attacker could possibly
use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19057)

It was discovered that the Realtek rtlwifi USB device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19063)

It was discovered that the Kvaser CAN/USB driver in the Linux kernel
did not properly initialize memory in certain situations. A local
attacker could possibly use this to expose sensitive information
(kernel memory). (CVE-2019-19947)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer
dereference. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2019-19965)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
implementation in the Linux kernel did not properly deallocate memory
in certain error conditions. An attacker could possibly use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-20096)

Mitchell Frank discovered that the Wi-Fi implementation in the Linux
kernel when used as an access point would send IAPP location updates
for stations before client authentication had completed. A physically
proximate attacker could use this to cause a denial of service.
(CVE-2019-5108)

It was discovered that a race condition can lead to a use-after-free
while destroying GEM contexts in the i915 driver for the Linux kernel.
A local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2020-7053).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4285-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7053");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");
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
  cve_list = make_list("CVE-2019-14615", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18786", "CVE-2019-18809", "CVE-2019-19057", "CVE-2019-19063", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108", "CVE-2020-7053");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4285-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1011-oracle", pkgver:"5.0.0-1011.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1025-aws", pkgver:"5.0.0-1025.28")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1030-gke", pkgver:"5.0.0-1030.31")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1031-gcp", pkgver:"5.0.0-1031.32")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1032-azure", pkgver:"5.0.0-1032.34")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1032.43")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.0.0.1031.35")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1030.18")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.0-aws / linux-image-5.0-azure / linux-image-5.0-gcp / etc");
}
