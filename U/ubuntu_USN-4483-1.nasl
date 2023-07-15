#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4483-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140181);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-20810", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10781", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12771", "CVE-2020-13974", "CVE-2020-14356", "CVE-2020-15393", "CVE-2020-24394");
  script_xref(name:"USN", value:"4483-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 : Linux kernel vulnerabilities (USN-4483-1)");
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
"Chuhong Yuan discovered that go7007 USB audio device driver in the
Linux kernel did not properly deallocate memory in some failure
conditions. A physically proximate attacker could use this to cause a
denial of service (memory exhaustion). (CVE-2019-20810) Fan Yang
discovered that the mremap implementation in the Linux kernel did not
properly handle DAX Huge Pages. A local attacker with access to DAX
storage could use this to gain administrative privileges.
(CVE-2020-10757) It was discovered that the Linux kernel did not
correctly apply Speculative Store Bypass Disable (SSBD) mitigations in
certain situations. A local attacker could possibly use this to expose
sensitive information. (CVE-2020-10766) It was discovered that the
Linux kernel did not correctly apply Indirect Branch Predictor Barrier
(IBPB) mitigations in certain situations. A local attacker could
possibly use this to expose sensitive information. (CVE-2020-10767) It
was discovered that the Linux kernel could incorrectly enable Indirect
Branch Speculation after it has been disabled for a process via a
prctl() call. A local attacker could possibly use this to expose
sensitive information. (CVE-2020-10768) Luca Bruno discovered that the
zram module in the Linux kernel did not properly restrict unprivileged
users from accessing the hot_add sysfs file. A local attacker could
use this to cause a denial of service (memory exhaustion).
(CVE-2020-10781) It was discovered that the XFS file system
implementation in the Linux kernel did not properly validate meta data
in some circumstances. An attacker could use this to construct a
malicious XFS image that, when mounted, could cause a denial of
service. (CVE-2020-12655) It was discovered that the bcache subsystem
in the Linux kernel did not properly release a lock in some error
conditions. A local attacker could possibly use this to cause a denial
of service. (CVE-2020-12771) It was discovered that the Virtual
Terminal keyboard driver in the Linux kernel contained an integer
overflow. A local attacker could possibly use this to have an
unspecified impact. (CVE-2020-13974) It was discovered that the cgroup
v2 subsystem in the Linux kernel did not properly perform reference
counting in some situations, leading to a NULL pointer dereference. A
local attacker could use this to cause a denial of service or possibly
gain administrative privileges. (CVE-2020-14356) Kyungtae Kim
discovered that the USB testing driver in the Linux kernel did not
properly deallocate memory on disconnect events. A physically
proximate attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2020-15393) It was discovered that the NFS server
implementation in the Linux kernel did not properly honor umask
settings when setting permissions while creating file system objects
if the underlying file system did not support ACLs. An attacker could
possibly use this to expose sensitive information or violate system
integrity. (CVE-2020-24394) It was discovered that the Kerberos SUNRPC
GSS implementation in the Linux kernel did not properly deallocate
memory on module unload. A local privileged attacker could possibly
use this to cause a denial of service (memory exhaustion).
(CVE-2020-12656).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4483-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14356");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-20810", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10781", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12771", "CVE-2020-13974", "CVE-2020-14356", "CVE-2020-15393", "CVE-2020-24394");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4483-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1016-raspi", pkgver:"5.4.0-1016.17~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1022-aws", pkgver:"5.4.0-1022.22~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1022-gcp", pkgver:"5.4.0-1022.22~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1022-oracle", pkgver:"5.4.0-1022.22~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-1023-azure", pkgver:"5.4.0-1023.23~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-45-generic", pkgver:"5.4.0-45.49~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-45-generic-lpae", pkgver:"5.4.0-45.49~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.4.0-45-lowlatency", pkgver:"5.4.0-45.49~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws-edge", pkgver:"5.4.0.1022.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.4.0.1023.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1022.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.4", pkgver:"5.4.0.1022.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1022.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi-hwe-18.04", pkgver:"5.4.0.1016.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1016-raspi", pkgver:"5.4.0-1016.17")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1022-aws", pkgver:"5.4.0-1022.22")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1022-gcp", pkgver:"5.4.0-1022.22")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1022-oracle", pkgver:"5.4.0-1022.22")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-1023-azure", pkgver:"5.4.0-1023.23")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-45-generic", pkgver:"5.4.0-45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-45-generic-lpae", pkgver:"5.4.0-45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-5.4.0-45-lowlatency", pkgver:"5.4.0-45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-aws", pkgver:"5.4.0.1022.23")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-azure", pkgver:"5.4.0.1023.22")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gcp", pkgver:"5.4.0.1022.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic", pkgver:"5.4.0.45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-generic-lpae", pkgver:"5.4.0.45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-gke", pkgver:"5.4.0.1022.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-kvm", pkgver:"5.4.0.1021.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-lowlatency", pkgver:"5.4.0.45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem", pkgver:"5.4.0.45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oem-osp1", pkgver:"5.4.0.45.49")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-oracle", pkgver:"5.4.0.1022.20")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-raspi", pkgver:"5.4.0.1016.51")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-raspi2", pkgver:"5.4.0.1016.51")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"linux-image-virtual", pkgver:"5.4.0.45.49")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.4-aws / linux-image-5.4-azure / linux-image-5.4-gcp / etc");
}
