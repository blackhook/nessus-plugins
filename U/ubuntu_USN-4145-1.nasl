#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4145-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129491);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2016-10905", "CVE-2017-18509", "CVE-2018-20961", "CVE-2018-20976", "CVE-2019-0136", "CVE-2019-10207", "CVE-2019-11487", "CVE-2019-13631", "CVE-2019-15211", "CVE-2019-15215", "CVE-2019-15926");
  script_xref(name:"USN", value:"4145-1");

  script_name(english:"Ubuntu 16.04 LTS : linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon vulnerabilities (USN-4145-1)");
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
"It was discovered that a race condition existed in the GFS2 file
system in the Linux kernel. A local attacker could possibly use this
to cause a denial of service (system crash). (CVE-2016-10905)

It was discovered that the IPv6 implementation in the Linux kernel did
not properly validate socket options in some situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-18509)

It was discovered that the USB gadget Midi driver in the Linux kernel
contained a double-free vulnerability when handling certain error
conditions. A local attacker could use this to cause a denial of
service (system crash). (CVE-2018-20961)

It was discovered that the XFS file system in the Linux kernel did not
properly handle mount failures in some situations. A local attacker
could possibly use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2018-20976)

It was discovered that the Intel Wi-Fi device driver in the Linux
kernel did not properly validate certain Tunneled Direct Link Setup
(TDLS). A physically proximate attacker could use this to cause a
denial of service (Wi-Fi disconnect). (CVE-2019-0136)

It was discovered that the Bluetooth UART implementation in the Linux
kernel did not properly check for missing tty operations. A local
attacker could use this to cause a denial of service. (CVE-2019-10207)

It was discovered that an integer overflow existed in the Linux kernel
when reference counting pages, leading to potential use-after-free
issues. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-11487)

It was discovered that the GTCO tablet input driver in the Linux
kernel did not properly bounds check the initial HID report sent by
the device. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2019-13631)

It was discovered that the Raremono AM/FM/SW radio device driver in
the Linux kernel did not properly allocate memory, leading to a
use-after-free. A physically proximate attacker could use this to
cause a denial of service or possibly execute arbitrary code.
(CVE-2019-15211)

It was discovered that a race condition existed in the CPiA2
video4linux device driver for the Linux kernel, leading to a
use-after-free. A physically proximate attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15215)

It was discovered that the Atheros mobile chipset driver in the Linux
kernel did not properly validate data in some situations. An attacker
could use this to cause a denial of service (system crash).
(CVE-2019-15926).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4145-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/01");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2016-10905", "CVE-2017-18509", "CVE-2018-20961", "CVE-2018-20976", "CVE-2019-0136", "CVE-2019-10207", "CVE-2019-11487", "CVE-2019-13631", "CVE-2019-15211", "CVE-2019-15215", "CVE-2019-15926");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4145-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1059-kvm", pkgver:"4.4.0-1059.66")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1095-aws", pkgver:"4.4.0-1095.106")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1123-raspi2", pkgver:"4.4.0-1123.132")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1127-snapdragon", pkgver:"4.4.0-1127.135")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-165-generic", pkgver:"4.4.0-165.193")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-165-generic-lpae", pkgver:"4.4.0-165.193")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-165-lowlatency", pkgver:"4.4.0-165.193")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1095.99")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.165.173")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.165.173")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1059.59")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.165.173")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1123.123")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1127.119")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual", pkgver:"4.4.0.165.173")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
