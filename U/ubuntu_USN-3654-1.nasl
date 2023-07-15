#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3654-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110048);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-17975", "CVE-2017-18193", "CVE-2017-18222", "CVE-2018-1065", "CVE-2018-1068", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  script_xref(name:"USN", value:"3654-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-3654-1) (Spectre)");
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
"Jann Horn and Ken Johnson discovered that microprocessors utilizing
speculative execution of a memory read may allow unauthorized memory
reads via a sidechannel attack. This flaw is known as Spectre Variant
4. A local attacker could use this to expose sensitive information,
including kernel memory. (CVE-2018-3639)

Tuba Yavuz discovered that a double-free error existed in the USBTV007
driver of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-17975)

It was discovered that a race condition existed in the F2FS
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2017-18193)

It was discovered that a buffer overflow existed in the Hisilicon HNS
Ethernet Device driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-18222)

It was discovered that the netfilter subsystem in the Linux kernel did
not validate that rules containing jumps contained user-defined
chains. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2018-1065)

It was discovered that the netfilter subsystem of the Linux kernel did
not properly validate ebtables offsets. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-1068)

It was discovered that a NULL pointer dereference vulnerability
existed in the DCCP protocol implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system
crash). (CVE-2018-1130)

It was discovered that the SCTP Protocol implementation in the Linux
kernel did not properly validate userspace provided payload lengths in
some situations. A local attacker could use this to cause a denial of
service (system crash). (CVE-2018-5803)

It was discovered that a double free error existed in the block layer
subsystem of the Linux kernel when setting up a request queue. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-7480)

It was discovered that a memory leak existed in the SAS driver
subsystem of the Linux kernel. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2018-7757)

It was discovered that a race condition existed in the x86 machine
check handler in the Linux kernel. A local privileged attacker could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-7995)

Eyal Itkin discovered that the USB displaylink video adapter driver in
the Linux kernel did not properly validate mmap offsets sent from
userspace. A local attacker could use this to expose sensitive
information (kernel memory) or possibly execute arbitrary code.
(CVE-2018-8781)

Silvio Cesare discovered a buffer overwrite existed in the NCPFS
implementation in the Linux kernel. A remote attacker controlling a
malicious NCPFS server could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2018-8822).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3654-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-17975", "CVE-2017-18193", "CVE-2017-18222", "CVE-2018-1065", "CVE-2018-1068", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3654-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1026-kvm", pkgver:"4.4.0-1026.31")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1060-aws", pkgver:"4.4.0-1060.69")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-127-generic", pkgver:"4.4.0-127.153")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-127-generic-lpae", pkgver:"4.4.0-127.153")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-127-lowlatency", pkgver:"4.4.0-127.153")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1060.62")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.127.133")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.127.133")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1026.25")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.127.133")) flag++;

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
