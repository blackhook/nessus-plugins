#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3696-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110896);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-13695", "CVE-2017-18255", "CVE-2017-18257", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-3665", "CVE-2018-5814", "CVE-2018-7755");
  script_xref(name:"USN", value:"3696-1");

  script_name(english:"Ubuntu 16.04 LTS : linux, linux-aws, linux-kvm, linux-raspi2, linux-snapdragon vulnerabilities (USN-3696-1)");
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
"It was discovered that an integer overflow existed in the perf
subsystem of the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2017-18255)

Wei Fang discovered an integer overflow in the F2FS filesystem
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service. (CVE-2017-18257)

It was discovered that an information leak existed in the generic SCSI
driver in the Linux kernel. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-1000204)

It was discovered that the wait4() system call in the Linux kernel did
not properly validate its arguments in some situations. A local
attacker could possibly use this to cause a denial of service.
(CVE-2018-10087)

It was discovered that the kill() system call implementation in the
Linux kernel did not properly validate its arguments in some
situations. A local attacker could possibly use this to cause a denial
of service. (CVE-2018-10124)

Julian Stecklina and Thomas Prescher discovered that FPU register
states (such as MMX, SSE, and AVX registers) which are lazily restored
are potentially vulnerable to a side channel attack. A local attacker
could use this to expose sensitive information. (CVE-2018-3665)

Jakub Jirasek discovered that multiple use-after-errors existed in the
USB/IP implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-5814)

It was discovered that an information leak vulnerability existed in
the floppy driver in the Linux kernel. A local attacker could use this
to expose sensitive information (kernel memory). (CVE-2018-7755)

Seunghun Han discovered an information leak in the ACPI handling code
in the Linux kernel when handling early termination of ACPI table
loading. A local attacker could use this to expose sensitive informal
(kernel address locations). (CVE-2017-13695)

It was discovered that a memory leak existed in the Serial Attached
SCSI (SAS) implementation in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2018-10021).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3696-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");
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
  cve_list = make_list("CVE-2017-13695", "CVE-2017-18255", "CVE-2017-18257", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-3665", "CVE-2018-5814", "CVE-2018-7755");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3696-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1029-kvm", pkgver:"4.4.0-1029.34")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1062-aws", pkgver:"4.4.0-1062.71")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1092-raspi2", pkgver:"4.4.0-1092.100")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1095-snapdragon", pkgver:"4.4.0-1095.100")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-130-generic", pkgver:"4.4.0-130.156")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-130-generic-lpae", pkgver:"4.4.0-130.156")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-130-lowlatency", pkgver:"4.4.0-130.156")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1062.64")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.130.136")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.130.136")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1029.28")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.130.136")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1092.92")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1095.87")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
