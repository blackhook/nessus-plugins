#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3741-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111752);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");
  script_xref(name:"USN", value:"3741-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Xenial HWE) vulnerabilities (USN-3741-2) (Foreshadow)");
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
"USN-3741-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

It was discovered that memory present in the L1 data cache of an Intel
CPU core may be exposed to a malicious process that is executing on
the CPU core. This vulnerability is also known as L1 Terminal Fault
(L1TF). A local attacker in a guest virtual machine could use this to
expose sensitive information (memory from other guests or the host
OS). (CVE-2018-3646)

It was discovered that memory present in the L1 data cache of an Intel
CPU core may be exposed to a malicious process that is executing on
the CPU core. This vulnerability is also known as L1 Terminal Fault
(L1TF). A local attacker could use this to expose sensitive
information (memory from the kernel or other processes).
(CVE-2018-3620)

Juha-Matti Tilli discovered that the TCP implementation in the Linux
kernel performed algorithmically expensive operations in some
situations when handling incoming packets. A remote attacker could use
this to cause a denial of service. (CVE-2018-5390)

Juha-Matti Tilli discovered that the IP implementation in the Linux
kernel performed algorithmically expensive operations in some
situations when handling incoming packet fragments. A remote attacker
could use this to cause a denial of service. (CVE-2018-5391).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3741-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");
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
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3741-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-1027-aws", pkgver:"4.4.0-1027.30")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-133-generic", pkgver:"4.4.0-133.159~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-133-generic-lpae", pkgver:"4.4.0-133.159~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-133-lowlatency", pkgver:"4.4.0-133.159~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1027.27")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae-lts-xenial", pkgver:"4.4.0.133.113")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lts-xenial", pkgver:"4.4.0.133.113")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency-lts-xenial", pkgver:"4.4.0.133.113")) flag++;

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
