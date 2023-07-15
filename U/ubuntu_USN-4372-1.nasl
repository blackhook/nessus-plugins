#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4372-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136803);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-15034", "CVE-2019-20382", "CVE-2020-10702", "CVE-2020-11869", "CVE-2020-1983");
  script_xref(name:"USN", value:"4372-1");
  script_xref(name:"IAVB", value:"2020-B-0026-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 / 20.04 : QEMU vulnerabilities (USN-4372-1)");
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
"It was discovered that QEMU incorrectly handled bochs-display devices.
A local attacker in a guest could use this to cause a denial of
service or possibly execute arbitrary code in the host. This issue
only affected Ubuntu 19.10. (CVE-2019-15034)

It was discovered that QEMU incorrectly handled memory during certain
VNC operations. A remote attacker could possibly use this issue to
cause QEMU to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and
Ubuntu 19.10. (CVE-2019-20382)

It was discovered that QEMU incorrectly generated QEMU Pointer
Authentication signatures on ARM. A local attacker could possibly use
this issue to bypass PAuth. This issue only affected Ubuntu 19.10.
(CVE-2020-10702)

Ziming Zhang discovered that QEMU incorrectly handled ATI VGA
emulation. A local attacker in a guest could use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 20.04 LTS. (CVE-2020-11869)

Aviv Sasson discovered that QEMU incorrectly handled Slirp networking.
A remote attacker could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and
Ubuntu 19.10. (CVE-2020-1983).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4372-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15034");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"qemu", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.44")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-arm", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-mips", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-ppc", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-s390x", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-sparc", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-x86", pkgver:"1:2.11+dfsg-1ubuntu7.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-arm", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-mips", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-ppc", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-s390x", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-sparc", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-x86", pkgver:"1:4.0+dfsg-0ubuntu9.6")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system-arm", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system-mips", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system-ppc", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system-s390x", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system-sparc", pkgver:"1:4.2-3ubuntu6.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"qemu-system-x86", pkgver:"1:4.2-3ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu / qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
