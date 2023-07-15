#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4191-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131017);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-12068", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-15890");
  script_xref(name:"USN", value:"4191-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 / 19.10 : QEMU vulnerabilities (USN-4191-1)");
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
"It was discovered that the LSI SCSI adapter emulator implementation in
QEMU did not properly validate executed scripts. A local attacker
could use this to cause a denial of service. (CVE-2019-12068)

Sergej Schumilo, Cornelius Aschermann and Simon Worner discovered
that the qxl paravirtual graphics driver implementation in QEMU
contained a NULL pointer dereference. A local attacker in a guest
could use this to cause a denial of service. (CVE-2019-12155)

Riccardo Schirone discovered that the QEMU bridge helper did not
properly validate network interface names. A local attacker could
possibly use this to bypass ACL restrictions. (CVE-2019-13164)

It was discovered that a heap-based buffer overflow existed in the
SLiRP networking implementation of QEMU. A local attacker in a guest
could use this to cause a denial of service or possibly execute
arbitrary code in the host. (CVE-2019-14378)

It was discovered that a use-after-free vulnerability existed in the
SLiRP networking implementation of QEMU. A local attacker in a guest
could use this to cause a denial of service. (CVE-2019-15890).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4191-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"qemu", pkgver:"1:2.5+dfsg-5ubuntu10.42")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-kvm", pkgver:"1:2.5+dfsg-5ubuntu10.42")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-common", pkgver:"1:2.5+dfsg-5ubuntu10.42")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.42")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-user-static", pkgver:"1:2.5+dfsg-5ubuntu10.42")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-utils", pkgver:"1:2.5+dfsg-5ubuntu10.42")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu", pkgver:"1:2.11+dfsg-1ubuntu7.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-kvm", pkgver:"1:2.11+dfsg-1ubuntu7.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-common", pkgver:"1:2.11+dfsg-1ubuntu7.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-x86", pkgver:"1:2.11+dfsg-1ubuntu7.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-user-static", pkgver:"1:2.11+dfsg-1ubuntu7.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-utils", pkgver:"1:2.11+dfsg-1ubuntu7.20")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu-kvm", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu-system-common", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu-system-gui", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu-system-x86", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu-user-static", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"qemu-utils", pkgver:"1:3.1+dfsg-2ubuntu3.6")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-kvm", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-common", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-gui", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-system-x86", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-user-static", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"qemu-utils", pkgver:"1:4.0+dfsg-0ubuntu9.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu / qemu-kvm / qemu-system-common / qemu-system-gui / etc");
}
