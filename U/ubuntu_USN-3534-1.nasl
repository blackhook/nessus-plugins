#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3534-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106134);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-1000408", "CVE-2017-1000409", "CVE-2017-15670", "CVE-2017-15804", "CVE-2017-16997", "CVE-2017-17426", "CVE-2018-1000001");
  script_xref(name:"USN", value:"3534-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : eglibc, glibc vulnerabilities (USN-3534-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that the GNU C library did not properly handle all
of the possible return values from the kernel getcwd(2) syscall. A
local attacker could potentially exploit this to execute arbitrary
code in setuid programs and gain administrative privileges.
(CVE-2018-1000001)

A memory leak was discovered in the _dl_init_paths() function in the
GNU C library dynamic loader. A local attacker could potentially
exploit this with a specially crafted value in the LD_HWCAP_MASK
environment variable, in combination with CVE-2017-1000409 and another
vulnerability on a system with hardlink protections disabled, in order
to gain administrative privileges. (CVE-2017-1000408)

A heap-based buffer overflow was discovered in the _dl_init_paths()
function in the GNU C library dynamic loader. A local attacker could
potentially exploit this with a specially crafted value in the
LD_LIBRARY_PATH environment variable, in combination with
CVE-2017-1000408 and another vulnerability on a system with hardlink
protections disabled, in order to gain administrative privileges.
(CVE-2017-1000409)

An off-by-one error leading to a heap-based buffer overflow was
discovered in the GNU C library glob() implementation. An attacker
could potentially exploit this to cause a denial of service or execute
arbitrary code via a maliciously crafted pattern. (CVE-2017-15670)

A heap-based buffer overflow was discovered during unescaping of user
names with the ~ operator in the GNU C library glob() implementation.
An attacker could potentially exploit this to cause a denial of
service or execute arbitrary code via a maliciously crafted pattern.
(CVE-2017-15804)

It was discovered that the GNU C library dynamic loader mishandles
RPATH and RUNPATH containing $ORIGIN for privileged (setuid or
AT_SECURE) programs. A local attacker could potentially exploit this
by providing a specially crafted library in the current working
directory in order to gain administrative privileges. (CVE-2017-16997)

It was discovered that the GNU C library malloc() implementation could
return a memory block that is too small if an attempt is made to
allocate an object whose size is close to SIZE_MAX, resulting in a
heap-based overflow. An attacker could potentially exploit this to
cause a denial of service or execute arbitrary code. This issue only
affected Ubuntu 17.10. (CVE-2017-17426).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3534-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected libc6 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "realpath()" Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libc6", pkgver:"2.19-0ubuntu6.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libc6", pkgver:"2.23-0ubuntu10")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libc6", pkgver:"2.26-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libc6");
}
