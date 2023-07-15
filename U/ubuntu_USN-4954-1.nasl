#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4954-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149477);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2009-5155", "CVE-2020-6096");
  script_xref(name:"USN", value:"4954-1");

  script_name(english:"Ubuntu 16.04 LTS : GNU C Library vulnerabilities (USN-4954-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4954-1 advisory.

  - In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses
    alternatives, which allows attackers to cause a denial of service (assertion failure and application exit)
    or trigger an incorrect result by attempting a regular-expression match. (CVE-2009-5155)

  - An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() implementation of GNU glibc
    2.30.9000. Calling memcpy() (on ARMv7 targets that utilize the GNU glibc implementation) with a negative
    value for the 'num' parameter results in a signed comparison vulnerability. If an attacker underflows the
    'num' parameter to memcpy(), this vulnerability could lead to undefined behavior such as writing to out-
    of-bounds memory and potentially remote code execution. Furthermore, this memcpy() implementation allows
    for program execution to continue in scenarios where a segmentation fault or crash should have occurred.
    The dangers occur in that subsequent execution and iterations of this code will be executed with this
    corrupted data. (CVE-2020-6096)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4954-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6096");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'glibc-source', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc-bin', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-armel', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-ppc64', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-i386', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-pic', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-ppc64', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-s390', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-udeb', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'libc6-x32', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'locales', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'locales-all', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'multiarch-support', 'pkgver': '2.23-0ubuntu11.3'},
    {'osver': '16.04', 'pkgname': 'nscd', 'pkgver': '2.23-0ubuntu11.3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-source / libc-bin / libc-dev-bin / libc6 / libc6-amd64 / etc');
}