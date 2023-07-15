#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5699-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166514);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2021-3326", "CVE-2021-35942");
  script_xref(name:"USN", value:"5699-1");

  script_name(english:"Ubuntu 16.04 ESM : GNU C Library vulnerabilities (USN-5699-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5699-1 advisory.

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid
    input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program,
    potentially resulting in a denial of service. (CVE-2021-3326)

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5699-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'glibc-source', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc-bin', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-armel', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-i386', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-pic', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-s390', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libc6-x32', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'locales', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'locales-all', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'multiarch-support', 'pkgver': '2.23-0ubuntu11.3+esm2'},
    {'osver': '16.04', 'pkgname': 'nscd', 'pkgver': '2.23-0ubuntu11.3+esm2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-source / libc-bin / libc-dev-bin / libc6 / libc6-amd64 / etc');
}
