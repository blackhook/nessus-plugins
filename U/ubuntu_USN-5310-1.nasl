#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5310-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158502);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2016-10228",
    "CVE-2019-25013",
    "CVE-2020-6096",
    "CVE-2020-27618",
    "CVE-2020-29562",
    "CVE-2021-3326",
    "CVE-2021-3998",
    "CVE-2021-3999",
    "CVE-2021-27645",
    "CVE-2021-35942",
    "CVE-2022-23218",
    "CVE-2022-23219"
  );
  script_xref(name:"USN", value:"5310-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : GNU C Library vulnerabilities (USN-5310-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5310-1 advisory.

  - The iconv program in the GNU C Library (aka glibc or libc6) 2.31 and earlier, when invoked with multiple
    suffixes in the destination encoding (TRANSLATE or IGNORE) along with the -c option, enters an infinite
    loop when processing invalid multi-byte input sequences, leading to a denial of service. (CVE-2016-10228)

  - The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-
    byte input sequences in the EUC-KR encoding, may have a buffer over-read. (CVE-2019-25013)

  - An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() implementation of GNU glibc
    2.30.9000. Calling memcpy() (on ARMv7 targets that utilize the GNU glibc implementation) with a negative
    value for the 'num' parameter results in a signed comparison vulnerability. If an attacker underflows the
    'num' parameter to memcpy(), this vulnerability could lead to undefined behavior such as writing to out-
    of-bounds memory and potentially remote code execution. Furthermore, this memcpy() implementation allows
    for program execution to continue in scenarios where a segmentation fault or crash should have occurred.
    The dangers occur in that subsequent execution and iterations of this code will be executed with this
    corrupted data. (CVE-2020-6096)

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid
    multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390, and IBM1399 encodings, fails to advance
    the input state, which could lead to an infinite loop in applications, resulting in a denial of service, a
    different vulnerability from CVE-2016-10228. (CVE-2020-27618)

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.30 to 2.32, when converting UCS4 text
    containing an irreversible character, fails an assertion in the code path and aborts the program,
    potentially resulting in a denial of service. (CVE-2020-29562)

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid
    input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program,
    potentially resulting in a denial of service. (CVE-2021-3326)

  - The nameserver caching daemon (nscd) in the GNU C Library (aka glibc or libc6) 2.29 through 2.33, when
    processing a request for netgroup lookup, may crash due to a double-free, potentially resulting in
    degraded service or Denial of Service on the local system. This is related to netgroupcache.c.
    (CVE-2021-27645)

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

  - The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its path argument on the stack without validating its length, which may result in a
    buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23218)

  - The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its hostname argument on the stack without validating its length, which may result in
    a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23219)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5310-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23219");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-devtools");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-lse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-prof");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'glibc-source', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc-bin', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-armel', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-dev', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-i386', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-lse', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-pic', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-s390', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'libc6-x32', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'locales', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'locales-all', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'multiarch-support', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '18.04', 'pkgname': 'nscd', 'pkgver': '2.27-3ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'glibc-source', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc-bin', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-armel', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-dev', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-i386', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-lse', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-pic', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-prof', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-s390', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'libc6-x32', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'locales', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'locales-all', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '20.04', 'pkgname': 'nscd', 'pkgver': '2.31-0ubuntu9.7'},
    {'osver': '21.10', 'pkgname': 'glibc-source', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc-bin', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc-dev-bin', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc-devtools', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-amd64', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-dev', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-i386', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-prof', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-s390', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'libc6-x32', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'locales', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'locales-all', 'pkgver': '2.34-0ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'nscd', 'pkgver': '2.34-0ubuntu3.2'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-source / libc-bin / libc-dev-bin / libc-devtools / libc6 / etc');
}
