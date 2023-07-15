##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5448-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161634);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2017-10684",
    "CVE-2017-10685",
    "CVE-2017-11112",
    "CVE-2017-11113",
    "CVE-2017-13728",
    "CVE-2017-13729",
    "CVE-2017-13730",
    "CVE-2017-13731",
    "CVE-2017-13732",
    "CVE-2017-13733",
    "CVE-2017-13734"
  );
  script_xref(name:"USN", value:"5448-1");

  script_name(english:"Ubuntu 16.04 ESM : ncurses vulnerabilities (USN-5448-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5448-1 advisory.

  - In ncurses 6.0, there is a stack-based buffer overflow in the fmt_entry function. A crafted input will
    lead to a remote arbitrary code execution attack. (CVE-2017-10684)

  - In ncurses 6.0, there is a format string vulnerability in the fmt_entry function. A crafted input will
    lead to a remote arbitrary code execution attack. (CVE-2017-10685)

  - In ncurses 6.0, there is an attempted 0xffffffffffffffff access in the append_acs function of
    tinfo/parse_entry.c. It could lead to a remote denial of service attack if the terminfo library code is
    used to process untrusted terminfo data. (CVE-2017-11112)

  - In ncurses 6.0, there is a NULL Pointer Dereference in the _nc_parse_entry function of
    tinfo/parse_entry.c. It could lead to a remote denial of service attack if the terminfo library code is
    used to process untrusted terminfo data. (CVE-2017-11113)

  - There is an infinite loop in the next_char function in comp_scan.c in ncurses 6.0, related to libtic. A
    crafted input will lead to a remote denial of service attack. (CVE-2017-13728)

  - There is an illegal address access in the _nc_save_str function in alloc_entry.c in ncurses 6.0. It will
    lead to a remote denial of service attack. (CVE-2017-13729)

  - There is an illegal address access in the function _nc_read_entry_source() in progs/tic.c in ncurses 6.0
    that might lead to a remote denial of service attack. (CVE-2017-13730)

  - There is an illegal address access in the function postprocess_termcap() in parse_entry.c in ncurses 6.0
    that will lead to a remote denial of service attack. (CVE-2017-13731)

  - There is an illegal address access in the function dump_uses() in progs/dump_entry.c in ncurses 6.0 that
    might lead to a remote denial of service attack. (CVE-2017-13732)

  - There is an illegal address access in the fmt_entry function in progs/dump_entry.c in ncurses 6.0 that
    might lead to a remote denial of service attack. (CVE-2017-13733)

  - There is an illegal address access in the _nc_safe_strcat function in strings.c in ncurses 6.0 that will
    lead to a remote denial of service attack. (CVE-2017-13734)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5448-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32tinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32tinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64tinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32tinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32tinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ncurses-term");
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
    {'osver': '16.04', 'pkgname': 'lib32ncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32ncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32ncursesw5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32ncursesw5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32tinfo-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32tinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib64ncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib64ncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib64tinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libncursesw5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libncursesw5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libtinfo-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libtinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32ncurses5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32ncurses5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32ncursesw5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32ncursesw5-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32tinfo-dev', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32tinfo5', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'ncurses-base', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'ncurses-bin', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'ncurses-examples', 'pkgver': '6.0+20160213-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'ncurses-term', 'pkgver': '6.0+20160213-1ubuntu1+esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lib32ncurses5 / lib32ncurses5-dev / lib32ncursesw5 / etc');
}
