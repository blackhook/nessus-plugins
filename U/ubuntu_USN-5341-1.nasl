#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5341-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159138);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2017-17122", "CVE-2021-3487", "CVE-2021-45078");
  script_xref(name:"USN", value:"5341-1");

  script_name(english:"Ubuntu 16.04 LTS : GNU binutils vulnerabilities (USN-5341-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5341-1 advisory.

  - The dump_relocs_in_section function in objdump.c in GNU Binutils 2.29.1 does not check for reloc count
    integer overflows, which allows remote attackers to cause a denial of service (excessive memory
    allocation, or heap-based buffer overflow and application crash) or possibly have unspecified other impact
    via a crafted PE file. (CVE-2017-17122)

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

  - stab_xcoff_builtin_type in stabs.c in GNU Binutils through 2.37 allows attackers to cause a denial of
    service (heap-based buffer overflow) or possibly have unspecified other impact, as demonstrated by an out-
    of-bounds write. NOTE: this issue exists because of an incorrect fix for CVE-2018-12699. (CVE-2021-45078)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5341-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabihf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsel-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-sh4-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'binutils', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-mips-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-mips64-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-mips64el-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-mipsel-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'},
    {'osver': '16.04', 'pkgname': 'binutils-source', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-aarch64-linux-gnu / binutils-alpha-linux-gnu / etc');
}
