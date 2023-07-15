#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5124-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154413);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-16592", "CVE-2021-3487");
  script_xref(name:"USN", value:"5124-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : GNU binutils vulnerabilities (USN-5124-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5124-1 advisory.

  - A use after free issue exists in the Binary File Descriptor (BFD) library (aka libbfd) in GNU Binutils
    2.34 in bfd_hash_lookup, as demonstrated in nm-new, that can cause a denial of service via a crafted file.
    (CVE-2020-16592)

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5124-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3487");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabihf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-for-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-for-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-i686-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-i686-kfreebsd-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-i686-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsel-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa32r6-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa32r6el-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsisa64r6el-linux-gnuabin32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-riscv64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-sh4-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-kfreebsd-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-x86-64-linux-gnux32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbinutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libctf0");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'binutils', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-common', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-dev', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-for-build', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-for-host', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-i686-kfreebsd-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mips-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mips64-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mips64-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mips64el-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mips64el-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsel-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa32r6-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa32r6el-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6el-linux-gnuabi64', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-mipsisa64r6el-linux-gnuabin32', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-source', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-x86-64-kfreebsd-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '18.04', 'pkgname': 'libbinutils', 'pkgver': '2.30-21ubuntu1~18.04.7'},
    {'osver': '20.04', 'pkgname': 'binutils', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-common', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-dev', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-for-build', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-for-host', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-i686-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-i686-kfreebsd-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-i686-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-riscv64-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-source', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-x86-64-kfreebsd-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-x86-64-linux-gnu', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'binutils-x86-64-linux-gnux32', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libbinutils', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libctf-nobfd0', 'pkgver': '2.34-6ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libctf0', 'pkgver': '2.34-6ubuntu1.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-aarch64-linux-gnu / binutils-alpha-linux-gnu / etc');
}
