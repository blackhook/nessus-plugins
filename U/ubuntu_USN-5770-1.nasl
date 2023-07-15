#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5770-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168518);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2017-11671");
  script_xref(name:"USN", value:"5770-1");

  script_name(english:"Ubuntu 16.04 ESM : GCC vulnerability (USN-5770-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by a vulnerability as referenced in the
USN-5770-1 advisory.

  - Under certain circumstances, the ix86_expand_builtin function in i386.c in GNU Compiler Collection (GCC)
    version 4.6, 4.7, 4.8, 4.9, 5 before 5.5, and 6 before 6.4 will generate instruction sequences that
    clobber the status flag of the RDRAND and RDSEED intrinsics before it can be read, potentially causing
    failures of these instructions to go unreported. This could potentially lead to less randomness in random
    number generation. (CVE-2017-11671)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5770-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cpp-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fixincludes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g++-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:g++-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-5-test-results");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcc-6-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gccgo-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gccgo-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gccgo-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gccgo-6-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-5-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-5-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-5-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-5-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gcj-5-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gdc-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gdc-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gfortran-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gfortran-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnat-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnat-5-sjlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gobjc++-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gobjc++-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gobjc-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gobjc-5-multilib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32asan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32atomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32cilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32gcc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32gcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32gfortran-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32gfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32go7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32go9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32gomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32itm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32lsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32mpx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32objc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32objc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32phobos-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32quadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32stdc++-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32stdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32ubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64asan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64atomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64cilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64gcc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64gcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64gfortran-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64gfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64go7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64go9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64gomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64itm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64mpx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64objc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64objc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64phobos-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64quadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64stdc++-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64stdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib64ubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libasan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcc1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgccjit-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgccjit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj16-awt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgcj16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgfortran-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnat-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnatprj5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnatprj5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnatvsn5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnatvsn5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgo7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgo9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmpx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libobjc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphobos-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfasan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfgcc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfgcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfgfortran-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfgfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfobjc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfphobos-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfstdc++-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsfubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++-5-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32asan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32atomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32cilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32gcc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32gcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32gfortran-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32gfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32go7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32go9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32gomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32itm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32lsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32objc-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32objc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32phobos-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32quadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32stdc++-5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32stdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx32ubsan0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'osver': '16.04', 'pkgname': 'cpp-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'fixincludes', 'pkgver': '1:5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'g++-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'g++-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5-base', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5-locales', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5-plugin-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5-source', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-5-test-results', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcc-6-base', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'gccgo-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gccgo-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gccgo-6', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'gccgo-6-multilib', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'gcj-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcj-5-jdk', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcj-5-jre', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcj-5-jre-headless', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcj-5-jre-lib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gcj-5-source', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gdc-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gdc-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gfortran-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gfortran-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gnat-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gnat-5-sjlj', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gobjc++-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gobjc++-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gobjc-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'gobjc-5-multilib', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32asan2', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32atomic1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32cilkrts5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32gcc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32gcc1', 'pkgver': '1:6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32gfortran-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32gfortran3', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32go7', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32go9', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib32gomp1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32itm1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32lsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32mpx0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32objc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32objc4', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32phobos-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32quadmath0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32stdc++-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32stdc++6', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib32ubsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64asan2', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64atomic1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64cilkrts5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64gcc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64gcc1', 'pkgver': '1:6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib64gfortran-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64gfortran3', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64go7', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64go9', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'lib64gomp1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64itm1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64mpx0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64objc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64objc4', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64phobos-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64quadmath0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64stdc++-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64stdc++6', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'lib64ubsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libasan2', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libatomic1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libcc1-0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libcilkrts5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgcc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgcc1', 'pkgver': '1:6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libgccjit-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgccjit0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgcj16', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgcj16-awt', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgcj16-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgfortran-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgfortran3', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgnat-5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgnatprj5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgnatprj5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgnatvsn5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgnatvsn5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgo7', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libgo9', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libgomp1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libitm1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'liblsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libmpx0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libobjc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libobjc4', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libphobos-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libquadmath0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfasan2', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfatomic1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfgcc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfgcc1', 'pkgver': '1:6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libsfgfortran-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfgfortran3', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfgomp1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfobjc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfobjc4', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfphobos-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfstdc++-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfstdc++6', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libsfubsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libstdc++-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libstdc++-5-pic', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libstdc++6', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libtsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libubsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32asan2', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32atomic1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32cilkrts5', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32gcc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32gcc1', 'pkgver': '1:6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32gfortran-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32gfortran3', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32go7', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32go9', 'pkgver': '6.0.1-0ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libx32gomp1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32itm1', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32lsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32objc-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32objc4', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32phobos-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32quadmath0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32stdc++-5-dev', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32stdc++6', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'},
    {'osver': '16.04', 'pkgname': 'libx32ubsan0', 'pkgver': '5.4.0-6ubuntu1~16.04.12+esm2'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp-5 / fixincludes / g++-5 / g++-5-multilib / gcc-5 / gcc-5-base / etc');
}
