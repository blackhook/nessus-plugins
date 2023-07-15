##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0019. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160739);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2014-5044", "CVE-2015-5276");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : gcc Multiple Vulnerabilities (NS-SA-2022-0019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has gcc packages installed that are affected by
multiple vulnerabilities:

  - Multiple integer overflows in libgfortran might allow remote attackers to execute arbitrary code or cause
    a denial of service (Fortran application crash) via vectors related to array allocation. (CVE-2014-5044)

  - The std::random_device class in libstdc++ in the GNU Compiler Collection (aka GCC) before 4.9.4 does not
    properly handle short reads from blocking sources, which makes it easier for context-dependent attackers
    to predict the random values via unspecified vectors. (CVE-2015-5276)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0019");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-5044");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2015-5276");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL gcc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'cpp-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-base-debuginfo-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-c++-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-debuginfo-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-gfortran-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-gnat-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-go-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-objc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-objc++-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-plugin-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libasan-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libasan-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libatomic-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libatomic-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgcc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgfortran-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgfortran-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgnat-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgnat-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgnat-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgo-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgo-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgo-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgomp-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libitm-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libitm-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libitm-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libmudflap-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libmudflap-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libmudflap-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libobjc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libquadmath-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libquadmath-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libquadmath-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-docs-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libtsan-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libtsan-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e'
  ],
  'CGSL MAIN 5.04': [
    'cpp-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-base-debuginfo-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-c++-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-debuginfo-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-gfortran-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-gnat-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-go-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-objc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-objc++-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'gcc-plugin-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libasan-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libasan-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libatomic-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libatomic-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgcc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgfortran-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgfortran-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgnat-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgnat-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgnat-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgo-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgo-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgo-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libgomp-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libitm-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libitm-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libitm-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libmudflap-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libmudflap-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libmudflap-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libobjc-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libquadmath-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libquadmath-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libquadmath-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-devel-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-docs-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libstdc++-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libtsan-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e',
    'libtsan-static-4.8.5-28.el7_5.1.cgslv5_4.0.1.g26ce34e'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gcc');
}
