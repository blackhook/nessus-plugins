#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0233. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132504);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-5044", "CVE-2015-5276");
  script_bugtraq_id(68870);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : gcc Multiple Vulnerabilities (NS-SA-2019-0233)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has gcc packages installed that are affected by
multiple vulnerabilities:

  - Multiple integer overflows in libgfortran might allow
    remote attackers to execute arbitrary code or cause a
    denial of service (Fortran application crash) via
    vectors related to array allocation. (CVE-2014-5044)

  - The std::random_device class in libstdc++ in the GNU
    Compiler Collection (aka GCC) before 4.9.4 does not
    properly handle short reads from blocking sources, which
    makes it easier for context-dependent attackers to
    predict the random values via unspecified vectors.
    (CVE-2015-5276)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0233");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL gcc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "cpp-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-base-debuginfo-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-c++-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-debuginfo-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-gfortran-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-gnat-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-objc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-objc++-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-plugin-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libasan-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libasan-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libatomic-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libatomic-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgcc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgfortran-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgfortran-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgnat-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgnat-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgnat-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgomp-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libitm-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libitm-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libitm-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libmudflap-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libmudflap-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libmudflap-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libobjc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libquadmath-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libquadmath-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libquadmath-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-docs-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libtsan-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libtsan-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1"
  ],
  "CGSL MAIN 5.05": [
    "cpp-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-base-debuginfo-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-c++-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-debuginfo-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-gfortran-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-gnat-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-objc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-objc++-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "gcc-plugin-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libasan-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libasan-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libatomic-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libatomic-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgcc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgfortran-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgfortran-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgnat-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgnat-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgnat-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libgomp-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libitm-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libitm-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libitm-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libmudflap-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libmudflap-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libmudflap-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libobjc-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libquadmath-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libquadmath-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libquadmath-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-devel-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-docs-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libstdc++-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libtsan-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1",
    "libtsan-static-4.8.5-36.el7_6.2.cgslv5_5.0.1.g2b256a1"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc");
}
