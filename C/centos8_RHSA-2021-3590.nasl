#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:3590. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153519);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-14672",
    "CVE-2020-14765",
    "CVE-2020-14769",
    "CVE-2020-14773",
    "CVE-2020-14775",
    "CVE-2020-14776",
    "CVE-2020-14777",
    "CVE-2020-14785",
    "CVE-2020-14786",
    "CVE-2020-14789",
    "CVE-2020-14790",
    "CVE-2020-14791",
    "CVE-2020-14793",
    "CVE-2020-14794",
    "CVE-2020-14800",
    "CVE-2020-14804",
    "CVE-2020-14809",
    "CVE-2020-14812",
    "CVE-2020-14814",
    "CVE-2020-14821",
    "CVE-2020-14828",
    "CVE-2020-14829",
    "CVE-2020-14830",
    "CVE-2020-14836",
    "CVE-2020-14837",
    "CVE-2020-14838",
    "CVE-2020-14839",
    "CVE-2020-14844",
    "CVE-2020-14845",
    "CVE-2020-14846",
    "CVE-2020-14848",
    "CVE-2020-14852",
    "CVE-2020-14860",
    "CVE-2020-14861",
    "CVE-2020-14866",
    "CVE-2020-14867",
    "CVE-2020-14868",
    "CVE-2020-14870",
    "CVE-2020-14873",
    "CVE-2020-14888",
    "CVE-2020-14891",
    "CVE-2020-14893",
    "CVE-2021-2001",
    "CVE-2021-2002",
    "CVE-2021-2010",
    "CVE-2021-2011",
    "CVE-2021-2021",
    "CVE-2021-2022",
    "CVE-2021-2024",
    "CVE-2021-2028",
    "CVE-2021-2030",
    "CVE-2021-2031",
    "CVE-2021-2032",
    "CVE-2021-2036",
    "CVE-2021-2038",
    "CVE-2021-2042",
    "CVE-2021-2046",
    "CVE-2021-2048",
    "CVE-2021-2055",
    "CVE-2021-2056",
    "CVE-2021-2058",
    "CVE-2021-2060",
    "CVE-2021-2061",
    "CVE-2021-2065",
    "CVE-2021-2070",
    "CVE-2021-2072",
    "CVE-2021-2076",
    "CVE-2021-2081",
    "CVE-2021-2087",
    "CVE-2021-2088",
    "CVE-2021-2122",
    "CVE-2021-2146",
    "CVE-2021-2164",
    "CVE-2021-2166",
    "CVE-2021-2169",
    "CVE-2021-2170",
    "CVE-2021-2171",
    "CVE-2021-2172",
    "CVE-2021-2174",
    "CVE-2021-2178",
    "CVE-2021-2179",
    "CVE-2021-2180",
    "CVE-2021-2193",
    "CVE-2021-2194",
    "CVE-2021-2196",
    "CVE-2021-2201",
    "CVE-2021-2202",
    "CVE-2021-2203",
    "CVE-2021-2208",
    "CVE-2021-2212",
    "CVE-2021-2213",
    "CVE-2021-2215",
    "CVE-2021-2217",
    "CVE-2021-2226",
    "CVE-2021-2230",
    "CVE-2021-2232",
    "CVE-2021-2278",
    "CVE-2021-2293",
    "CVE-2021-2298",
    "CVE-2021-2299",
    "CVE-2021-2300",
    "CVE-2021-2301",
    "CVE-2021-2304",
    "CVE-2021-2305",
    "CVE-2021-2307",
    "CVE-2021-2308",
    "CVE-2021-2339",
    "CVE-2021-2340",
    "CVE-2021-2342",
    "CVE-2021-2352",
    "CVE-2021-2354",
    "CVE-2021-2356",
    "CVE-2021-2357",
    "CVE-2021-2367",
    "CVE-2021-2370",
    "CVE-2021-2372",
    "CVE-2021-2374",
    "CVE-2021-2383",
    "CVE-2021-2384",
    "CVE-2021-2385",
    "CVE-2021-2387",
    "CVE-2021-2389",
    "CVE-2021-2390",
    "CVE-2021-2399",
    "CVE-2021-2402",
    "CVE-2021-2410",
    "CVE-2021-2412",
    "CVE-2021-2417",
    "CVE-2021-2418",
    "CVE-2021-2422",
    "CVE-2021-2424",
    "CVE-2021-2425",
    "CVE-2021-2426",
    "CVE-2021-2427",
    "CVE-2021-2429",
    "CVE-2021-2437",
    "CVE-2021-2440",
    "CVE-2021-2441",
    "CVE-2021-2444"
  );
  script_xref(name:"RHSA", value:"2021:3590");
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 8 : mysql:8.0 (CESA-2021:3590)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:3590 advisory.

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2020) (CVE-2020-14672)

  - mysql: Server: FTS unspecified vulnerability (CPU Oct 2020) (CVE-2020-14765, CVE-2020-14789,
    CVE-2020-14804)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2020) (CVE-2020-14769, CVE-2020-14773,
    CVE-2020-14777, CVE-2020-14785, CVE-2020-14793, CVE-2020-14794, CVE-2020-14809, CVE-2020-14830,
    CVE-2020-14836, CVE-2020-14837, CVE-2020-14839, CVE-2020-14845, CVE-2020-14846, CVE-2020-14861,
    CVE-2020-14866, CVE-2020-14868, CVE-2020-14888, CVE-2020-14891, CVE-2020-14893)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2020) (CVE-2020-14775, CVE-2020-14776, CVE-2020-14791,
    CVE-2020-14821, CVE-2020-14829, CVE-2020-14848)

  - mysql: Server: PS unspecified vulnerability (CPU Oct 2020) (CVE-2020-14786, CVE-2020-14790,
    CVE-2020-14844)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2020) (CVE-2020-14800)

  - mysql: Server: Locking unspecified vulnerability (CPU Oct 2020) (CVE-2020-14812)

  - mysql: Server: DML unspecified vulnerability (CPU Oct 2020) (CVE-2020-14814, CVE-2020-14828)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2020) (CVE-2020-14838)

  - mysql: Server: Charsets unspecified vulnerability (CPU Oct 2020) (CVE-2020-14852)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Oct 2020) (CVE-2020-14860)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct 2020) (CVE-2020-14867)

  - mysql: Server: X Plugin unspecified vulnerability (CPU Oct 2020) (CVE-2020-14870)

  - mysql: Server: Logging unspecified vulnerability (CPU Oct 2020) (CVE-2020-14873)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2021) (CVE-2021-2001, CVE-2021-2021,
    CVE-2021-2024, CVE-2021-2030, CVE-2021-2031, CVE-2021-2036, CVE-2021-2055, CVE-2021-2060, CVE-2021-2065,
    CVE-2021-2070, CVE-2021-2076)

  - mysql: Server: Replication unspecified vulnerability (CPU Jan 2021) (CVE-2021-2002)

  - mysql: C API unspecified vulnerability (CPU Jan 2021) (CVE-2021-2010, CVE-2021-2011)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2021) (CVE-2021-2022, CVE-2021-2028, CVE-2021-2042,
    CVE-2021-2048)

  - mysql: Information Schema unspecified vulnerability (CPU Jan 2021) (CVE-2021-2032)

  - mysql: Server: Components Services unspecified vulnerability (CPU Jan 2021) (CVE-2021-2038)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jan 2021) (CVE-2021-2046, CVE-2021-2072,
    CVE-2021-2081)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2021) (CVE-2021-2056, CVE-2021-2087, CVE-2021-2088)

  - mysql: Server: Locking unspecified vulnerability (CPU Jan 2021) (CVE-2021-2058)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2021) (CVE-2021-2061, CVE-2021-2122)

  - mysql: Server: Options unspecified vulnerability (CPU Apr 2021) (CVE-2021-2146)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2021) (CVE-2021-2164, CVE-2021-2169,
    CVE-2021-2170, CVE-2021-2193, CVE-2021-2203, CVE-2021-2212, CVE-2021-2213, CVE-2021-2230, CVE-2021-2278,
    CVE-2021-2298, CVE-2021-2299)

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2021) (CVE-2021-2166, CVE-2021-2172, CVE-2021-2196,
    CVE-2021-2300, CVE-2021-2305)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2021) (CVE-2021-2171, CVE-2021-2178,
    CVE-2021-2202)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2021) (CVE-2021-2174, CVE-2021-2180, CVE-2021-2194)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2021) (CVE-2021-2179,
    CVE-2021-2232)

  - mysql: Server: Partition unspecified vulnerability (CPU Apr 2021) (CVE-2021-2201, CVE-2021-2208)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Apr 2021) (CVE-2021-2215, CVE-2021-2217,
    CVE-2021-2293, CVE-2021-2304)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Apr 2021) (CVE-2021-2226, CVE-2021-2301,
    CVE-2021-2308)

  - mysql: Server: Packaging unspecified vulnerability (CPU Apr 2021) (CVE-2021-2307)

  - mysql: Server: DDL unspecified vulnerability (CPU Jul 2021) (CVE-2021-2339, CVE-2021-2352, CVE-2021-2399)

  - mysql: Server: Memcached unspecified vulnerability (CPU Jul 2021) (CVE-2021-2340)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2021) (CVE-2021-2342, CVE-2021-2357,
    CVE-2021-2367, CVE-2021-2383, CVE-2021-2384, CVE-2021-2387, CVE-2021-2410, CVE-2021-2412, CVE-2021-2418,
    CVE-2021-2425, CVE-2021-2426, CVE-2021-2427, CVE-2021-2437, CVE-2021-2441, CVE-2021-2444)

  - mysql: Server: Federated unspecified vulnerability (CPU Jul 2021) (CVE-2021-2354)

  - mysql: Server: Replication unspecified vulnerability (CPU Jul 2021) (CVE-2021-2356, CVE-2021-2385)

  - mysql: Server: DML unspecified vulnerability (CPU Jul 2021) (CVE-2021-2370, CVE-2021-2440)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2021) (CVE-2021-2372, CVE-2021-2374, CVE-2021-2389,
    CVE-2021-2390, CVE-2021-2429)

  - mysql: Server: Locking unspecified vulnerability (CPU Jul 2021) (CVE-2021-2402)

  - mysql: Server: GIS unspecified vulnerability (CPU Jul 2021) (CVE-2021-2417)

  - mysql: Server: PS unspecified vulnerability (CPU Jul 2021) (CVE-2021-2422)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jul 2021) (CVE-2021-2424)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3590");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2417");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'mecab-0.996-1.module_el8.0.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mecab-0.996-1.module_el8.0.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.0.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.0.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.0.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.0.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-common-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-common-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-devel-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-devel-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-errmsg-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-errmsg-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-libs-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-libs-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-server-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-server-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-test-8.0.26-1.module_el8.4.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql-test-8.0.26-1.module_el8.4.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-ipadic / mecab-ipadic-EUCJP / mysql / mysql-common / etc');
}
