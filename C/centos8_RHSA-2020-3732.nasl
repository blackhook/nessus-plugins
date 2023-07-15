##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:3732. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145871);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2019-2911",
    "CVE-2019-2914",
    "CVE-2019-2938",
    "CVE-2019-2946",
    "CVE-2019-2957",
    "CVE-2019-2960",
    "CVE-2019-2963",
    "CVE-2019-2966",
    "CVE-2019-2967",
    "CVE-2019-2968",
    "CVE-2019-2974",
    "CVE-2019-2982",
    "CVE-2019-2991",
    "CVE-2019-2993",
    "CVE-2019-2997",
    "CVE-2019-2998",
    "CVE-2019-3004",
    "CVE-2019-3009",
    "CVE-2019-3011",
    "CVE-2019-3018",
    "CVE-2020-2570",
    "CVE-2020-2573",
    "CVE-2020-2574",
    "CVE-2020-2577",
    "CVE-2020-2579",
    "CVE-2020-2580",
    "CVE-2020-2584",
    "CVE-2020-2588",
    "CVE-2020-2589",
    "CVE-2020-2627",
    "CVE-2020-2660",
    "CVE-2020-2679",
    "CVE-2020-2686",
    "CVE-2020-2694",
    "CVE-2020-2752",
    "CVE-2020-2759",
    "CVE-2020-2760",
    "CVE-2020-2761",
    "CVE-2020-2762",
    "CVE-2020-2763",
    "CVE-2020-2765",
    "CVE-2020-2770",
    "CVE-2020-2774",
    "CVE-2020-2779",
    "CVE-2020-2780",
    "CVE-2020-2804",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-2853",
    "CVE-2020-2892",
    "CVE-2020-2893",
    "CVE-2020-2895",
    "CVE-2020-2896",
    "CVE-2020-2897",
    "CVE-2020-2898",
    "CVE-2020-2901",
    "CVE-2020-2903",
    "CVE-2020-2904",
    "CVE-2020-2921",
    "CVE-2020-2922",
    "CVE-2020-2923",
    "CVE-2020-2924",
    "CVE-2020-2925",
    "CVE-2020-2926",
    "CVE-2020-2928",
    "CVE-2020-2930",
    "CVE-2020-14539",
    "CVE-2020-14540",
    "CVE-2020-14547",
    "CVE-2020-14550",
    "CVE-2020-14553",
    "CVE-2020-14559",
    "CVE-2020-14567",
    "CVE-2020-14568",
    "CVE-2020-14575",
    "CVE-2020-14576",
    "CVE-2020-14586",
    "CVE-2020-14597",
    "CVE-2020-14614",
    "CVE-2020-14619",
    "CVE-2020-14620",
    "CVE-2020-14623",
    "CVE-2020-14624",
    "CVE-2020-14631",
    "CVE-2020-14632",
    "CVE-2020-14633",
    "CVE-2020-14634",
    "CVE-2020-14641",
    "CVE-2020-14643",
    "CVE-2020-14651",
    "CVE-2020-14654",
    "CVE-2020-14656",
    "CVE-2020-14663",
    "CVE-2020-14678",
    "CVE-2020-14680",
    "CVE-2020-14697",
    "CVE-2020-14702",
    "CVE-2020-14725",
    "CVE-2020-14799"
  );
  script_xref(name:"RHSA", value:"2020:3732");

  script_name(english:"CentOS 8 : mysql:8.0 (CESA-2020:3732)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:3732 advisory.

  - mysql: Information Schema unspecified vulnerability (CPU Oct 2019) (CVE-2019-2911)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2019) (CVE-2019-2914,
    CVE-2019-2957)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2019) (CVE-2019-2938, CVE-2019-2963, CVE-2019-2968,
    CVE-2019-3018)

  - mysql: Server: PS unspecified vulnerability (CPU Oct 2019) (CVE-2019-2946)

  - mysql: Server: Replication unspecified vulnerability (CPU Oct 2019) (CVE-2019-2960)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2019) (CVE-2019-2966, CVE-2019-2967,
    CVE-2019-2974, CVE-2019-2982, CVE-2019-2991, CVE-2019-2998)

  - mysql: Server: C API unspecified vulnerability (CPU Oct 2019) (CVE-2019-2993, CVE-2019-3011)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct 2019) (CVE-2019-2997)

  - mysql: Server: Parser unspecified vulnerability (CPU Oct 2019) (CVE-2019-3004)

  - mysql: Server: Connection unspecified vulnerability (CPU Oct 2019) (CVE-2019-3009)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2020) (CVE-2020-14539, CVE-2020-14547,
    CVE-2020-14597, CVE-2020-14614, CVE-2020-14654, CVE-2020-14680, CVE-2020-14725)

  - mysql: Server: DML unspecified vulnerability (CPU Jul 2020) (CVE-2020-14540, CVE-2020-14575,
    CVE-2020-14620)

  - mysql: C API unspecified vulnerability (CPU Jul 2020) (CVE-2020-14550)

  - mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2020) (CVE-2020-14553)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Jul 2020) (CVE-2020-14559)

  - mysql: Server: Replication unspecified vulnerability (CPU Jul 2020) (CVE-2020-14567)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2020) (CVE-2020-14568, CVE-2020-14623, CVE-2020-14633,
    CVE-2020-14634)

  - mysql: Server: UDF unspecified vulnerability (CPU Jul 2020) (CVE-2020-14576)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2020) (CVE-2020-14586,
    CVE-2020-14663, CVE-2020-14678, CVE-2020-14697, CVE-2020-14702)

  - mysql: Server: Parser unspecified vulnerability (CPU Jul 2020) (CVE-2020-14619)

  - mysql: Server: JSON unspecified vulnerability (CPU Jul 2020) (CVE-2020-14624)

  - mysql: Server: Security: Audit unspecified vulnerability (CPU Jul 2020) (CVE-2020-14631)

  - mysql: Server: Options unspecified vulnerability (CPU Jul 2020) (CVE-2020-14632)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Jul 2020) (CVE-2020-14641, CVE-2020-14643,
    CVE-2020-14651)

  - mysql: Server: Locking unspecified vulnerability (CPU Jul 2020) (CVE-2020-14656)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2020) (CVE-2020-14799)

  - mysql: C API unspecified vulnerability (CPU Jan 2020) (CVE-2020-2570, CVE-2020-2573, CVE-2020-2574)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2020) (CVE-2020-2577, CVE-2020-2589)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2020) (CVE-2020-2579, CVE-2020-2660,
    CVE-2020-2679, CVE-2020-2686)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2020) (CVE-2020-2580)

  - mysql: Server: Options unspecified vulnerability (CPU Jan 2020) (CVE-2020-2584)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2020) (CVE-2020-2588)

  - mysql: Server: Parser unspecified vulnerability (CPU Jan 2020) (CVE-2020-2627)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Jan 2020) (CVE-2020-2694)

  - mysql: C API unspecified vulnerability (CPU Apr 2020) (CVE-2020-2752, CVE-2020-2922)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2020) (CVE-2020-2759, CVE-2020-2763)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2020) (CVE-2020-2760, CVE-2020-2762, CVE-2020-2814,
    CVE-2020-2893, CVE-2020-2895)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2020) (CVE-2020-2761,
    CVE-2020-2774, CVE-2020-2779, CVE-2020-2853)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2020) (CVE-2020-2765, CVE-2020-2892,
    CVE-2020-2897, CVE-2020-2901, CVE-2020-2904, CVE-2020-2923, CVE-2020-2924, CVE-2020-2928)

  - mysql: Server: Logging unspecified vulnerability (CPU Apr 2020) (CVE-2020-2770)

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2020) (CVE-2020-2780)

  - mysql: Server: Memcached unspecified vulnerability (CPU Apr 2020) (CVE-2020-2804)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Apr 2020) (CVE-2020-2812)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Apr 2020) (CVE-2020-2896)

  - mysql: Server: Charsets unspecified vulnerability (CPU Apr 2020) (CVE-2020-2898)

  - mysql: Server: Connection Handling unspecified vulnerability (CPU Apr 2020) (CVE-2020-2903)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2020) (CVE-2020-2921)

  - mysql: Server: PS unspecified vulnerability (CPU Apr 2020) (CVE-2020-2925)

  - mysql: Server: Group Replication GCS unspecified vulnerability (CPU Apr 2020) (CVE-2020-2926)

  - mysql: Server: Parser unspecified vulnerability (CPU Apr 2020) (CVE-2020-2930)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2021) (CVE-2021-1998, CVE-2021-2016,
    CVE-2021-2020)

  - mysql: C API unspecified vulnerability (CPU Jan 2021) (CVE-2021-2006, CVE-2021-2007)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Jan 2021) (CVE-2021-2009)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2021) (CVE-2021-2012,
    CVE-2021-2019)

  - mysql: Server: Parser unspecified vulnerability (CPU Apr 2021) (CVE-2021-2144)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2021) (CVE-2021-2160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3732");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var appstreams = {
    'mysql:8.0': [
      {'reference':'mecab-0.996-1.module_el8.0.0+41+ca30bab6.9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-0.996-1.module_el8.0.0+41+ca30bab6.9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.21-1.module_el8.2.0+493+63b41e36', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
