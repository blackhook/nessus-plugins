##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:2511. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145612);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2019-2420",
    "CVE-2019-2434",
    "CVE-2019-2436",
    "CVE-2019-2455",
    "CVE-2019-2481",
    "CVE-2019-2482",
    "CVE-2019-2486",
    "CVE-2019-2494",
    "CVE-2019-2495",
    "CVE-2019-2502",
    "CVE-2019-2503",
    "CVE-2019-2507",
    "CVE-2019-2510",
    "CVE-2019-2528",
    "CVE-2019-2529",
    "CVE-2019-2530",
    "CVE-2019-2531",
    "CVE-2019-2532",
    "CVE-2019-2533",
    "CVE-2019-2534",
    "CVE-2019-2535",
    "CVE-2019-2536",
    "CVE-2019-2537",
    "CVE-2019-2539",
    "CVE-2019-2580",
    "CVE-2019-2581",
    "CVE-2019-2584",
    "CVE-2019-2585",
    "CVE-2019-2587",
    "CVE-2019-2589",
    "CVE-2019-2592",
    "CVE-2019-2593",
    "CVE-2019-2596",
    "CVE-2019-2606",
    "CVE-2019-2607",
    "CVE-2019-2614",
    "CVE-2019-2617",
    "CVE-2019-2620",
    "CVE-2019-2623",
    "CVE-2019-2624",
    "CVE-2019-2625",
    "CVE-2019-2626",
    "CVE-2019-2627",
    "CVE-2019-2628",
    "CVE-2019-2630",
    "CVE-2019-2631",
    "CVE-2019-2634",
    "CVE-2019-2635",
    "CVE-2019-2636",
    "CVE-2019-2644",
    "CVE-2019-2681",
    "CVE-2019-2683",
    "CVE-2019-2685",
    "CVE-2019-2686",
    "CVE-2019-2687",
    "CVE-2019-2688",
    "CVE-2019-2689",
    "CVE-2019-2691",
    "CVE-2019-2693",
    "CVE-2019-2694",
    "CVE-2019-2695",
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2752",
    "CVE-2019-2755",
    "CVE-2019-2757",
    "CVE-2019-2758",
    "CVE-2019-2774",
    "CVE-2019-2778",
    "CVE-2019-2780",
    "CVE-2019-2784",
    "CVE-2019-2785",
    "CVE-2019-2789",
    "CVE-2019-2795",
    "CVE-2019-2796",
    "CVE-2019-2797",
    "CVE-2019-2798",
    "CVE-2019-2800",
    "CVE-2019-2801",
    "CVE-2019-2802",
    "CVE-2019-2803",
    "CVE-2019-2805",
    "CVE-2019-2808",
    "CVE-2019-2810",
    "CVE-2019-2811",
    "CVE-2019-2812",
    "CVE-2019-2814",
    "CVE-2019-2815",
    "CVE-2019-2819",
    "CVE-2019-2826",
    "CVE-2019-2830",
    "CVE-2019-2834",
    "CVE-2019-2879",
    "CVE-2019-2948",
    "CVE-2019-2950",
    "CVE-2019-2969",
    "CVE-2019-3003"
  );
  script_bugtraq_id(
    106619,
    106622,
    106625,
    106626,
    106627,
    106628,
    107913,
    107924,
    107927,
    107928,
    109243,
    109247,
    109259,
    109260
  );
  script_xref(name:"RHSA", value:"2019:2511");

  script_name(english:"CentOS 8 : mysql:8.0 (CESA-2019:2511)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:2511 advisory.

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2019) (CVE-2019-2420, CVE-2019-2481,
    CVE-2019-2507, CVE-2019-2529, CVE-2019-2530)

  - mysql: Server: Parser unspecified vulnerability (CPU Jan 2019) (CVE-2019-2434, CVE-2019-2455)

  - mysql: Server: Replication unspecified vulnerability (CPU Jan 2019) (CVE-2019-2436, CVE-2019-2531,
    CVE-2019-2534)

  - mysql: Server: PS unspecified vulnerability (CPU Jan 2019) (CVE-2019-2482)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2019) (CVE-2019-2486,
    CVE-2019-2532, CVE-2019-2533)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2019) (CVE-2019-2494, CVE-2019-2495, CVE-2019-2537)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2019) (CVE-2019-2502, CVE-2019-2510)

  - mysql: Server: Connection Handling unspecified vulnerability (CPU Jan 2019) (CVE-2019-2503)

  - mysql: Server: Partition unspecified vulnerability (CPU Jan 2019) (CVE-2019-2528)

  - mysql: Server: Options unspecified vulnerability (CPU Jan 2019) (CVE-2019-2535)

  - mysql: Server: Packaging unspecified vulnerability (CPU Jan 2019) (CVE-2019-2536)

  - mysql: Server: Connection unspecified vulnerability (CPU Jan 2019) (CVE-2019-2539)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2019) (CVE-2019-2580, CVE-2019-2585, CVE-2019-2593,
    CVE-2019-2624, CVE-2019-2628)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2019) (CVE-2019-2581, CVE-2019-2596,
    CVE-2019-2607, CVE-2019-2625, CVE-2019-2681, CVE-2019-2685, CVE-2019-2686, CVE-2019-2687, CVE-2019-2688,
    CVE-2019-2689, CVE-2019-2693, CVE-2019-2694, CVE-2019-2695)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2019) (CVE-2019-2584,
    CVE-2019-2589, CVE-2019-2606, CVE-2019-2620, CVE-2019-2627)

  - mysql: Server: Partition unspecified vulnerability (CPU Apr 2019) (CVE-2019-2587)

  - mysql: Server: PS unspecified vulnerability (CPU Apr 2019) (CVE-2019-2592)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2019) (CVE-2019-2614, CVE-2019-2617,
    CVE-2019-2630, CVE-2019-2634, CVE-2019-2635)

  - mysql: Server: Options unspecified vulnerability (CPU Apr 2019) (CVE-2019-2623, CVE-2019-2683)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr 2019) (CVE-2019-2626, CVE-2019-2644)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Apr 2019) (CVE-2019-2631)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2019) (CVE-2019-2636)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Apr 2019) (CVE-2019-2691)

  - mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2019) (CVE-2019-2737)

  - mysql: Server: Compiling unspecified vulnerability (CPU Jul 2019) (CVE-2019-2738)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2019) (CVE-2019-2739,
    CVE-2019-2778, CVE-2019-2789, CVE-2019-2811)

  - mysql: Server: XML unspecified vulnerability (CPU Jul 2019) (CVE-2019-2740)

  - mysql: Server: Options unspecified vulnerability (CPU Jul 2019) (CVE-2019-2752)

  - mysql: Server: Replication unspecified vulnerability (CPU Jul 2019) (CVE-2019-2755, CVE-2019-2800)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2019) (CVE-2019-2757, CVE-2019-2774,
    CVE-2019-2796, CVE-2019-2802, CVE-2019-2803, CVE-2019-2808, CVE-2019-2810, CVE-2019-2812, CVE-2019-2815,
    CVE-2019-2830, CVE-2019-2834)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2019) (CVE-2019-2758, CVE-2019-2785, CVE-2019-2798,
    CVE-2019-2814, CVE-2019-2879)

  - mysql: Server: Components / Services unspecified vulnerability (CPU Jul 2019) (CVE-2019-2780)

  - mysql: Server: DML unspecified vulnerability (CPU Jul 2019) (CVE-2019-2784)

  - mysql: Server: Charsets unspecified vulnerability (CPU Jul 2019) (CVE-2019-2795)

  - mysql: Client programs unspecified vulnerability (CPU Jul 2019) (CVE-2019-2797)

  - mysql: Server: FTS unspecified vulnerability (CPU Jul 2019) (CVE-2019-2801)

  - mysql: Server: Parser unspecified vulnerability (CPU Jul 2019) (CVE-2019-2805)

  - mysql: Server: Security: Audit unspecified vulnerability (CPU Jul 2019) (CVE-2019-2819)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Jul 2019) (CVE-2019-2826)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2019) (CVE-2019-2948, CVE-2019-2950)

  - mysql: Client programs unspecified vulnerability (CPU Oct 2019) (CVE-2019-2969)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2019) (CVE-2019-3003)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2511");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2819");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

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
      {'reference':'mysql-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.17-3.module_el8.0.0+181+899d6349', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
