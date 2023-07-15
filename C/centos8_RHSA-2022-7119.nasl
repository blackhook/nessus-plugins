#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2022:7119. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166460);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2021-2478",
    "CVE-2021-2479",
    "CVE-2021-2481",
    "CVE-2021-35546",
    "CVE-2021-35575",
    "CVE-2021-35577",
    "CVE-2021-35591",
    "CVE-2021-35596",
    "CVE-2021-35597",
    "CVE-2021-35602",
    "CVE-2021-35604",
    "CVE-2021-35607",
    "CVE-2021-35608",
    "CVE-2021-35610",
    "CVE-2021-35612",
    "CVE-2021-35622",
    "CVE-2021-35623",
    "CVE-2021-35624",
    "CVE-2021-35625",
    "CVE-2021-35626",
    "CVE-2021-35627",
    "CVE-2021-35628",
    "CVE-2021-35630",
    "CVE-2021-35631",
    "CVE-2021-35632",
    "CVE-2021-35633",
    "CVE-2021-35634",
    "CVE-2021-35635",
    "CVE-2021-35636",
    "CVE-2021-35637",
    "CVE-2021-35638",
    "CVE-2021-35639",
    "CVE-2021-35640",
    "CVE-2021-35641",
    "CVE-2021-35642",
    "CVE-2021-35643",
    "CVE-2021-35644",
    "CVE-2021-35645",
    "CVE-2021-35646",
    "CVE-2021-35647",
    "CVE-2021-35648",
    "CVE-2022-21245",
    "CVE-2022-21249",
    "CVE-2022-21253",
    "CVE-2022-21254",
    "CVE-2022-21256",
    "CVE-2022-21264",
    "CVE-2022-21265",
    "CVE-2022-21270",
    "CVE-2022-21278",
    "CVE-2022-21297",
    "CVE-2022-21301",
    "CVE-2022-21302",
    "CVE-2022-21303",
    "CVE-2022-21304",
    "CVE-2022-21339",
    "CVE-2022-21342",
    "CVE-2022-21344",
    "CVE-2022-21348",
    "CVE-2022-21351",
    "CVE-2022-21352",
    "CVE-2022-21358",
    "CVE-2022-21362",
    "CVE-2022-21367",
    "CVE-2022-21368",
    "CVE-2022-21370",
    "CVE-2022-21372",
    "CVE-2022-21374",
    "CVE-2022-21378",
    "CVE-2022-21379",
    "CVE-2022-21412",
    "CVE-2022-21413",
    "CVE-2022-21414",
    "CVE-2022-21415",
    "CVE-2022-21417",
    "CVE-2022-21418",
    "CVE-2022-21423",
    "CVE-2022-21425",
    "CVE-2022-21427",
    "CVE-2022-21435",
    "CVE-2022-21436",
    "CVE-2022-21437",
    "CVE-2022-21438",
    "CVE-2022-21440",
    "CVE-2022-21444",
    "CVE-2022-21451",
    "CVE-2022-21452",
    "CVE-2022-21454",
    "CVE-2022-21455",
    "CVE-2022-21457",
    "CVE-2022-21459",
    "CVE-2022-21460",
    "CVE-2022-21462",
    "CVE-2022-21478",
    "CVE-2022-21479",
    "CVE-2022-21509",
    "CVE-2022-21515",
    "CVE-2022-21517",
    "CVE-2022-21522",
    "CVE-2022-21525",
    "CVE-2022-21526",
    "CVE-2022-21527",
    "CVE-2022-21528",
    "CVE-2022-21529",
    "CVE-2022-21530",
    "CVE-2022-21531",
    "CVE-2022-21534",
    "CVE-2022-21537",
    "CVE-2022-21538",
    "CVE-2022-21539",
    "CVE-2022-21547",
    "CVE-2022-21553",
    "CVE-2022-21556",
    "CVE-2022-21569",
    "CVE-2022-21592",
    "CVE-2022-21595",
    "CVE-2022-21600",
    "CVE-2022-21605",
    "CVE-2022-21607",
    "CVE-2022-21635",
    "CVE-2022-21638",
    "CVE-2022-21641"
  );
  script_xref(name:"RHSA", value:"2022:7119");

  script_name(english:"CentOS 8 : mysql:8.0 (CESA-2022:7119)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2022:7119 advisory.

  - mysql: Server: DML unspecified vulnerability (CPU Oct 2021) (CVE-2021-2478, CVE-2021-2479, CVE-2021-35591,
    CVE-2021-35607)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2021) (CVE-2021-2481, CVE-2021-35575,
    CVE-2021-35577, CVE-2021-35610, CVE-2021-35612, CVE-2021-35626, CVE-2021-35627, CVE-2021-35628,
    CVE-2021-35634, CVE-2021-35635, CVE-2021-35636, CVE-2021-35638, CVE-2021-35641, CVE-2021-35642,
    CVE-2021-35643, CVE-2021-35644, CVE-2021-35645, CVE-2021-35646, CVE-2021-35647)

  - mysql: Server: Replication unspecified vulnerability (CPU Oct 2021) (CVE-2021-35546)

  - mysql: Server: Error Handling unspecified vulnerability (CPU Oct 2021) (CVE-2021-35596)

  - mysql: C API unspecified vulnerability (CPU Oct 2021) (CVE-2021-35597)

  - mysql: Server: Options unspecified vulnerability (CPU Oct 2021) (CVE-2021-35602, CVE-2021-35630)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2021) (CVE-2021-35604)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Oct 2021) (CVE-2021-35608)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2021) (CVE-2021-35622)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Oct 2021) (CVE-2021-35623)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2021) (CVE-2021-35624,
    CVE-2021-35625)

  - mysql: Server: GIS unspecified vulnerability (CPU Oct 2021) (CVE-2021-35631)

  - mysql: Server: Data Dictionary unspecified vulnerability (CPU Oct 2021) (CVE-2021-35632)

  - mysql: Server: Logging unspecified vulnerability (CPU Oct 2021) (CVE-2021-35633)

  - mysql: Server: PS unspecified vulnerability (CPU Oct 2021) (CVE-2021-35637)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2021) (CVE-2021-35639)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct 2021) (CVE-2021-35640)

  - mysql: Server: FTS unspecified vulnerability (CPU Oct 2021) (CVE-2021-35648)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2022) (CVE-2022-21245)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2022) (CVE-2022-21249)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2022) (CVE-2022-21253, CVE-2022-21254,
    CVE-2022-21264, CVE-2022-21265, CVE-2022-21278, CVE-2022-21297, CVE-2022-21339, CVE-2022-21342,
    CVE-2022-21351, CVE-2022-21370, CVE-2022-21378)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Jan 2022) (CVE-2022-21256,
    CVE-2022-21379)

  - mysql: Server: Federated unspecified vulnerability (CPU Jan 2022) (CVE-2022-21270)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2022) (CVE-2022-21301)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2022) (CVE-2022-21302, CVE-2022-21348, CVE-2022-21352)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jan 2022) (CVE-2022-21303)

  - mysql: Server: Parser unspecified vulnerability (CPU Jan 2022) (CVE-2022-21304)

  - mysql: Server: Replication unspecified vulnerability (CPU Jan 2022) (CVE-2022-21344)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2022) (CVE-2022-21358,
    CVE-2022-21372)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Jan 2022) (CVE-2022-21362,
    CVE-2022-21374)

  - mysql: Server: Compiling unspecified vulnerability (CPU Jan 2022) (CVE-2022-21367)

  - mysql: Server: Components Services unspecified vulnerability (CPU Jan 2022) (CVE-2022-21368)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2022) (CVE-2022-21412, CVE-2022-21414,
    CVE-2022-21435, CVE-2022-21436, CVE-2022-21437, CVE-2022-21438, CVE-2022-21440, CVE-2022-21452,
    CVE-2022-21459, CVE-2022-21462, CVE-2022-21478, CVE-2022-21479)

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2022) (CVE-2022-21413)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2022) (CVE-2022-21415)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2022) (CVE-2022-21417, CVE-2022-21418, CVE-2022-21423,
    CVE-2022-21451)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr 2022) (CVE-2022-21425, CVE-2022-21444)

  - mysql: Server: FTS unspecified vulnerability (CPU Apr 2022) (CVE-2022-21427)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2022) (CVE-2022-21454)

  - mysql: Server: PAM Auth Plugin unspecified vulnerability (CPU Jul 2022) (CVE-2022-21455)

  - mysql: Server: PAM Auth Plugin unspecified vulnerability (CPU Apr 2022) (CVE-2022-21457)

  - mysql: Server: Logging unspecified vulnerability (CPU Apr 2022) (CVE-2022-21460)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2022) (CVE-2022-21509, CVE-2022-21525,
    CVE-2022-21526, CVE-2022-21527, CVE-2022-21528, CVE-2022-21529, CVE-2022-21530, CVE-2022-21531,
    CVE-2022-21553, CVE-2022-21556, CVE-2022-21569)

  - mysql: Server: Options unspecified vulnerability (CPU Jul 2022) (CVE-2022-21515)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2022) (CVE-2022-21517, CVE-2022-21537, CVE-2022-21539)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jul 2022) (CVE-2022-21522, CVE-2022-21534)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Jul 2022) (CVE-2022-21538)

  - mysql: Server: Federated unspecified vulnerability (CPU Jul 2022) (CVE-2022-21547)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2022) (CVE-2022-21592)

  - mysql: C API unspecified vulnerability (CPU Oct 2022) (CVE-2022-21595)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21600, CVE-2022-21607,
    CVE-2022-21638, CVE-2022-21641)

  - mysql: Server: Data Dictionary unspecified vulnerability (CPU Oct 2022) (CVE-2022-21605)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21635)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21866, CVE-2023-21872)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:7119");
  script_set_attribute(attribute:"solution", value:
"Update the affected mecab-ipadic and / or mecab-ipadic-EUCJP packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.0.0+41+ca30bab6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab-ipadic / mecab-ipadic-EUCJP');
}
