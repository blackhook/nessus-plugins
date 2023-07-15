##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:3708. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145609);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2019-2510",
    "CVE-2019-2537",
    "CVE-2019-2614",
    "CVE-2019-2627",
    "CVE-2019-2628",
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2758",
    "CVE-2019-2805",
    "CVE-2020-2922"
  );
  script_bugtraq_id(
    106619,
    106627,
    107924,
    107927,
    109243,
    109247
  );
  script_xref(name:"RHSA", value:"2019:3708");

  script_name(english:"CentOS 8 : mariadb:10.3 (CESA-2019:3708)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:3708 advisory.

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2019) (CVE-2019-2510)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2019) (CVE-2019-2537)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2019) (CVE-2019-2614)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2019) (CVE-2019-2627)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2019) (CVE-2019-2628)

  - mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2019) (CVE-2019-2737)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2019) (CVE-2019-2739)

  - mysql: Server: XML unspecified vulnerability (CPU Jul 2019) (CVE-2019-2740)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2019) (CVE-2019-2758)

  - mysql: Server: Parser unspecified vulnerability (CPU Jul 2019) (CVE-2019-2805)

  - mysql: C API unspecified vulnerability (CPU Apr 2020) (CVE-2020-2922)

  - mysql: C API unspecified vulnerability (CPU Jan 2021) (CVE-2021-2007)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3708");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var module_ver = get_kb_item('Host/RedHat/appstream/mariadb-devel');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb-devel:10.3');
if ('10.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mariadb-devel:' + module_ver);

var appstreams = {
    'mariadb-devel:10.3': [
      {'reference':'galera-25.3.26-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.3.17-1.module_el8.1.0+217+4d875839', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb-devel:10.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'galera / mariadb / mariadb-backup / mariadb-common / mariadb-devel / etc');
}
