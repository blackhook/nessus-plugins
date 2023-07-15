#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2020:4682.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157665);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2018-18624",
    "CVE-2019-19499",
    "CVE-2020-11110",
    "CVE-2020-12052",
    "CVE-2020-12245",
    "CVE-2020-12458",
    "CVE-2020-12459",
    "CVE-2020-13430"
  );
  script_xref(name:"ALSA", value:"2020:4682");

  script_name(english:"AlmaLinux 8 : grafana (ALSA-2020:4682)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2020:4682 advisory.

  - Grafana 5.3.1 has XSS via a column style on the Dashboard > Table Panel screen. NOTE: this issue exists
    because of an incomplete fix for CVE-2018-12099. (CVE-2018-18624)

  - Grafana <= 6.4.3 has an Arbitrary File Read vulnerability, which could be exploited by an authenticated
    attacker that has privileges to modify the data source configurations. (CVE-2019-19499)

  - Grafana through 6.7.1 allows stored XSS due to insufficient input protection in the originalUrl field,
    which allows an attacker to inject JavaScript code that will be executed after clicking on Open Original
    Dashboard after visiting the snapshot. (CVE-2020-11110)

  - Grafana version < 6.7.3 is vulnerable for annotation popup XSS. (CVE-2020-12052)

  - Grafana before 6.7.3 allows table-panel XSS via column.title or cellLinkTooltip. (CVE-2020-12245)

  - An information-disclosure flaw was found in Grafana through 6.7.3. The database directory /var/lib/grafana
    and database file /var/lib/grafana/grafana.db are world readable. This can result in exposure of sensitive
    information (e.g., cleartext or encrypted datasource passwords). (CVE-2020-12458)

  - In certain Red Hat packages for Grafana 6.x through 6.3.6, the configuration files
    /etc/grafana/grafana.ini and /etc/grafana/ldap.toml (which contain a secret_key and a bind_password) are
    world readable. (CVE-2020-12459)

  - Grafana before 7.0.0 allows tag value XSS via the OpenTSDB datasource. (CVE-2020-13430)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2020-4682.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13430");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19499");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-azure-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-cloudwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-loki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-opentsdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-postgres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:grafana-stackdriver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'grafana-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-azure-monitor-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-cloudwatch-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-elasticsearch-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-graphite-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-influxdb-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-loki-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-mssql-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-mysql-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-opentsdb-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-postgres-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-prometheus-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grafana-stackdriver-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana / grafana-azure-monitor / grafana-cloudwatch / etc');
}
