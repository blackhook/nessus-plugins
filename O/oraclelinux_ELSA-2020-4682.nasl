##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4682.
##

include('compat.inc');

if (description)
{
  script_id(142792);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

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

  script_name(english:"Oracle Linux 8 : grafana (ELSA-2020-4682)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4682 advisory.

  - An information-disclosure flaw was found in Grafana through 6.7.3. The database directory /var/lib/grafana
    and database file /var/lib/grafana/grafana.db are world readable. This can result in exposure of sensitive
    information (e.g., cleartext or encrypted datasource passwords). (CVE-2020-12458)

  - Grafana before 6.7.3 allows table-panel XSS via column.title or cellLinkTooltip. (CVE-2020-12245)

  - Grafana <= 6.4.3 has an Arbitrary File Read vulnerability, which could be exploited by an authenticated
    attacker that has privileges to modify the data source configurations. (CVE-2019-19499)

  - Grafana before 7.0.0 allows tag value XSS via the OpenTSDB datasource. (CVE-2020-13430)

  - Grafana 5.3.1 has XSS via a column style on the Dashboard > Table Panel screen. NOTE: this issue exists
    because of an incomplete fix for CVE-2018-12099. (CVE-2018-18624)

  - Grafana through 6.7.1 allows stored XSS due to insufficient input protection in the originalUrl field,
    which allows an attacker to inject JavaScript code that will be executed after clicking on Open Original
    Dashboard after visiting the snapshot. (CVE-2020-11110)

  - Grafana version < 6.7.3 is vulnerable for annotation popup XSS. (CVE-2020-12052)

  - In certain Red Hat packages for Grafana 6.x through 6.3.6, the configuration files
    /etc/grafana/grafana.ini and /etc/grafana/ldap.toml (which contain a secret_key and a bind_password) are
    world readable. (CVE-2020-12459)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4682.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13430");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19499");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-azure-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-cloudwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-loki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-opentsdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-postgres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grafana-stackdriver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'grafana-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-azure-monitor-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-azure-monitor-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-cloudwatch-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-cloudwatch-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-elasticsearch-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-elasticsearch-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-graphite-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-graphite-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-influxdb-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-influxdb-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-loki-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-loki-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-mssql-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-mssql-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-mysql-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-mysql-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-opentsdb-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-opentsdb-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-postgres-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-postgres-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-prometheus-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-prometheus-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'grafana-stackdriver-6.7.4-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'grafana-stackdriver-6.7.4-3.el8', 'cpu':'x86_64', 'release':'8'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana / grafana-azure-monitor / grafana-cloudwatch / etc');
}