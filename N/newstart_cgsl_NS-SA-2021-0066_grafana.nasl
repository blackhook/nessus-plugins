##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0066. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147708);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

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

  script_name(english:"NewStart CGSL MAIN 6.02 : grafana Multiple Vulnerabilities (NS-SA-2021-0066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has grafana packages installed that are affected by multiple
vulnerabilities:

  - An information-disclosure flaw was found in Grafana through 6.7.3. The database directory /var/lib/grafana
    and database file /var/lib/grafana/grafana.db are world readable. This can result in exposure of sensitive
    information (e.g., cleartext or encrypted datasource passwords). (CVE-2020-12458)

  - In certain Red Hat packages for Grafana 6.x through 6.3.6, the configuration files
    /etc/grafana/grafana.ini and /etc/grafana/ldap.toml (which contain a secret_key and a bind_password) are
    world readable. (CVE-2020-12459)

  - Grafana version < 6.7.3 is vulnerable for annotation popup XSS. (CVE-2020-12052)

  - Grafana before 7.0.0 allows tag value XSS via the OpenTSDB datasource. (CVE-2020-13430)

  - Grafana 5.3.1 has XSS via a column style on the Dashboard > Table Panel screen. NOTE: this issue exists
    because of an incomplete fix for CVE-2018-12099. (CVE-2018-18624)

  - Grafana before 6.7.3 allows table-panel XSS via column.title or cellLinkTooltip. (CVE-2020-12245)

  - Grafana through 6.7.1 allows stored XSS due to insufficient input protection in the originalUrl field,
    which allows an attacker to inject JavaScript code that will be executed after clicking on Open Original
    Dashboard after visiting the snapshot. (CVE-2020-11110)

  - Grafana <= 6.4.3 has an Arbitrary File Read vulnerability, which could be exploited by an authenticated
    attacker that has privileges to modify the data source configurations. (CVE-2019-19499)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0066");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL grafana packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13430");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19499");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'grafana-6.7.4-3.el8',
    'grafana-azure-monitor-6.7.4-3.el8',
    'grafana-cloudwatch-6.7.4-3.el8',
    'grafana-debuginfo-6.7.4-3.el8',
    'grafana-elasticsearch-6.7.4-3.el8',
    'grafana-graphite-6.7.4-3.el8',
    'grafana-influxdb-6.7.4-3.el8',
    'grafana-loki-6.7.4-3.el8',
    'grafana-mssql-6.7.4-3.el8',
    'grafana-mysql-6.7.4-3.el8',
    'grafana-opentsdb-6.7.4-3.el8',
    'grafana-postgres-6.7.4-3.el8',
    'grafana-prometheus-6.7.4-3.el8',
    'grafana-stackdriver-6.7.4-3.el8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana');
}
