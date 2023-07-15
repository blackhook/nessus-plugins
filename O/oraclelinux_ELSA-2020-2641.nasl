#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2641 and 
# Oracle Linux Security Advisory ELSA-2020-2641 respectively.
#

include('compat.inc');

if (description)
{
  script_id(137771);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-13379");
  script_xref(name:"RHSA", value:"2020:2641");

  script_name(english:"Oracle Linux 8 : grafana (ELSA-2020-2641)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2020:2641 :

The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:2641 advisory.

  - grafana: SSRF incorrect access control vulnerability
    allows unauthenticated users to make grafana send HTTP
    requests to any URL (CVE-2020-13379)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-June/010072.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-azure-monitor-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-cloudwatch-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-elasticsearch-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-graphite-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-influxdb-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-loki-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-mssql-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-mysql-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-opentsdb-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-postgres-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-prometheus-6.3.6-2.el8_2")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grafana-stackdriver-6.3.6-2.el8_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grafana / grafana-azure-monitor / grafana-cloudwatch / etc");
}
