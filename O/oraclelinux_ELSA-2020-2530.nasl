#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2530 and 
# Oracle Linux Security Advisory ELSA-2020-2530 respectively.
#

include('compat.inc');

if (description)
{
  script_id(137387);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9484");
  script_xref(name:"RHSA", value:"2020:2530");
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Linux 7 : tomcat (ELSA-2020-2530)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2020:2530 :

The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:2530 advisory.

  - tomcat: deserialization flaw in session persistence
    storage leading to RCE (CVE-2020-9484)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-June/010048.html");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-June/010050.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-lib-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.76-12.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-webapps-7.0.76-12.el7_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
