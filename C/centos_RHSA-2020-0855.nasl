#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:0855 and 
# CentOS Errata and Security Advisory 2020:0855 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134906);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2020-1938");
  script_xref(name:"RHSA", value:"2020:0855");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"CentOS 7 : tomcat (CESA-2020:0855)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:0855 advisory.

  - tomcat: Apache Tomcat AJP File Read/Inclusion
    Vulnerability (CVE-2020-1938)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-March/035669.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aba2486");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-lib-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.76-11.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-webapps-7.0.76-11.el7_7")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
