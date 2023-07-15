#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-777.
#

include('compat.inc');

if (description)
{
  script_id(95897);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2016-6816", "CVE-2016-8735");
  script_xref(name:"ALAS", value:"2016-777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Amazon Linux AMI : tomcat7 (ALAS-2016-777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"CVE-2016-6816 tomcat: HTTP Request smuggling vulnerability due to
permitting invalid character in HTTP requests

CVE-2016-8735 tomcat: Remote code execution vulnerability in
JmxRemoteLifecycleListener");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2016-777.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update tomcat7' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"tomcat7-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-admin-webapps-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-docs-webapp-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-el-2.2-api-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-javadoc-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-jsp-2.2-api-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-lib-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-log4j-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-servlet-3.0-api-7.0.73-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-webapps-7.0.73-1.23.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat7 / tomcat7-admin-webapps / tomcat7-docs-webapp / etc");
}
