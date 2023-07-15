#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-972.
#

include("compat.inc");

if (description)
{
  script_id(108597);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/13 15:23:36");

  script_cve_id("CVE-2018-1304", "CVE-2018-1305");
  script_xref(name:"ALAS", value:"2018-972");

  script_name(english:"Amazon Linux AMI : tomcat7 / tomcat8 (ALAS-2018-972)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Late application of security constraints can lead to resource exposure
for unauthorised users :

Security constraints defined by annotations of Servlets in Apache
Tomcat were only applied once a Servlet had been loaded. Because
security constraints defined in this way apply to the URL pattern and
any URLs below that point, it was possible - depending on the order
Servlets were loaded - for some security constraints not to be
applied. This could have exposed resources to users who were not
authorised to access them. (CVE-2018-1305)

Incorrect handling of empty string URL in security constraints can
lead to unintended exposure of resources :

The URL pattern of '' (the empty string) which exactly maps to the
context root was not correctly handled in Apache Tomcat when used as
part of a security constraint definition. This caused the constraint
to be ignored. It was, therefore, possible for unauthorised users to
gain access to web application resources that should have been
protected. Only security constraints with a URL pattern of the empty
string were affected. (CVE-2018-1304)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-972.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update tomcat7' to update your system.

Run 'yum update tomcat8' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

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
if (rpm_check(release:"ALA", reference:"tomcat7-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-admin-webapps-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-docs-webapp-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-el-2.2-api-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-javadoc-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-jsp-2.2-api-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-lib-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-log4j-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-servlet-3.0-api-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-webapps-7.0.85-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-admin-webapps-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-docs-webapp-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-el-3.0-api-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-javadoc-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-jsp-2.3-api-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-lib-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-log4j-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-servlet-3.1-api-8.5.29-1.77.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-webapps-8.5.29-1.77.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat7 / tomcat7-admin-webapps / tomcat7-docs-webapp / etc");
}
