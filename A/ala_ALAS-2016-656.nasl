#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-656.
#

include("compat.inc");

if (description)
{
  script_id(89837);
  script_version("2.2");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2014-0230", "CVE-2014-7810");
  script_xref(name:"ALAS", value:"2016-656");

  script_name(english:"Amazon Linux AMI : tomcat6 (ALAS-2016-656)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the expression language resolver evaluated
expressions within a privileged code section. A malicious web
application could use this flaw to bypass security manager
protections. (CVE-2014-7810)

It was found that Tomcat would keep connections open after processing
requests with a large enough request body. A remote attacker could
potentially use this flaw to exhaust the pool of available connections
and preventing further, legitimate connections to the Tomcat server to
be made. (CVE-2014-0230)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-656.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tomcat6' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"tomcat6-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-admin-webapps-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-docs-webapp-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-el-2.1-api-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-javadoc-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-jsp-2.1-api-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-lib-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-servlet-2.5-api-6.0.44-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-webapps-6.0.44-1.3.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
}
