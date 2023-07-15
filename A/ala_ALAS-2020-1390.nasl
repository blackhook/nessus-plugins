#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1390.
#

include('compat.inc');

if (description)
{
  script_id(138061);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9484");
  script_xref(name:"ALAS", value:"2020-1390");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Amazon Linux AMI : tomcat8 (ALAS-2020-1390)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to
9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able
to control the contents and name of a file on the server; and b) the
server is configured to use the PersistenceManager with a FileStore;
and c) the PersistenceManager is configured with
sessionAttributeValueClassNameFilter='null' (the default unless a
SecurityManager is used) or a sufficiently lax filter to allow the
attacker provided object to be deserialized; and d) the attacker knows
the relative file path from the storage location used by FileStore to
the file the attacker has control over; then, using a specifically
crafted request, the attacker will be able to trigger remote code
execution via deserialization of the file under their control. Note
that all of conditions a) to d) must be true for the attack to
succeed. (CVE-2020-9484)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1390.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update tomcat8' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"tomcat8-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-admin-webapps-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-docs-webapp-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-el-3.0-api-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-javadoc-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-jsp-2.3-api-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-lib-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-log4j-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-servlet-3.1-api-8.5.56-1.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-webapps-8.5.56-1.84.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat8 / tomcat8-admin-webapps / tomcat8-docs-webapp / etc");
}
