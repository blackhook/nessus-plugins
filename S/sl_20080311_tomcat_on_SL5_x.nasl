#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60371);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-5342", "CVE-2007-5461");

  script_name(english:"Scientific Linux Security Update : tomcat on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A directory traversal vulnerability existed in the Apache Tomcat
webdav servlet. In some configurations it allowed remote authenticated
users to read files accessible to the local tomcat process.
(CVE-2007-5461)

The default security policy in the JULI logging component did not
restrict access permissions to files. This could be misused by
untrusted web applications to access and write arbitrary files in the
context of the tomcat process. (CVE-2007-5342)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0803&L=scientific-linux-errata&T=0&P=1946
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd4f68a7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"tomcat5-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-common-lib-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-server-lib-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-webapps-5.5.23-0jpp.3.0.3.el5_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
