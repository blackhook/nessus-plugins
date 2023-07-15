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
  script_id(66664);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1976");

  script_name(english:"Scientific Linux Security Update : tomcat5 on SL5.x i386/x86_64 (20130528)");
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
"A flaw was found in the way the tomcat5 init script handled the
catalina.out log file. A malicious web application deployed on Tomcat
could use this flaw to perform a symbolic link attack to change the
ownership of an arbitrary system file to that of the tomcat user,
allowing them to escalate their privileges to root. (CVE-2013-1976)

Note: With this update, /var/log/tomcat5/catalina.out has been moved
to the /var/log/tomcat5-initd.log file.

Tomcat must be restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1305&L=scientific-linux-errata&T=0&P=2291
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddc5e362"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"tomcat5-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-common-lib-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-debuginfo-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-server-lib-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-webapps-5.5.23-0jpp.40.el5_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat5 / tomcat5-admin-webapps / tomcat5-common-lib / etc");
}
