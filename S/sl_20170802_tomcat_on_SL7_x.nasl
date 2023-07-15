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
  script_id(102664);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797");

  script_name(english:"Scientific Linux Security Update : tomcat on SL7.x (noarch) (20170802)");
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
"The following packages have been upgraded to a later upstream version:
tomcat (7.0.76).

Security Fix(es) :

  - The Realm implementations did not process the supplied
    password if the supplied user name did not exist. This
    made a timing attack possible to determine valid user
    names. Note that the default configuration includes the
    LockOutRealm which makes exploitation of this
    vulnerability harder. (CVE-2016-0762)

  - It was discovered that a malicious web application could
    bypass a configured SecurityManager via a Tomcat utility
    method that was accessible to web applications.
    (CVE-2016-5018)

  - It was discovered that when a SecurityManager was
    configured, Tomcat's system property replacement feature
    for configuration files could be used by a malicious web
    application to bypass the SecurityManager and read
    system properties that should not be visible.
    (CVE-2016-6794)

  - It was discovered that a malicious web application could
    bypass a configured SecurityManager via manipulation of
    the configuration parameters for the JSP Servlet.
    (CVE-2016-6796)

  - It was discovered that it was possible for a web
    application to access any global JNDI resource whether
    an explicit ResourceLink had been configured or not.
    (CVE-2016-6797)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=8410
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a41e7848"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", reference:"tomcat-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-admin-webapps-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-docs-webapp-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-el-2.2-api-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-javadoc-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsp-2.2-api-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsvc-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-lib-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-servlet-3.0-api-7.0.76-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-webapps-7.0.76-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
