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
  script_id(95863);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763", "CVE-2016-3092");

  script_name(english:"Scientific Linux Security Update : tomcat on SL7.x (noarch) (20161103)");
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
"The following packages have been upgraded to a newer upstream version:
tomcat (7.0.69).

Security Fix(es) :

  - A CSRF flaw was found in Tomcat's the index pages for
    the Manager and Host Manager applications. These
    applications included a valid CSRF token when issuing a
    redirect as a result of an unauthenticated request to
    the root of the web application. This token could then
    be used by an attacker to perform a CSRF attack.
    (CVE-2015-5351)

  - It was found that several Tomcat session persistence
    mechanisms could allow a remote, authenticated user to
    bypass intended SecurityManager restrictions and execute
    arbitrary code in a privileged context via a web
    application that placed a crafted object in a session.
    (CVE-2016-0714)

  - A security manager bypass flaw was found in Tomcat that
    could allow remote, authenticated users to access
    arbitrary application data, potentially resulting in a
    denial of service. (CVE-2016-0763)

  - A denial of service vulnerability was identified in
    Commons FileUpload that occurred when the length of the
    multipart boundary was just below the size of the buffer
    (4096 bytes) used to read the uploaded file if the
    boundary was the typical tens of bytes long.
    (CVE-2016-3092)

  - A directory traversal flaw was found in Tomcat's
    RequestUtil.java. A remote, authenticated user could use
    this flaw to bypass intended SecurityManager
    restrictions and list a parent directory via a '/..' in
    a pathname used by a web application in a getResource,
    getResourceAsStream, or getResourcePaths call.
    (CVE-2015-5174)

  - It was found that Tomcat could reveal the presence of a
    directory even when that directory was protected by a
    security constraint. A user could make a request to a
    directory via a URL not ending with a slash and,
    depending on whether Tomcat redirected that request,
    could confirm whether that directory existed.
    (CVE-2015-5345)

  - It was found that Tomcat allowed the
    StatusManagerServlet to be loaded by a web application
    when a security manager was configured. This allowed a
    web application to list all deployed web applications
    and expose sensitive information such as session IDs.
    (CVE-2016-0706)

Additional Changes :"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=3481
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?379ee337"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", reference:"tomcat-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-admin-webapps-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-docs-webapp-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-el-2.2-api-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-javadoc-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsp-2.2-api-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsvc-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-lib-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-servlet-3.0-api-7.0.69-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-webapps-7.0.69-10.el7")) flag++;


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
