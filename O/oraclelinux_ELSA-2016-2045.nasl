#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2045 and 
# Oracle Linux Security Advisory ELSA-2016-2045 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93947);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-5388", "CVE-2016-6325");
  script_xref(name:"RHSA", value:"2016:2045");

  script_name(english:"Oracle Linux 6 : tomcat6 (ELSA-2016-2045) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2045 :

An update for tomcat6 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

Security Fix(es) :

* It was discovered that the Tomcat packages installed certain
configuration files read by the Tomcat initialization script as
writeable to the tomcat group. A member of the group or a malicious
web application deployed on Tomcat could use this flaw to escalate
their privileges. (CVE-2016-6325)

* It was found that several Tomcat session persistence mechanisms
could allow a remote, authenticated user to bypass intended
SecurityManager restrictions and execute arbitrary code in a
privileged context via a web application that placed a crafted object
in a session. (CVE-2016-0714)

* It was discovered that tomcat used the value of the Proxy header
from HTTP requests to initialize the HTTP_PROXY environment variable
for CGI scripts, which in turn was incorrectly used by certain HTTP
client implementations to configure the proxy for outgoing HTTP
requests. A remote attacker could possibly use this flaw to redirect
HTTP requests performed by a CGI script to an attacker-controlled
proxy via a malicious HTTP request. (CVE-2016-5388)

* A directory traversal flaw was found in Tomcat's RequestUtil.java. A
remote, authenticated user could use this flaw to bypass intended
SecurityManager restrictions and list a parent directory via a '/..'
in a pathname used by a web application in a getResource,
getResourceAsStream, or getResourcePaths call, as demonstrated by the
$CATALINA_BASE/webapps directory. (CVE-2015-5174)

* It was found that Tomcat could reveal the presence of a directory
even when that directory was protected by a security constraint. A
user could make a request to a directory via a URL not ending with a
slash and, depending on whether Tomcat redirected that request, could
confirm whether that directory existed. (CVE-2015-5345)

* It was found that Tomcat allowed the StatusManagerServlet to be
loaded by a web application when a security manager was configured.
This allowed a web application to list all deployed web applications
and expose sensitive information such as session IDs. (CVE-2016-0706)

Red Hat would like to thank Scott Geary (VendHQ) for reporting
CVE-2016-5388. The CVE-2016-6325 issue was discovered by Red Hat
Product Security.

Bug Fix(es) :

* Due to a bug in the tomcat6 spec file, the catalina.out file's
md5sum, size, and mtime attributes were compared to the file's
attributes at installation time. Because these attributes change after
the service is started, the 'rpm -V' command previously failed. With
this update, the attributes mentioned above are ignored in the RPM
verification and the catalina.out file now passes the verification
check. (BZ#1357123)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-October/006408.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"tomcat6-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-admin-webapps-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-docs-webapp-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-el-2.1-api-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-javadoc-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-jsp-2.1-api-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-lib-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-servlet-2.5-api-6.0.24-98.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-webapps-6.0.24-98.el6_8")) flag++;


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
