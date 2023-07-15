#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101438);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-6816",
    "CVE-2016-8745"
  );

  script_name(english:"Virtuozzo 6 : tomcat6 / tomcat6-admin-webapps / etc (VZLSA-2017-0527)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for tomcat6 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

Security Fix(es) :

* It was discovered that the code that parsed the HTTP request line
permitted invalid characters. This could be exploited, in conjunction
with a proxy that also permitted the invalid characters but with a
different interpretation, to inject data into the HTTP response. By
manipulating the HTTP response the attacker could poison a web-cache,
perform an XSS attack, or obtain sensitive information from requests
other then their own. (CVE-2016-6816)

Note: This fix causes Tomcat to respond with an HTTP 400 Bad Request
error when request contains characters that are not permitted by the
HTTP specification to appear not encoded, even though they were
previously accepted. The newly introduced system property
tomcat.util.http.parser.HttpParser.requestTargetAllow can be used to
configure Tomcat to accept curly braces ({ and }) and the pipe symbol
(|) in not encoded form, as these are often used in URLs without being
properly encoded.

* A bug was discovered in the error handling of the send file code for
the NIO HTTP connector. This led to the current Processor object being
added to the Processor cache multiple times allowing information
leakage between requests including, and not limited to, session ID and
the response body. (CVE-2016-8745)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0527.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9920be2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0527");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat6 / tomcat6-admin-webapps / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["tomcat6-6.0.24-105.vl6",
        "tomcat6-admin-webapps-6.0.24-105.vl6",
        "tomcat6-docs-webapp-6.0.24-105.vl6",
        "tomcat6-el-2.1-api-6.0.24-105.vl6",
        "tomcat6-javadoc-6.0.24-105.vl6",
        "tomcat6-jsp-2.1-api-6.0.24-105.vl6",
        "tomcat6-lib-6.0.24-105.vl6",
        "tomcat6-servlet-2.5-api-6.0.24-105.vl6",
        "tomcat6-webapps-6.0.24-105.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / etc");
}
