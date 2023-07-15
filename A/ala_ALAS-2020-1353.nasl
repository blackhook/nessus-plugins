#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1353.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134575);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938");
  script_xref(name:"ALAS", value:"2020-1353");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Amazon Linux AMI : tomcat8 (ALAS-2020-1353)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to
7.0.99 the HTTP header parsing code used an approach to end-of-line
parsing that allowed some invalid HTTP headers to be parsed as valid.
This led to a possibility of HTTP Request Smuggling if Tomcat was
located behind a reverse proxy that incorrectly handled the invalid
Transfer-Encoding header in a particular manner. Such a reverse proxy
is considered unlikely. (CVE-2020-1935)

The refactoring present in Apache Tomcat 9.0.28 to 9.0.30, 8.5.48 to
8.5.50 and 7.0.98 to 7.0.99 introduced a regression. The result of the
regression was that invalid Transfer-Encoding headers were incorrectly
processed leading to a possibility of HTTP Request Smuggling if Tomcat
was located behind a reverse proxy that incorrectly handled the
invalid Transfer-Encoding header in a particular manner. Such a
reverse proxy is considered unlikely. (CVE-2019-17569)

When using the Apache JServ Protocol (AJP), care must be taken when
trusting incoming connections to Apache Tomcat. Tomcat treats AJP
connections as having higher trust than, for example, a similar HTTP
connection. If such connections are available to an attacker, they can
be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1
to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with
an AJP Connector enabled by default that listened on all configured IP
addresses. It was expected (and recommended in the security guide)
that this Connector would be disabled if not required. This
vulnerability report identified a mechanism that allowed: - returning
arbitrary files from anywhere in the web application - processing any
file in the web application as a JSP Further, if the web application
allowed file upload and stored those files within the web application
(or the attacker was able to control the content of the web
application by some other means) then this, along with the ability to
process a file as a JSP, made remote code execution possible. It is
important to note that mitigation is only required if an AJP port is
accessible to untrusted users. Users wishing to take a
defence-in-depth approach and block the vector that permits returning
arbitrary files and execution as JSP may upgrade to Apache Tomcat
9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to
the default AJP Connector configuration in 9.0.31 to harden the
default configuration. It is likely that users upgrading to 9.0.31,
8.5.51 or 7.0.100 or later will need to make small changes to their
configurations. (CVE-2020-1938)

As part of our fix for this CVE, we are disabling Tomcat 2019 AJP
connector in the default configuration in alignment with the upstream
changes. This change will require customers who use the default Tomcat
configuration (in which the AJP connector was previously enabled) to
explicitly re-enable the connector if they need it. Also take note
that a connector configured without an explicit address will only bind
to the loopback address.

Examples of output from netstat before and after updating tomcat8 and
tomcat7 are below (note that it is the same on AL1 and AL2 with both
tomcat7 and tomcat8).

AL1 tomcat7 :

before :

tcp6 0 0 :::8009 :::* LISTEN 25772/java

tcp6 0 0 :::8080 :::* LISTEN 25772/java

tcp6 0 0 127.0.0.1:8005 :::* LISTEN 25772/java

After :

tcp6 0 0 :::8080 :::* LISTEN 25772/java

tcp6 0 0 127.0.0.1:8005 :::* LISTEN 25772/java

To re-enable the AJP port in Tomcat for AL1, users can uncomment the
following line in /etc/tomcat{TOMCAT_VERSION}/server.xml and restart
the service :

<!--

<Connector protocol='AJP/1.3'

address='::1'

port='8009'

redirectPort='8443' />

-->

See also :

Apache Tomcat release notes

Tomcat 7

<a
href='http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_
8.5.51'>Tomcat 8

RedHat <a href='https://access.redhat.com/solutions/4851251'>solutions");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?177285c3");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1353.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update tomcat8' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");

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

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"tomcat8-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-admin-webapps-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-docs-webapp-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-el-3.0-api-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-javadoc-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-jsp-2.3-api-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-lib-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-log4j-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-servlet-3.1-api-8.5.51-1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-webapps-8.5.51-1.83.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat8 / tomcat8-admin-webapps / tomcat8-docs-webapp / etc");
}
