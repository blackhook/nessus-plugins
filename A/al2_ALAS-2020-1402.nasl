#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1402.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134569);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id(
    "CVE-2018-1304",
    "CVE-2018-1305",
    "CVE-2018-8014",
    "CVE-2018-8034",
    "CVE-2020-1938"
  );
  script_xref(name:"ALAS", value:"2020-1402");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Amazon Linux 2 : tomcat (ALAS-2020-1402)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The host name verification when using TLS with the WebSocket client
was missing. It is now enabled by default. Versions Affected: Apache
Tomcat 9.0.0.M1 to 9.0.9, 8.5.0 to 8.5.31, 8.0.0.RC1 to 8.0.52, and
7.0.35 to 7.0.88. (CVE-2018-8034)

The URL pattern of '' (the empty string) which exactly maps to the
context root was not correctly handled in Apache Tomcat 9.0.0.M1 to
9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 when
used as part of a security constraint definition. This caused the
constraint to be ignored. It was, therefore, possible for unauthorised
users to gain access to web application resources that should have
been protected. Only security constraints with a URL pattern of the
empty string were affected. (CVE-2018-1304)

Security constraints defined by annotations of Servlets in Apache
Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and
7.0.0 to 7.0.84 were only applied once a Servlet had been loaded.
Because security constraints defined in this way apply to the URL
pattern and any URLs below that point, it was possible - depending on
the order Servlets were loaded - for some security constraints not to
be applied. This could have exposed resources to users who were not
authorised to access them. (CVE-2018-1305)

The defaults settings for the CORS filter provided in Apache Tomcat
9.0.0.M1 to 9.0.8, 8.5.0 to 8.5.31, 8.0.0.RC1 to 8.0.52, 7.0.41 to
7.0.88 are insecure and enable 'supportsCredentials' for all origins.
It is expected that users of the CORS filter will have configured it
appropriately for their environment rather than using it in the
default configuration. Therefore, it is expected that most users will
not be impacted by this issue. (CVE-2018-8014)

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

AL2 tomcat8.5 :

before :

tcp6 0 0 :::8009 :::* LISTEN 25772/java

tcp6 0 0 :::8080 :::* LISTEN 25772/java

tcp6 0 0 127.0.0.1:8005 :::* LISTEN 25772/java

After :

tcp6 0 0 :::8080 :::* LISTEN 25772/java

tcp6 0 0 127.0.0.1:8005 :::* LISTEN 25772/java

To re-enable the AJP port in Tomcat, users can follow the steps 
below :

1) For AL2 Core (tomcat7): Uncomment the following line in
/etc/tomcat/server.xml and restart the service

<!--

<Connector port='8009' protocol='AJP/1.3' redirectPort='8443' />

-->

2) For AL2 Tomcat8.5 extra: Uncomment the following line in
/etc/tomcat/server.xml and restart the service

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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1402.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update tomcat' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"tomcat-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-admin-webapps-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-docs-webapp-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-el-2.2-api-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-javadoc-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-jsp-2.2-api-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-jsvc-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-lib-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-servlet-3.0-api-7.0.76-10.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tomcat-webapps-7.0.76-10.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
