#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1780 and 
# Oracle Linux Security Advisory ELSA-2011-1780 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68399);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");
  script_bugtraq_id(48456, 48667, 49353, 49762);
  script_xref(name:"RHSA", value:"2011:1780");

  script_name(english:"Oracle Linux 6 : tomcat6 (ELSA-2011-1780)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1780 :

Updated tomcat6 packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

APR (Apache Portable Runtime) as mentioned in the CVE-2011-3190 and
CVE-2011-2526 descriptions does not refer to APR provided by the apr
packages. It refers to the implementation of APR provided by the
Tomcat Native library, which provides support for using APR with
Tomcat. This library is not shipped with Red Hat Enterprise Linux 6.
This update includes fixes for users who have elected to use APR with
Tomcat by taking the Tomcat Native library from a different product.
Such a configuration is not supported by Red Hat, however.

Multiple flaws were found in the way Tomcat handled HTTP DIGEST
authentication. These flaws weakened the Tomcat HTTP DIGEST
authentication implementation, subjecting it to some of the weaknesses
of HTTP BASIC authentication, for example, allowing remote attackers
to perform session replay attacks. (CVE-2011-1184)

A flaw was found in the way the Coyote
(org.apache.coyote.ajp.AjpProcessor) and APR
(org.apache.coyote.ajp.AjpAprProcessor) Tomcat AJP (Apache JServ
Protocol) connectors processed certain POST requests. An attacker
could send a specially crafted request that would cause the connector
to treat the message body as a new request. This allows arbitrary AJP
messages to be injected, possibly allowing an attacker to bypass a web
application's authentication checks and gain access to information
they would otherwise be unable to access. The JK
(org.apache.jk.server.JkCoyoteHandler) connector is used by default
when the APR libraries are not present. The JK connector is not
affected by this flaw. (CVE-2011-3190)

A flaw was found in the Tomcat MemoryUserDatabase. If a runtime
exception occurred when creating a new user with a JMX client, that
user's password was logged to Tomcat log files. Note: By default, only
administrators have access to such log files. (CVE-2011-2204)

A flaw was found in the way Tomcat handled sendfile request attributes
when using the HTTP APR or NIO (Non-Blocking I/O) connector. A
malicious web application running on a Tomcat instance could use this
flaw to bypass security manager restrictions and gain access to files
it would otherwise be unable to access, or possibly terminate the Java
Virtual Machine (JVM). The HTTP blocking IO (BIO) connector, which is
not vulnerable to this issue, is used by default in Red Hat Enterprise
Linux 6. (CVE-2011-2526)

Red Hat would like to thank the Apache Tomcat project for reporting
the CVE-2011-2526 issue.

This update also fixes the following bug :

* Previously, in certain cases, if 'LANG=fr_FR' or 'LANG=fr_FR.UTF-8'
was set as an environment variable or in '/etc/sysconfig/tomcat6' on
64-bit PowerPC systems, Tomcat may have failed to start correctly.
With this update, Tomcat works as expected when LANG is set to 'fr_FR'
or 'fr_FR.UTF-8'. (BZ#748807)

Users of Tomcat should upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-December/002493.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL6", reference:"tomcat6-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-admin-webapps-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-docs-webapp-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-el-2.1-api-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-javadoc-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-jsp-2.1-api-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-lib-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-servlet-2.5-api-6.0.24-35.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-webapps-6.0.24-35.el6_1")) flag++;


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
