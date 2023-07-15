#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0580 and 
# CentOS Errata and Security Advisory 2010:0580 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48218);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0781", "CVE-2009-2693", "CVE-2009-2696", "CVE-2009-2902", "CVE-2010-2227");
  script_xref(name:"RHSA", value:"2010:0580");

  script_name(english:"CentOS 5 : tomcat5 (CESA-2010:0580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

A flaw was found in the way Tomcat handled the Transfer-Encoding
header in HTTP requests. A specially crafted HTTP request could
prevent Tomcat from sending replies, or cause Tomcat to return
truncated replies, or replies containing data related to the requests
of other users, for all subsequent HTTP requests. (CVE-2010-2227)

The Tomcat security update RHSA-2009:1164 did not, unlike the erratum
text stated, provide a fix for CVE-2009-0781, a cross-site scripting
(XSS) flaw in the examples calendar application. With some web
browsers, remote attackers could use this flaw to inject arbitrary web
script or HTML via the 'time' parameter. (CVE-2009-2696)

Two directory traversal flaws were found in the Tomcat deployment
process. A specially crafted WAR file could, when deployed, cause a
file to be created outside of the web root into any directory writable
by the Tomcat user, or could lead to the deletion of files in the
Tomcat host's work directory. (CVE-2009-2693, CVE-2009-2902)

Users of Tomcat should upgrade to these updated packages, which
contain backported patches to resolve these issues. Tomcat must be
restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016858.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?765d4416"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c24545c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-common-lib-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-server-lib-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-webapps-5.5.23-0jpp.9.el5_5")) flag++;


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
