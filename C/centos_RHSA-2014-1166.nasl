#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1166 and 
# CentOS Errata and Security Advisory 2014:1166 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77564);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3577");
  script_bugtraq_id(69258);
  script_xref(name:"RHSA", value:"2014:1166");

  script_name(english:"CentOS 5 / 6 / 7 : jakarta-commons-httpclient (CESA-2014:1166)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jakarta-commons-httpclient packages that fix one security
issue are now available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Jakarta Commons HTTPClient implements the client side of HTTP
standards.

It was discovered that the HTTPClient incorrectly extracted host name
from an X.509 certificate subject's Common Name (CN) field. A
man-in-the-middle attacker could use this flaw to spoof an SSL server
using a specially crafted X.509 certificate. (CVE-2014-3577)

For additional information on this flaw, refer to the Knowledgebase
article in the References section.

All jakarta-commons-httpclient users are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d73c8749"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c085d854"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42e0eb1d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-commons-httpclient packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3577");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-commons-httpclient-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-commons-httpclient-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-commons-httpclient-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"jakarta-commons-httpclient-3.0-7jpp.4.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"jakarta-commons-httpclient-demo-3.0-7jpp.4.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"jakarta-commons-httpclient-javadoc-3.0-7jpp.4.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"jakarta-commons-httpclient-manual-3.0-7jpp.4.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"jakarta-commons-httpclient-3.1-0.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jakarta-commons-httpclient-demo-3.1-0.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jakarta-commons-httpclient-javadoc-3.1-0.9.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jakarta-commons-httpclient-manual-3.1-0.9.el6_5")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jakarta-commons-httpclient-3.1-16.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jakarta-commons-httpclient-demo-3.1-16.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jakarta-commons-httpclient-javadoc-3.1-16.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jakarta-commons-httpclient-manual-3.1-16.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-httpclient / jakarta-commons-httpclient-demo / etc");
}
