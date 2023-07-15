#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1193 and 
# CentOS Errata and Security Advisory 2014:1193 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77692);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3596");
  script_bugtraq_id(69295);
  script_xref(name:"RHSA", value:"2014:1193");

  script_name(english:"CentOS 5 / 6 : axis (CESA-2014:1193)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated axis packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Apache Axis is an implementation of SOAP (Simple Object Access
Protocol). It can be used to build both web service clients and
servers.

It was discovered that Axis incorrectly extracted the host name from
an X.509 certificate subject's Common Name (CN) field. A
man-in-the-middle attacker could use this flaw to spoof an SSL server
using a specially crafted X.509 certificate. (CVE-2014-3596)

For additional information on this flaw, refer to the Knowledgebase
article in the References section.

This issue was discovered by David Jorm and Arun Neelicattu of Red Hat
Product Security.

All axis users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. Applications using
Apache Axis must be restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5a69369"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-September/020562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52891895"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected axis packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3596");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:axis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:axis-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:axis-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"axis-1.2.1-2jpp.8.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"axis-javadoc-1.2.1-2jpp.8.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"axis-manual-1.2.1-2jpp.8.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"axis-1.2.1-7.5.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"axis-javadoc-1.2.1-7.5.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"axis-manual-1.2.1-7.5.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "axis / axis-javadoc / axis-manual");
}
