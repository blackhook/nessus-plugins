#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0097 and 
# CentOS Errata and Security Advisory 2014:0097 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72153);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4578", "CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_xref(name:"RHSA", value:"2014:0097");

  script_name(english:"CentOS 5 / 6 : java-1.6.0-openjdk (CESA-2014:0097)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Java Software Development Kit.

An input validation flaw was discovered in the font layout engine in
the 2D component. A specially crafted font file could trigger a Java
Virtual Machine memory corruption when processed. An untrusted Java
application or applet could possibly use this flaw to bypass Java
sandbox restrictions. (CVE-2013-5907)

Multiple improper permission check issues were discovered in the CORBA
and JNDI components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-0428, CVE-2014-0422)

Multiple improper permission check issues were discovered in the
Serviceability, Security, CORBA, JAAS, JAXP, and Networking components
in OpenJDK. An untrusted Java application or applet could use these
flaws to bypass certain Java sandbox restrictions. (CVE-2014-0373,
CVE-2013-5878, CVE-2013-5910, CVE-2013-5896, CVE-2013-5884,
CVE-2014-0416, CVE-2014-0376, CVE-2014-0368)

It was discovered that the Beans component did not restrict processing
of XML external entities. This flaw could cause a Java application
using Beans to leak sensitive information, or affect application
availability. (CVE-2014-0423)

It was discovered that the JSSE component could leak timing
information during the TLS/SSL handshake. This could possibly lead to
a disclosure of information about the used encryption keys.
(CVE-2014-0411)

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-January/020120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0aac2b51"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-January/020121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f02653c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5907");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-3.1.13.1.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-3.1.13.1.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-3.1.13.1.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-3.1.13.1.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-3.1.13.1.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-1.6.0.0-3.1.13.1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-demo-1.6.0.0-3.1.13.1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-devel-1.6.0.0-3.1.13.1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-3.1.13.1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-src-1.6.0.0-3.1.13.1.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
