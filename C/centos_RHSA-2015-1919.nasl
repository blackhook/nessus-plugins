#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1919 and 
# CentOS Errata and Security Advisory 2015:1919 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86516);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");
  script_xref(name:"RHSA", value:"2015:1919");

  script_name(english:"CentOS 6 / 7 : java-1.8.0-openjdk (CESA-2015:1919)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.8.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Multiple flaws were discovered in the CORBA, Libraries, RMI,
Serialization, and 2D components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2015-4835, CVE-2015-4881, CVE-2015-4843,
CVE-2015-4883, CVE-2015-4860, CVE-2015-4805, CVE-2015-4844)

Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application
using JAXP to consume an excessive amount of CPU and memory when
parsed. (CVE-2015-4803, CVE-2015-4893, CVE-2015-4911)

A flaw was found in the way the Libraries component in OpenJDK handled
certificate revocation lists (CRL). In certain cases, CRL checking
code could fail to report a revoked certificate, causing the
application to accept it as trusted. (CVE-2015-4868)

It was discovered that the Security component in OpenJDK failed to
properly check if a certificate satisfied all defined constraints. In
certain cases, this could cause a Java application to accept an X.509
certificate which does not meet requirements of the defined policy.
(CVE-2015-4872)

Multiple flaws were found in the Libraries, 2D, CORBA, JAXP, JGSS, and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass certain Java sandbox restrictions.
(CVE-2015-4806, CVE-2015-4840, CVE-2015-4882, CVE-2015-4842,
CVE-2015-4734, CVE-2015-4903)

Red Hat would like to thank Andrea Palazzo of Truel IT for reporting
the CVE-2015-4806 issue.

All users of java-1.8.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-October/021436.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0336b1db"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-October/021440.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c65ccdd3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.8.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4805");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-debug-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-1.8.0.65-0.b17.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.65-0.b17.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.65-2.b17.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.65-2.b17.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.65-2.b17.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.65-2.b17.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.65-2.b17.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.65-2.b17.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
