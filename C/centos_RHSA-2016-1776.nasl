#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1776 and 
# CentOS Errata and Security Advisory 2016:1776 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93129);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-3458", "CVE-2016-3500", "CVE-2016-3508", "CVE-2016-3550", "CVE-2016-3606");
  script_xref(name:"RHSA", value:"2016:1776");

  script_name(english:"CentOS 5 / 6 / 7 : java-1.6.0-openjdk (CESA-2016:1776)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.6.0-openjdk is now available for Red Hat
Enterprise Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Security Fix(es) :

* An insufficient bytecode verification flaw was discovered in the
Hotspot component in OpenJDK. An untrusted Java application or applet
could use this flaw to completely bypass Java sandbox restrictions.
(CVE-2016-3606)

* Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application
using JAXP to consume an excessive amount of CPU and memory when
parsed. (CVE-2016-3500, CVE-2016-3508)

* Multiple flaws were found in the CORBA and Hotsport components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2016-3458,
CVE-2016-3550)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-August/022054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df2fecb9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-August/022055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf5eab87"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-August/022056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9d13f10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3606");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.40-1.13.12.4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.4.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.40-1.13.12.4.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-src-1.6.0.40-1.13.12.6.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.40-1.13.12.5.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
