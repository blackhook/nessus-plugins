#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0436 and 
# CentOS Errata and Security Advisory 2019:0436 respectively.
#

include('compat.inc');

if (description)
{
  script_id(122618);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2019-2422");
  script_xref(name:"RHSA", value:"2019:0436");

  script_name(english:"CentOS 7 : java-11-openjdk (CESA-2019:0436)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for java-11-openjdk is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-11-openjdk packages provide the OpenJDK 11 Java Runtime
Environment and the OpenJDK 11 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: memory disclosure in FileChannelImpl (Libraries, 8206290)
(CVE-2019-2422)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.");
  # https://lists.centos.org/pipermail/centos-announce/2019-March/023212.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f05a35bf");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-11-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-jmods-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-demo-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-devel-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-headless-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-jmods-debug-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.2.7-0.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-src-debug-11.0.2.7-0.el7_6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-debug / java-11-openjdk-demo / etc");
}
