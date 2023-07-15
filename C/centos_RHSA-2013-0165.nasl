#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0165 and 
# CentOS Errata and Security Advisory 2013:0165 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63581);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2012-3174", "CVE-2013-0422");
  script_bugtraq_id(57246, 57312);
  script_xref(name:"RHSA", value:"2013:0165");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"CentOS 5 / 6 : java-1.7.0-openjdk (CESA-2013:0165)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated java-1.7.0-openjdk packages that fix two security issues are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 7 Java Runtime Environment and the
OpenJDK 7 Software Development Kit.

Two improper permission check issues were discovered in the reflection
API in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass Java sandbox restrictions. (CVE-2012-3174,
CVE-2013-0422)

This erratum also upgrades the OpenJDK package to IcedTea7 2.3.4.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect.");
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019203.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8227c40e");
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019204.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?051e9c91");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0422");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JMX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-1.7.0.9-2.3.4.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-demo-1.7.0.9-2.3.4.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-devel-1.7.0.9-2.3.4.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.9-2.3.4.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-src-1.7.0.9-2.3.4.el5_9.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-1.7.0.9-2.3.4.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-demo-1.7.0.9-2.3.4.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-devel-1.7.0.9-2.3.4.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.9-2.3.4.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-src-1.7.0.9-2.3.4.1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-demo / etc");
}
