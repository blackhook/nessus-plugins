#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0906. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40728);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3109", "CVE-2008-3110", "CVE-2008-3112", "CVE-2008-3114");
  script_xref(name:"RHSA", value:"2008:0906");

  script_name(english:"RHEL 4 / 5 : java-1.6.0-ibm (RHSA-2008:0906)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 4 Extras and Red Hat
Enterprise Linux 5 Supplementary.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The IBM 1.6.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

A flaw was found in the Java Management Extensions (JMX) management
agent. When local monitoring is enabled, remote attackers could use
this flaw to perform illegal operations. (CVE-2008-3103)

Several flaws involving the handling of unsigned applets were found. A
remote attacker could misuse an unsigned applet in order to connect to
services on the host running the applet. (CVE-2008-3104)

Several flaws in the Java API for XML Web Services (JAX-WS) client and
the JAX-WS service implementation were found. A remote attacker who
could cause malicious XML to be processed by an application could
access URLs, or cause a denial of service. (CVE-2008-3105,
CVE-2008-3106)

Several flaws within the Java Runtime Environment (JRE) scripting
support were found. A remote attacker could grant an untrusted applet
extended privileges, such as reading and writing local files,
executing local programs, or querying the sensitive data of other
applets. (CVE-2008-3109, CVE-2008-3110)

A flaw in Java Web Start was found. Using an untrusted Java Web Start
application, a remote attacker could create or delete arbitrary files
with the permissions of the user running the untrusted application.
(CVE-2008-3112)

A flaw in Java Web Start when processing untrusted applications was
found. An attacker could use this flaw to acquire sensitive
information, such as the location of the cache. (CVE-2008-3114)

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM 1.6.0 SR2 Java release, which resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3114"
  );
  # http://www-128.ibm.com/developerworks/java/jdk/alerts/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ibm.com/us-en/?ar=1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0906"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0906";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-demo-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-devel-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-jdbc-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.2-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-src-1.6.0.2-1jpp.2.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-accessibility-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-accessibility-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-accessibility-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-demo-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-devel-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-jdbc-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.2-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-src-1.6.0.2-1jpp.2.el5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-ibm / java-1.6.0-ibm-accessibility / java-1.6.0-ibm-demo / etc");
  }
}
