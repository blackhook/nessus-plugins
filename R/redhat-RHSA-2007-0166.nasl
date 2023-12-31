#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0166. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40702);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-0243");
  script_bugtraq_id(22085);
  script_xref(name:"RHSA", value:"2007:0166");

  script_name(english:"RHEL 3 / 4 / 5 : java-1.4.2-ibm (RHSA-2007:0166)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.4.2-ibm packages to correct a security issue are now
available for Red Hat Enterprise Linux 3 and 4 Extras.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

IBM's 1.4.2 SR8 Java release includes the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit.

A flaw in GIF image handling was found in the SUN Java Runtime
Environment that has now been reported as also affecting IBM Java 2.
An untrusted applet or application could use this flaw to elevate its
privileges and potentially execute arbitrary code. (CVE-2007-0243)

All users of java-1.4.2-ibm should upgrade to these updated packages,
which contain IBM's 1.4.2 SR8 Java release which resolves this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0243"
  );
  # http://www-128.ibm.com/developerworks/java/jdk/alerts/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ibm.com/us-en/?ar=1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:0166"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/25");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0166";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-1.4.2.8-1jpp.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-demo-1.4.2.8-1jpp.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-devel-1.4.2.8-1jpp.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"java-1.4.2-ibm-plugin-1.4.2.8-1jpp.1.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-src-1.4.2.8-1jpp.1.el3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-demo-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-devel-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-javacomm-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.4.2-ibm-javacomm-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-plugin-1.4.2.8-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-src-1.4.2.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-demo-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-devel-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.4.2-ibm-javacomm-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.4.2-ibm-javacomm-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390", reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.4.2-ibm-plugin-1.4.2.8-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-src-1.4.2.8-1jpp.1.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.4.2-ibm / java-1.4.2-ibm-demo / java-1.4.2-ibm-devel / etc");
  }
}
