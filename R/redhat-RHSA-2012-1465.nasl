#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1465. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62930);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1531", "CVE-2012-3143", "CVE-2012-3216", "CVE-2012-4820", "CVE-2012-4822", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5089", "CVE-2013-1475");
  script_bugtraq_id(53951, 55336, 55339, 55495, 56025, 56033, 56039, 56043, 56046, 56051, 56054, 56055, 56056, 56057, 56058, 56059, 56061, 56063, 56065, 56070, 56071, 56072, 56075, 56079, 56080, 56081, 56082, 56083);
  script_xref(name:"RHSA", value:"2012:1465");

  script_name(english:"RHEL 5 / 6 : java-1.5.0-ibm (RHSA-2012:1465) (ROBOT)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

IBM J2SE version 5.0 includes the IBM Java Runtime Environment and the
IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Detailed
vulnerability descriptions are linked from the IBM Security alerts
page, listed in the References section. (CVE-2012-1531, CVE-2012-3143,
CVE-2012-3216, CVE-2012-4820, CVE-2012-4822, CVE-2012-5069,
CVE-2012-5071, CVE-2012-5073, CVE-2012-5075, CVE-2012-5079,
CVE-2012-5081, CVE-2012-5083, CVE-2012-5084, CVE-2012-5089)

All users of java-1.5.0-ibm are advised to upgrade to these updated
packages, containing the IBM J2SE 5.0 SR15 release. All running
instances of IBM Java must be restarted for this update to take
effect."
  );
  # https://www.ibm.com/developerworks/java/jdk/alerts/
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1475"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Method Handle Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1465";
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
  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-accessibility-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.5.0-ibm-accessibility-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-accessibility-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-demo-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-devel-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.15.0-1jpp.1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-src-1.5.0.15.0-1jpp.1.el5_8")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.5.0-ibm-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-demo-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.5.0-ibm-demo-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-demo-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.5.0-ibm-devel-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-javacomm-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-jdbc-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-plugin-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-src-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.5.0-ibm-src-1.5.0.15.0-1jpp.1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-src-1.5.0.15.0-1jpp.1.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-ibm / java-1.5.0-ibm-accessibility / java-1.5.0-ibm-demo / etc");
  }
}
