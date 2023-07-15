#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1508. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70792);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-3829", "CVE-2013-4041", "CVE-2013-5372", "CVE-2013-5375", "CVE-2013-5457", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5776", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5787", "CVE-2013-5789", "CVE-2013-5797", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5812", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5818", "CVE-2013-5819", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5824", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5831", "CVE-2013-5832", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843", "CVE-2013-5848", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");
  script_bugtraq_id(63082, 63089, 63095, 63098, 63101, 63103, 63106, 63110, 63115, 63118, 63120, 63121, 63124, 63126, 63128, 63129, 63133, 63134, 63135, 63137, 63139, 63141, 63142, 63143, 63146, 63147, 63148, 63149, 63150, 63151, 63152, 63153, 63154, 63155, 63156, 63157, 63158, 63224);
  script_xref(name:"RHSA", value:"2013:1508");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-ibm (RHSA-2013:1508)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

IBM Java SE version 6 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Detailed
vulnerability descriptions are linked from the IBM Security alerts
page, listed in the References section. (CVE-2013-3829, CVE-2013-4041,
CVE-2013-5372, CVE-2013-5375, CVE-2013-5457, CVE-2013-5772,
CVE-2013-5774, CVE-2013-5776, CVE-2013-5778, CVE-2013-5780,
CVE-2013-5782, CVE-2013-5783, CVE-2013-5784, CVE-2013-5787,
CVE-2013-5789, CVE-2013-5797, CVE-2013-5801, CVE-2013-5802,
CVE-2013-5803, CVE-2013-5804, CVE-2013-5809, CVE-2013-5812,
CVE-2013-5814, CVE-2013-5817, CVE-2013-5818, CVE-2013-5819,
CVE-2013-5820, CVE-2013-5823, CVE-2013-5824, CVE-2013-5825,
CVE-2013-5829, CVE-2013-5830, CVE-2013-5831, CVE-2013-5832,
CVE-2013-5840, CVE-2013-5842, CVE-2013-5843, CVE-2013-5848,
CVE-2013-5849, CVE-2013-5850, CVE-2013-5851)

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 6 SR15 release. All running
instances of IBM Java must be restarted for the update to take effect."
  );
  # https://www.ibm.com/developerworks/java/jdk/alerts/
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-3829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5457"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:1508";
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
  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-accessibility-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-accessibility-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-accessibility-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-demo-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-devel-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-jdbc-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.15.0-1jpp.1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-src-1.6.0.15.0-1jpp.1.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-demo-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-demo-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-demo-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.6.0-ibm-devel-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-javacomm-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-jdbc-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-jdbc-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-jdbc-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-plugin-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-src-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-src-1.6.0.15.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-src-1.6.0.15.0-1jpp.1.el6_4")) flag++;


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
