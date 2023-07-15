#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0383. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46304);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849"
  );
  script_bugtraq_id(
    39062,
    39065,
    39067,
    39068,
    39069,
    39070,
    39072,
    39073,
    39075,
    39077,
    39078,
    39081,
    39083,
    39084,
    39086,
    39090,
    39091,
    39093,
    39094,
    39095,
    39096
  );
  script_xref(name:"RHSA", value:"2010:0383");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"RHEL 4 / 5 : java-1.6.0-ibm (RHSA-2010:0383)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The IBM 1.6.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

This update fixes several vulnerabilities in the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit. These
vulnerabilities are summarized on the IBM 'Security alerts' page
listed in the References section. (CVE-2010-0084, CVE-2010-0085,
CVE-2010-0087, CVE-2010-0088, CVE-2010-0089, CVE-2010-0090,
CVE-2010-0091, CVE-2010-0092, CVE-2010-0094, CVE-2010-0095,
CVE-2010-0837, CVE-2010-0838, CVE-2010-0839, CVE-2010-0840,
CVE-2010-0841, CVE-2010-0842, CVE-2010-0843, CVE-2010-0844,
CVE-2010-0846, CVE-2010-0848, CVE-2010-0849)

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM 1.6.0 SR8 Java release. All running
instances of IBM Java must be restarted for the update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0084");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0085");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0088");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0089");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0090");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0091");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0092");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0094");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0095");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0837");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0838");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0839");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0840");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0841");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0842");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0846");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0847");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0848");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0849");
  script_set_attribute(attribute:"see_also", value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0383");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0849");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2010:0383";
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
  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-demo-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-devel-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-jdbc-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.8-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.6.0-ibm-src-1.6.0.8-1jpp.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-accessibility-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-accessibility-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-accessibility-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-demo-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-devel-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-jdbc-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.8-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.6.0-ibm-src-1.6.0.8-1jpp.1.el5")) flag++;


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
