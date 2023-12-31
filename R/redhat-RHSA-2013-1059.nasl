#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1059. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68900);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2437",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3009",
    "CVE-2013-3011",
    "CVE-2013-3012",
    "CVE-2013-3743",
    "CVE-2013-4002"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60631,
    60632,
    60633,
    60634,
    60636,
    60637,
    60638,
    60640,
    60641,
    60643,
    60644,
    60646,
    60647,
    60650,
    60651,
    60653,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_xref(name:"RHSA", value:"2013:1059");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-ibm (RHSA-2013:1059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
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
page, listed in the References section. (CVE-2013-1500, CVE-2013-1571,
CVE-2013-2407, CVE-2013-2412, CVE-2013-2437, CVE-2013-2442,
CVE-2013-2443, CVE-2013-2444, CVE-2013-2446, CVE-2013-2447,
CVE-2013-2448, CVE-2013-2450, CVE-2013-2451, CVE-2013-2452,
CVE-2013-2453, CVE-2013-2454, CVE-2013-2455, CVE-2013-2456,
CVE-2013-2457, CVE-2013-2459, CVE-2013-2463, CVE-2013-2464,
CVE-2013-2465, CVE-2013-2466, CVE-2013-2468, CVE-2013-2469,
CVE-2013-2470, CVE-2013-2471, CVE-2013-2472, CVE-2013-2473,
CVE-2013-3743)

Red Hat would like to thank Tim Brown for reporting CVE-2013-1500, and
US-CERT for reporting CVE-2013-1571. US-CERT acknowledges Oracle as
the original reporter of CVE-2013-1571.

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 6 SR14 release. All running
instances of IBM Java must be restarted for the update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1059");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2465");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1571");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2472");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2412");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2454");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2455");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2456");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2457");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2450");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2452");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2453");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2459");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2470");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2471");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2473");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2446");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2463");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2407");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1500");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2469");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2443");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2444");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2451");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2464");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2468");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2442");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3743");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3009");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3011");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3012");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-4002");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5\.9|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9 / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1059";
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
  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"java-1.6.0-ibm-accessibility-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"java-1.6.0-ibm-accessibility-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"java-1.6.0-ibm-accessibility-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-demo-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-devel-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-jdbc-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-src-1.6.0.14.0-1jpp.1.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-demo-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-demo-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-demo-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.6.0-ibm-devel-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-javacomm-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-jdbc-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-jdbc-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-jdbc-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-plugin-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-src-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-src-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-src-1.6.0.14.0-1jpp.1.el6_4")) flag++;


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
