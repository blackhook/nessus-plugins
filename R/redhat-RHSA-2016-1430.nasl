#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1430. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92400);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2015-4734",
    "CVE-2015-4803",
    "CVE-2015-4805",
    "CVE-2015-4806",
    "CVE-2015-4810",
    "CVE-2015-4835",
    "CVE-2015-4840",
    "CVE-2015-4842",
    "CVE-2015-4843",
    "CVE-2015-4844",
    "CVE-2015-4860",
    "CVE-2015-4871",
    "CVE-2015-4872",
    "CVE-2015-4882",
    "CVE-2015-4883",
    "CVE-2015-4893",
    "CVE-2015-4902",
    "CVE-2015-4903",
    "CVE-2015-5006",
    "CVE-2015-5041",
    "CVE-2015-7575",
    "CVE-2015-7981",
    "CVE-2015-8126",
    "CVE-2015-8472",
    "CVE-2015-8540",
    "CVE-2016-0264",
    "CVE-2016-0363",
    "CVE-2016-0376",
    "CVE-2016-0402",
    "CVE-2016-0448",
    "CVE-2016-0466",
    "CVE-2016-0483",
    "CVE-2016-0494",
    "CVE-2016-0686",
    "CVE-2016-0687",
    "CVE-2016-3422",
    "CVE-2016-3426",
    "CVE-2016-3427",
    "CVE-2016-3443",
    "CVE-2016-3449"
  );
  script_xref(name:"RHSA", value:"2016:1430");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"RHEL 5 / 6 : java-1.7.0-ibm and java-1.7.1-ibm (RHSA-2016:1430) (SLOTH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.7.0-ibm and java-1.7.1-ibm is now available for
Red Hat Satellite 5.7 and Red Hat Satellite 5.6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 7 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update upgrades IBM Java SE 7 to versions 7 SR9-FP40 and 7R1
SR3-FP40.

Security Fix(es) :

* This update fixes multiple vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Further
information about these flaws can be found on the IBM Java Security
alerts page, listed in the References section. (CVE-2015-4734,
CVE-2015-4803, CVE-2015-4805, CVE-2015-4806, CVE-2015-4810,
CVE-2015-4835, CVE-2015-4840, CVE-2015-4842, CVE-2015-4843,
CVE-2015-4844, CVE-2015-4860, CVE-2015-4871, CVE-2015-4872,
CVE-2015-4882, CVE-2015-4883, CVE-2015-4893, CVE-2015-4902,
CVE-2015-4903, CVE-2015-5006, CVE-2015-5041, CVE-2015-7575,
CVE-2015-7981, CVE-2015-8126, CVE-2015-8472, CVE-2015-8540,
CVE-2016-0264, CVE-2016-0363, CVE-2016-0376, CVE-2016-0402,
CVE-2016-0448, CVE-2016-0466, CVE-2016-0483, CVE-2016-0494,
CVE-2016-0686, CVE-2016-0687, CVE-2016-3422, CVE-2016-3426,
CVE-2016-3427, CVE-2016-3443, CVE-2016-3449)

Red Hat would like to thank Andrea Palazzo of Truel IT for reporting
the CVE-2015-4806 issue.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:1430");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4734");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4803");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4810");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4835");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4840");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4842");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4860");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4872");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4882");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4883");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4902");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-4903");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5006");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7575");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7981");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8126");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8472");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8540");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0264");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0363");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0376");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0402");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0483");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0494");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0686");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0687");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3422");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3426");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3443");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3449");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3443");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2016:1430";
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
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.7.0-ibm-1.7.0.9.40-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-ibm-1.7.0.9.40-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.7.0-ibm-devel-1.7.0.9.40-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-ibm-devel-1.7.0.9.40-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-2.0.2-109.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-2.0.2-109.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-2.0.2-109.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-2.0.2-109.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-postgresql-2.0.2-109.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-2.0.2-109.el5sat")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-1.7.1.3.40-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-1.7.1.3.40-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-devel-1.7.1.3.40-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-devel-1.7.1.3.40-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.0.2-109.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.0.2-109.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.0.2-109.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.0.2-109.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.0.2-109.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.0.2-109.el6sat")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-ibm / java-1.7.0-ibm-devel / java-1.7.1-ibm / etc");
  }
}
