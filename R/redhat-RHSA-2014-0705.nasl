#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0705. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76900);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5887", "CVE-2013-5888", "CVE-2013-5889", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899", "CVE-2013-5907", "CVE-2013-5910", "CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0387", "CVE-2014-0403", "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424", "CVE-2014-0428", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0448", "CVE-2014-0449", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0878", "CVE-2014-1876", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2402", "CVE-2014-2409", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2420", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-2428");
  script_xref(name:"RHSA", value:"2014:0705");

  script_name(english:"RHEL 7 : java-1.7.1-ibm (RHSA-2014:0705)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.1-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 7 Supplementary.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

IBM Java SE version 7 Release 1 includes the IBM Java Runtime
Environment and the IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Detailed
vulnerability descriptions are linked from the IBM Security alerts
page, listed in the References section. (CVE-2013-5878, CVE-2013-5884,
CVE-2013-5887, CVE-2013-5888, CVE-2013-5889, CVE-2013-5896,
CVE-2013-5898, CVE-2013-5899, CVE-2013-5907, CVE-2013-5910,
CVE-2013-6629, CVE-2013-6954, CVE-2014-0368, CVE-2014-0373,
CVE-2014-0375, CVE-2014-0376, CVE-2014-0387, CVE-2014-0403,
CVE-2014-0410, CVE-2014-0411, CVE-2014-0415, CVE-2014-0416,
CVE-2014-0417, CVE-2014-0422, CVE-2014-0423, CVE-2014-0424,
CVE-2014-0428, CVE-2014-0429, CVE-2014-0446, CVE-2014-0448,
CVE-2014-0449, CVE-2014-0451, CVE-2014-0452, CVE-2014-0453,
CVE-2014-0454, CVE-2014-0455, CVE-2014-0457, CVE-2014-0458,
CVE-2014-0459, CVE-2014-0460, CVE-2014-0461, CVE-2014-1876,
CVE-2014-2398, CVE-2014-2401, CVE-2014-2402, CVE-2014-2409,
CVE-2014-2412, CVE-2014-2414, CVE-2014-2420, CVE-2014-2421,
CVE-2014-2423, CVE-2014-2427, CVE-2014-2428)

All users of java-1.7.1-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 7R1 SR1 release. All running
instances of IBM Java must be restarted for the update to take effect."
  );
  # https://www.ibm.com/developerworks/java/jdk/alerts/
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-6629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-1876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-2409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-6954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0878"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0705";
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
  if (rpm_check(release:"RHEL7", reference:"java-1.7.1-ibm-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-demo-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-demo-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.7.1-ibm-devel-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-jdbc-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-jdbc-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-plugin-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-src-1.7.1.1.0-1jpp.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-src-1.7.1.1.0-1jpp.2.el7_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.1-ibm / java-1.7.1-ibm-demo / java-1.7.1-ibm-devel / etc");
  }
}
