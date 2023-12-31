#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1657. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79056);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6476", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6515", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558");
  script_xref(name:"RHSA", value:"2014:1657");

  script_name(english:"RHEL 5 / 6 / 7 : java-1.7.0-oracle (RHSA-2014:1657)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-oracle packages that fix several security issues
are now available for Oracle Java for Red Hat Enterprise Linux 5, 6,
and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Oracle Java SE version 7 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java Runtime
Environment and the Oracle Java Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch Update Advisory page, listed in the References section.
(CVE-2014-4288, CVE-2014-6456, CVE-2014-6457, CVE-2014-6458,
CVE-2014-6476, CVE-2014-6492, CVE-2014-6493, CVE-2014-6502,
CVE-2014-6503, CVE-2014-6504, CVE-2014-6506, CVE-2014-6511,
CVE-2014-6512, CVE-2014-6515, CVE-2014-6517, CVE-2014-6519,
CVE-2014-6527, CVE-2014-6531, CVE-2014-6532, CVE-2014-6558)

The CVE-2014-6512 issue was discovered by Florian Weimer of Red Hat
Product Security.

All users of java-1.7.0-oracle are advised to upgrade to these updated
packages, which provide Oracle Java 7 Update 72 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-4288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6558"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3421cbe7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1657"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-javafx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1657";
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
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-devel-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-javafx-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-jdbc-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-plugin-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-src-1.7.0.72-1jpp.4.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.72-1jpp.4.el5_11")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-javafx-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.72-1jpp.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.72-1jpp.2.el6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.72-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.72-1jpp.2.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-oracle / java-1.7.0-oracle-devel / etc");
  }
}
