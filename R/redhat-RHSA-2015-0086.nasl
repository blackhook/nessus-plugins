#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0086. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81014);
  script_version("1.15");
  script_cvs_date("Date: 2019/10/24 15:35:39");

  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0403", "CVE-2015-0406", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_xref(name:"RHSA", value:"2015:0086");

  script_name(english:"RHEL 5 / 6 / 7 : java-1.6.0-sun (RHSA-2015:0086) (POODLE)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-sun packages that fix several security issues are
now available for Oracle Java for Red Hat Enterprise Linux 5, 6, and
7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Oracle Java SE version 6 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java Runtime
Environment and the Oracle Java Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch Update Advisory page, listed in the References section.
(CVE-2014-3566, CVE-2014-6585, CVE-2014-6587, CVE-2014-6591,
CVE-2014-6593, CVE-2014-6601, CVE-2015-0383, CVE-2015-0395,
CVE-2015-0403, CVE-2015-0406, CVE-2015-0407, CVE-2015-0408,
CVE-2015-0410, CVE-2015-0412)

The CVE-2015-0383 issue was discovered by Red Hat.

Note: With this update, the Oracle Java SE now disables the SSL 3.0
protocol to address the CVE-2014-3566 issue (also known as POODLE).
Refer to the Red Hat Bugzilla bug linked to in the References section
for instructions on how to re-enable SSL 3.0 support if needed.

All users of java-1.6.0-sun are advised to upgrade to these updated
packages, which provide Oracle Java 6 Update 91 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df55894d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152789#c82"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:0086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-6601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0412"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:0086";
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
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-demo-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-devel-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-jdbc-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-plugin-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-src-1.6.0.91-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.91-1jpp.1.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-demo-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-devel-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-jdbc-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-plugin-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-src-1.6.0.91-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.91-1jpp.1.el6")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.6.0-sun-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.6.0-sun-devel-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.91-1jpp.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.91-1jpp.1.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-sun / java-1.6.0-sun-demo / java-1.6.0-sun-devel / etc");
  }
}
