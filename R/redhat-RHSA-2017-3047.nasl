#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3047. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104140);
  script_version("3.7");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10293", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");
  script_xref(name:"RHSA", value:"2017:3047");

  script_name(english:"RHEL 6 / 7 : java-1.6.0-sun (RHSA-2017:3047)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.6.0-sun is now available for Oracle Java for Red
Hat Enterprise Linux 6 and Oracle Java for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Oracle Java SE version 6 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update upgrades Oracle Java SE 6 to version 6 Update 171.

Security Fix(es) :

* This update fixes multiple vulnerabilities in the Oracle Java
Runtime Environment and the Oracle Java Software Development Kit.
Further information about these flaws can be found on the Oracle Java
SE Critical Patch Update Advisory page listed in the References
section. (CVE-2016-9840, CVE-2016-9841, CVE-2016-9842, CVE-2016-9843,
CVE-2017-10274, CVE-2017-10281, CVE-2017-10285, CVE-2017-10293,
CVE-2017-10295, CVE-2017-10345, CVE-2017-10346, CVE-2017-10347,
CVE-2017-10348, CVE-2017-10349, CVE-2017-10355, CVE-2017-10356,
CVE-2017-10357, CVE-2017-10388)

Note: Starting with this update, Java web browser plugin and Java Web
Start application are no longer included with Oracle Java SE 6. Refer
to the Releases Notes and the Oracle Java SE Support Roadmap pages
linked to in the References section for further information about this
change."
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e07fa0e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/java/javase/documentation/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/java/javase/eol-135779.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-10388"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:3047";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-demo-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-devel-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-jdbc-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-plugin-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-src-1.6.0.171-1jpp.4.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.171-1jpp.4.el6")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.6.0-sun-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.6.0-sun-devel-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.171-1jpp.4.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.171-1jpp.4.el7")) flag++;


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
