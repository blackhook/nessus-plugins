#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2557. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112104);
  script_version("1.8");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-10915");
  script_xref(name:"RHSA", value:"2018:2557");

  script_name(english:"RHEL 7 : postgresql (RHSA-2018:2557)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for postgresql is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The following packages have been upgraded to a later upstream version:
postgresql (9.2.24). (BZ#1612667)

Security Fix(es) :

* postgresql: Certain host connection parameters defeat client-side
security defenses (CVE-2018-10915)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the PostgreSQL project for reporting this
issue. Upstream acknowledges Andrew Krasichkov as the original
reporter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10915"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:2557";
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
  if (rpm_check(release:"RHEL7", reference:"postgresql-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-contrib-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-debuginfo-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-devel-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-docs-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-docs-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-libs-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-plperl-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-plpython-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-pltcl-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-server-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-server-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-static-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-test-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-test-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-upgrade-9.2.24-1.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.24-1.el7_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
  }
}
