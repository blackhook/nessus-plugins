#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2606. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94569);
  script_version("2.18");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_xref(name:"RHSA", value:"2016:2606");

  script_name(english:"RHEL 7 : postgresql (RHSA-2016:2606)");
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
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The following packages have been upgraded to a newer upstream version:
postgresql (9.2.18).

Security Fix(es) :

* A flaw was found in the way PostgreSQL server handled certain SQL
statements containing CASE/WHEN commands. A remote, authenticated
attacker could use a specially crafted SQL statement to cause
PostgreSQL to crash or disclose a few bytes of server memory or
possibly execute arbitrary code. (CVE-2016-5423)

* A flaw was found in the way PostgreSQL client programs handled
database and role names containing newlines, carriage returns, double
quotes, or backslashes. By crafting such an object name, roles with
the CREATEDB or CREATEROLE option could escalate their privileges to
superuser when a superuser next executes maintenance with a vulnerable
client program. (CVE-2016-5424)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Heikki Linnakangas as the original
reporter of CVE-2016-5423; and Nathan Bossart as the original reporter
of CVE-2016-5424.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5424"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2016:2606";
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
  if (rpm_check(release:"RHEL7", reference:"postgresql-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-contrib-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-debuginfo-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-devel-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-docs-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-docs-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-libs-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-plperl-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-plpython-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-pltcl-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-server-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-server-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-test-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-test-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-upgrade-9.2.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.18-1.el7")) flag++;


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
